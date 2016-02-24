/*
 * Zadara send-receive code.
 * This file is meant to be included directly from fs/btrfs/send.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 * If Zadara changes are ever accepted by the community, the contents of this file
 * will move into send.c and this file will disappear.
 */

#include <linux/bio.h>
#include <zbio.h>

/*************************************************************************************/
/* Flags that are used to alter normal send behavior; to be used only for testing!!! */
static struct
{
	unsigned int one_cmd_per_buffer;
	unsigned int long_replay;
	unsigned int force_cp_version;
	
} ZSEND_TEST = { 
	.one_cmd_per_buffer = 0,
	.long_replay = 0,
	.force_cp_version = 0,
};
module_param_named(zsend__one_cmd_per_buffer__FOR_DEV_TEST_ONLY, ZSEND_TEST.one_cmd_per_buffer, uint, S_IRUSR | S_IWUSR);
module_param_named(zsend__long_replay__FOR_DEV_TEST_ONLY, ZSEND_TEST.long_replay, uint, S_IRUSR | S_IWUSR);
module_param_named(zsend__force_cp_version__FOR_DEV_TEST_ONLY, ZSEND_TEST.force_cp_version, uint, S_IRUSR | S_IWUSR);
/*************************************************************************************/

static const u16 MAX_U16 = (u16)-1;

struct send_cp_ctx
{
	struct send_ctx base;

	/* flags that are used during replay of the send-stream */
	u64 replay_stream_flags;
	/* flags that are used when generating a new send-stream */
	u64 gen_stream_flags;

	/* How many commands/bytes we need to skip, before we can start sending new commands */
	u64 n_cmds_to_skip;
	u64 offset_in_write_cmd_bytes_to_skip;

	/* Our current checkpoint */
	struct btrfs_send_checkpoint curr_cp;

	/* User buffer to be filled with data and how much data there already is */
	u8 __user *out_buffer;
	u32 out_buffer_size_bytes; /* total size - constant */
	u32 out_buffer_l_bytes;    /* useful data on the left part */
	u32 out_buffer_r_bytes;    /* useful data on the right part - for BTRFS_SEND_C_ZWRITE_ALIGNED data */

	/* 
	 * We set this to 1, when we cannot put more data into the user buffer, 
	 * and we return -EOVERFLOW. We need this field to distinguish from
	 * some other -EOVERFLOW error that we maybe can encounter.
	 */
	u8 out_buffer_full;
};

#define ZKLOG_PRINT_CP(fs_info, log_level, tag, cp, ...)                                                                              \
({                                                                                                                                    \
	if (zklog_will_print_tag((log_level), (tag))) {                                                                                   \
		char lkey_oid[21] = "-1";                                                                                                     \
		char lkey_off[21] = "-1";                                                                                                     \
		char rkey_oid[21] = "-1";                                                                                                     \
		char rkey_off[21] = "-1";                                                                                                     \
		ZBTRFSLOG_TAG((fs_info), (log_level), (tag), "cp ino(%llu,%llu): [new=%d del=%d new_gen=%d] size(%llu) mode(0%llo) prgr=%llu",\
			      le64_to_cpu((cp)->cur_ino), le64_to_cpu((cp)->cur_inode_gen),                                                       \
			      (cp)->cur_inode_new, (cp)->cur_inode_deleted, (cp)->cur_inode_new_gen,                                              \
			      le64_to_cpu((cp)->cur_inode_size), le64_to_cpu((cp)->cur_inode_mode), le64_to_cpu((cp)->send_progress));            \
		if (le64_to_cpu((cp)->tree_cmp_cp.left_key__objectid) != (u64)-1)                                                             \
			snprintf(lkey_oid, sizeof(lkey_oid), "%llu", le64_to_cpu((cp)->tree_cmp_cp.left_key__objectid));                          \
		if (le64_to_cpu((cp)->tree_cmp_cp.left_key__offset) != (u64)-1)                                                               \
			snprintf(lkey_off, sizeof(lkey_off), "%llu", le64_to_cpu((cp)->tree_cmp_cp.left_key__offset));                            \
		if (le64_to_cpu((cp)->tree_cmp_cp.right_key__objectid) != (u64)-1)                                                            \
			snprintf(rkey_oid, sizeof(rkey_oid), "%llu", le64_to_cpu((cp)->tree_cmp_cp.right_key__objectid));                         \
		if (le64_to_cpu((cp)->tree_cmp_cp.right_key__offset) != (u64)-1)                                                              \
			snprintf(rkey_off, sizeof(rkey_off), "%llu", le64_to_cpu((cp)->tree_cmp_cp.right_key__offset));                           \
		ZBTRFSLOG_TAG((fs_info), (log_level), (tag), "cp ino(%llu,%llu): L(%s,%s,%s)R(%s,%s,%s)",                                     \
			      le64_to_cpu((cp)->cur_ino), le64_to_cpu((cp)->cur_inode_gen),                                                       \
			      lkey_oid, btrfs_fs_key_type_to_str((cp)->tree_cmp_cp.left_key__type), lkey_off,                                     \
			      rkey_oid, btrfs_fs_key_type_to_str((cp)->tree_cmp_cp.right_key__type), rkey_off);                                   \
		ZBTRFSLOG_TAG((fs_info), (log_level), (tag), "cp ino(%llu,%llu): n_skip=%llu, offset=%llu",                                   \
			      le64_to_cpu((cp)->cur_ino), le64_to_cpu((cp)->cur_inode_gen),                                                       \
			      le64_to_cpu((cp)->n_cmds_since_cp), le64_to_cpu((cp)->offset_in_write_cmd_bytes));                                  \
	}                                                                                                                                 \
})

/* this is only relevant for commands, which are beyond checkpoint version==1 */
static inline bool ZSENDING_FEATURE_SUPPORTED(struct send_cp_ctx *sctx, u64 flag, bool *out_replaying)
{
	bool replaying = (sctx->n_cmds_to_skip > 0 || sctx->offset_in_write_cmd_bytes_to_skip > 0);
	bool supported = replaying ? (sctx->replay_stream_flags & flag) : (sctx->gen_stream_flags & flag);

	*out_replaying = replaying;
	return supported;
}

static inline const char*  send_cmd_to_str(u16 cmd)
{
	static const char* cmd_to_str[] = {
		[BTRFS_SEND_C_UNSPEC]        = "UNSPEC",

		[BTRFS_SEND_C_SUBVOL]        = "SUBVOL",
		[BTRFS_SEND_C_SNAPSHOT]      = "SNAPSHOT",

		[BTRFS_SEND_C_MKFILE]        = "MKFILE",
		[BTRFS_SEND_C_MKDIR]         = "MKDIR",
		[BTRFS_SEND_C_MKNOD]         = "MKNOD",
		[BTRFS_SEND_C_MKFIFO]        = "MKFIFO",
		[BTRFS_SEND_C_MKSOCK]        = "MKSOCK",
		[BTRFS_SEND_C_SYMLINK]       = "SYMLINK",

		[BTRFS_SEND_C_RENAME]        = "RENAME",
		[BTRFS_SEND_C_LINK]          = "LINK",
		[BTRFS_SEND_C_UNLINK]        = "UNLINK",
		[BTRFS_SEND_C_RMDIR]         = "RMDIR",

		[BTRFS_SEND_C_SET_XATTR]     = "SET_XATTR",
		[BTRFS_SEND_C_REMOVE_XATTR]  = "REMOVE_XATTR",

		[BTRFS_SEND_C_WRITE]         = "WRITE",
		[BTRFS_SEND_C_CLONE]         = "CLONE",

		[BTRFS_SEND_C_TRUNCATE]      = "TRUNCATE",
		[BTRFS_SEND_C_CHMOD]         = "CHMOD",
		[BTRFS_SEND_C_CHOWN]         = "CHOWN",
		[BTRFS_SEND_C_UTIMES]        = "UTIMES",

		[BTRFS_SEND_C_END]           = "END",
		[BTRFS_SEND_C_UPDATE_EXTENT] = "UPD_EXT",

		[BTRFS_SEND_C_ZWRITE_ALIGNED]= "ZWRITE_ALIGNED",
		[BTRFS_SEND_C_ZUNMAP]        = "ZUNMAP",
	};

	if (unlikely(cmd > BTRFS_SEND_C_MAX))
		return "???";

	return cmd_to_str[cmd];
}

static int is_bv_extent_unchanged(struct send_cp_ctx *sctx, struct btrfs_path *left_path, struct btrfs_key *ekey)
{
	int ret = 0;
	struct btrfs_key key;
	struct btrfs_path *path = NULL;
	struct extent_buffer *eb = NULL;
	int slot = -1;
	struct btrfs_key found_key;
	struct btrfs_bv_file_extent_item *bfei = NULL;
	u64 left_disknr = 0, right_disknr = 0;

	path = alloc_path_for_send();
	if (!path)
		return -ENOMEM;

	eb = left_path->nodes[0];
	slot = left_path->slots[0];
	bfei = btrfs_item_ptr(eb, slot, struct btrfs_bv_file_extent_item);
	left_disknr = btrfs_bv_file_extent_disk_bytenr(eb, bfei);

	ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "(%llu,%llu): ekey(%llu EXTENT_DATA %llu) Lextent(disknr=%llu)",
		          sctx->base.cur_ino, sctx->base.cur_inode_gen, ekey->objectid, ekey->offset, left_disknr);

	/*
	 * In block-virt architecture, the only case when we can say "yes"
	 * in the outcome of this function, is if the right tree has an
	 * extent at the same offset with the same disknr.
	 */
	key.objectid = ekey->objectid;
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = ekey->offset;
	ret = btrfs_search_slot_for_read(sctx->base.parent_root, &key, path, 0, 0);
	if (ret < 0)
		goto out;
	if (ret) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "(%llu,%llu): ekey(%llu EXTENT_DATA %llu) nothing found on parent",
			          sctx->base.cur_ino, sctx->base.cur_inode_gen, ekey->objectid, ekey->offset);
		ret = 0;
		goto out;
	}

	/* 
	 * we need to see exactly the same key;
	 * this also covers the case of no extents at all at the right side
	 */
	eb = path->nodes[0];
	slot = path->slots[0];
	btrfs_item_key_to_cpu(eb, &found_key, slot);
	if (found_key.objectid != key.objectid ||
		found_key.type != key.type ||
		found_key.offset != key.offset) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "(%llu,%llu): ekey(%llu EXTENT_DATA %llu) Rkey(%llu %u %llu) - changed",
				  sctx->base.cur_ino, sctx->base.cur_inode_gen, 
				  ekey->objectid, ekey->offset,
				  found_key.objectid, found_key.type, found_key.offset);
		ret = 0;
		goto out;
	}

	if (!btrfs_is_bv_file_extent_item(eb, slot)) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "(%llu,%llu): ekey(%llu EXTENT_DATA %llu) Rkey(%llu %u %llu) - not block-virt!!!",
			      sctx->base.cur_ino, sctx->base.cur_inode_gen, 
			      ekey->objectid, ekey->offset,
			      found_key.objectid, found_key.type, found_key.offset);
		ret = -EPROTO;
		goto out;
	}

	bfei = btrfs_item_ptr(eb, slot, struct btrfs_bv_file_extent_item);
	right_disknr = btrfs_bv_file_extent_disk_bytenr(eb, bfei);

	if (left_disknr == right_disknr)
		ret = 1;
	else
		ret = 0;
	ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "(%llu,%llu): ekey(%llu EXTENT_DATA %llu) Lextent(disknr=%llu) Rextent(disknr=%llu) %s",
		      sctx->base.cur_ino, sctx->base.cur_inode_gen, 
		      ekey->objectid, ekey->offset,
		      left_disknr, right_disknr,
		      ret == 0 ? "CHANGED" : "NOT CHANGED");

out:
	btrfs_free_path(path);
	return ret;
}

/*
 * With block-virt architecture, we don't update INODE_ITEM on every write.
 * So it may happen that an EXTENT_DATA changed, but INODE_ITEM didn't.
 * As a result, we will not process the changed_inode() callback, which sets cur_no, cur_ino_gen etc.
 * So here we simulate this callback only for this specific case.
 * Note that if inode was deleted, or a  new inode was created, or the same inode 
 * was deleted+created (cur_inode_new_gen), we WILL receive the changed_inode() notification 
 * and sctx->cur_ino will be updated at this point.
 * UPDATE: now that we have ztenant accounting in btrfs_inode_item.block_group, we
 *         should receive CHANGED callbacks for INODE_ITEMs too, but there could be old
 *         block-virt inodes, which do not have a ztenant.
 */
static int simulate_changed_inode_if_needed(struct send_cp_ctx *sctx)
{
	int ret = 0;

	if (sctx->base.cmp_key->type == BTRFS_EXTENT_DATA_KEY &&
		sctx->base.cmp_key->objectid != BTRFS_FREE_INO_OBJECTID &&
		sctx->base.cmp_key->objectid != BTRFS_FREE_SPACE_OBJECTID &&
		sctx->base.cur_ino != sctx->base.cmp_key->objectid) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "Simulating changed_inode(CHG) for ino(%llu)", sctx->base.cmp_key->objectid);

		/* we are starting to handle a new inode - finish previous one */
		ret = finish_inode_if_needed(&sctx->base, 0/*at_end*/);
		if (ret < 0)
			goto out;

		sctx->base.cur_ino = sctx->base.cmp_key->objectid;
		sctx->base.send_progress = sctx->base.cur_ino;
		
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB2, ZKLOG_TAG_SR, "Now sp=%llu", sctx->base.send_progress);

		sctx->base.cur_inode_new = 0;
		sctx->base.cur_inode_new_gen = 0;
		sctx->base.cur_inode_deleted = 0;
		sctx->base.cur_inode_last_extent = (u64)-1;

		ret = get_inode_info(sctx->base.send_root, sctx->base.cur_ino,
			                 &sctx->base.cur_inode_size,
			                 &sctx->base.cur_inode_gen,
			                 &sctx->base.cur_inode_mode,
			                 NULL/*uid*/, NULL/*gid*/, NULL/*rdev*/);
		if (ret < 0)
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "get_inode_info(root=%llu,ino=%llu) failed, ret=%d",
			              sctx->base.send_root->objectid, sctx->base.cur_ino, ret);
	}

out:
	return ret;
}

static void record_checkpoint(struct send_cp_ctx *sctx, struct btrfs_compare_trees_checkpoint *tree_cp)
{
	struct btrfs_send_checkpoint old_cp;
	struct btrfs_send_checkpoint *new_cp = &sctx->curr_cp;

	/* Cannot take a checkpoint, if we have a context that we don't save */
	if (!list_empty(&sctx->base.new_refs) || !list_empty(&sctx->base.deleted_refs))
		return;

	/* this should not happen in block-virt configuration */
	if (ZBTRFS_WARN_ON(!RB_EMPTY_ROOT(&sctx->base.pending_dir_moves)) ||
		ZBTRFS_WARN_ON(!RB_EMPTY_ROOT(&sctx->base.waiting_dir_moves)) ||
		ZBTRFS_WARN_ON(!RB_EMPTY_ROOT(&sctx->base.orphan_dirs)))
		return;

	/* ---- For testing only --------- */
	/*
	 * we want to test cases with large n_cmds_since_cp.
	 * for this, we will record only the first checkpoint
	 */
	if (unlikely(ZSEND_TEST.long_replay)) {
		if (BTRFS_HAS_SEND_CHECKPOINT(&sctx->curr_cp)) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_CHCKP, "subvol[%llu]: <TEST> not recording checkpoint!!!", sctx->base.send_root->objectid);
			return;
		}
	}
	/* ------------------------------- */

	/* Take checkpoint */
	old_cp                            = sctx->curr_cp;
	new_cp->tree_cmp_cp               = *tree_cp;

	/*
	 * we don't save fields like cur_inode_rdev/cur_inode_last_extent, because
	 * we use this code only for block-virt inodes, and for them
	 * these fields are irrelevant.
	 * actually, some of the fields we do save, like cur_inode_size, are also
	 * irrelevant for block-virt inodes.
	 */
	new_cp->cur_ino                   = cpu_to_le64(sctx->base.cur_ino);
	new_cp->cur_inode_gen             = cpu_to_le64(sctx->base.cur_inode_gen);
	new_cp->cur_inode_new             = sctx->base.cur_inode_new;     /* u8 */
	new_cp->cur_inode_new_gen         = sctx->base.cur_inode_new_gen; /* u8 */
	new_cp->cur_inode_deleted         = sctx->base.cur_inode_deleted; /* u8 */
	new_cp->cur_inode_size            = cpu_to_le64(sctx->base.cur_inode_size);
	new_cp->cur_inode_mode            = cpu_to_le64(sctx->base.cur_inode_mode);
	new_cp->send_progress             = cpu_to_le64(sctx->base.send_progress);

	/* checkpoint means we can reset those two counters */
	new_cp->n_cmds_since_cp           = cpu_to_le64(0);
	new_cp->offset_in_write_cmd_bytes = cpu_to_le64(0);

	ZKLOG_PRINT_CP(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_CHCKP, new_cp);

	/*
	 * If the compare_tree checkpoint is identical and we have already produced
	 * some commands, this is a bug. 
	 * If it's identical, but we haven't produced any commands, this is a warning.
	 */
	if (memcmp(&old_cp.tree_cmp_cp, &new_cp->tree_cmp_cp, 
		       sizeof(struct btrfs_compare_trees_checkpoint)) == 0) {
		if (le64_to_cpu(old_cp.n_cmds_since_cp) > 0 || le64_to_cpu(old_cp.offset_in_write_cmd_bytes) > 0) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_CHCKP,
				      "subvol[%llu]: Identical tree cp! n_cmds_since_cp=%llu  offset_in_write_cmd_bytes=%llu",
				      sctx->base.send_root->objectid,
				      le64_to_cpu(old_cp.n_cmds_since_cp), le64_to_cpu(old_cp.offset_in_write_cmd_bytes));
			ZBTRFS_WARN_ON(1);
		} else {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_CHCKP, "subvol[%llu]: Identical tree cp!", sctx->base.send_root->objectid);
			ZBTRFS_WARN_ON(1);
		}
	}
}

static void user_buffer_assert(struct send_cp_ctx *sctx, u32 l_bytes, u32 r_bytes, int check_out_buffer_full)
{
	/* Sanity check on free space in our buffer */
	ZBTRFS_BUG_ON(check_out_buffer_full && sctx->out_buffer_full);
	ZBTRFS_BUG_ON(sctx->out_buffer_l_bytes + sctx->out_buffer_r_bytes > sctx->out_buffer_size_bytes);

	ZBTRFS_BUG_ON(!BYTES_ALIGNED_TO_BLK(r_bytes));
	ZBTRFS_BUG_ON(!BYTES_ALIGNED_TO_BLK(sctx->out_buffer_r_bytes));

	if (l_bytes > 0 || r_bytes > 0)
		ZBTRFS_BUG_ON(sctx->out_buffer_l_bytes + l_bytes + sctx->out_buffer_r_bytes + r_bytes > sctx->out_buffer_size_bytes);
}

static u32 user_buffer_get_free_bytes(struct send_cp_ctx *sctx)
{
	user_buffer_assert(sctx, 0/*l*/, 0/*r*/, 1/*check_full*/);

	return
		sctx->out_buffer_size_bytes - (sctx->out_buffer_l_bytes + sctx->out_buffer_r_bytes);
}

static int user_buffer_can_push_cmd(struct send_cp_ctx *sctx, u16 cmd, u32 mdata_len_bytes)
{
	int ret = 0;
	u32 bytes_free = 0;

	ZBTRFS_BUG_ON(cmd > BTRFS_SEND_C_MAX);

	bytes_free = user_buffer_get_free_bytes(sctx);
	switch (cmd) {
		case BTRFS_SEND_C_ZWRITE_ALIGNED:
			/* we should be able to push at least one sector */
			ret = (bytes_free >= mdata_len_bytes + ONE_BLK);
			break;
		default:
			/* rest of commands contain only metadata and we cannot break them */
			ret = (bytes_free >= mdata_len_bytes);
			break;
	}

	return ret;
}

/*
 * Called when we have added some useful data into the user buffer, 
 * when handling a particular command.
 */
static void user_buffer_account_data(struct send_cp_ctx *sctx, u16 cmd, u32 l_data_len, u32 r_data_len)
{
	user_buffer_assert(sctx, l_data_len, r_data_len, 1/*check_full*/);

	sctx->out_buffer_l_bytes += l_data_len;
	sctx->out_buffer_r_bytes += r_data_len;
}

static int user_buffer_pad_to_zero(struct send_cp_ctx *sctx)
{
	int ret = 0;

	/* this is called when we are finishing the current buffer, so out_buffer_full may be set */
	user_buffer_assert(sctx, 0/*l*/, 0/*r*/, 0/*check_full*/);

	if (sctx->out_buffer_r_bytes > 0) {
		u32 num_bytes_to_clear = sctx->out_buffer_size_bytes - sctx->out_buffer_l_bytes - sctx->out_buffer_r_bytes;

		ret = clear_user(sctx->out_buffer + sctx->out_buffer_l_bytes, num_bytes_to_clear);
		if (ret != 0) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: clear_user(off=%u len=%u) failed ret=%d",
				          sctx->base.send_root->objectid, sctx->out_buffer_l_bytes, num_bytes_to_clear, ret);
			ret = -EFAULT;
		}
	}

	return ret;
}

/*
 * Updates tracking info for a command that was either fully sent or fully skipped.
 * Used for both WRITE and non-WRITE commands.
 * Resets send_size for the next command.
 */
static void __cmd_fully_sent(struct send_cp_ctx *sctx, u16 cmd, int skipped)
{
	/* Update our tracking info */

	sctx->curr_cp.n_cmds_since_cp = cpu_to_le64(le64_to_cpu(sctx->curr_cp.n_cmds_since_cp) + 1);
	/* Since the command was fully sent/skipped, let's be explicit and reset this */
	sctx->curr_cp.offset_in_write_cmd_bytes = cpu_to_le64(0);

	if (skipped) {
		ZBTRFS_BUG_ON(sctx->n_cmds_to_skip == 0);
		--sctx->n_cmds_to_skip;
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: skipping cmd:%s, left to skip: %llu (n_cmds_since_cp=%llu)", 
			          sctx->base.send_root->objectid, send_cmd_to_str(cmd), sctx->n_cmds_to_skip, le64_to_cpu(sctx->curr_cp.n_cmds_since_cp));

		/* we must not touch offset_in_write_cmd_bytes_to_skip here */
	} else {
		/* If we are not skipping, we mustn't have any leftovers */
		ZBTRFS_BUG_ON(sctx->n_cmds_to_skip > 0);
		/*
		 * If we have not skipped this command, then we must reset this,
		 * because the command was processed fully, and we may be processing
		 * more WRITE commands in this batch.
		 */
		sctx->offset_in_write_cmd_bytes_to_skip = 0;
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: sent cmd:%s (n_cmds_since_cp=%llu)", 
			          sctx->base.send_root->objectid, send_cmd_to_str(cmd), le64_to_cpu(sctx->curr_cp.n_cmds_since_cp));
	}

	sctx->base.send_size = 0; /* This is most important - for next command */
}

/*
 * Command is ready on send_buf, and send_size is the total command size.
 * Set up the correct length and command header and calculate CRC.
 * Then copy the whole command to the user buffer and update data accounting.
 * This function is used only for non-WRITE commands, as for WRITE commands
 * user buffer is filled in multiple steps.
 */
static int __finalize_non_write_cmd(struct send_cp_ctx *sctx)
{
	int ret = 0;
	struct btrfs_cmd_header *hdr = (struct btrfs_cmd_header*)sctx->base.send_buf;
	u16 cmd = le16_to_cpu(hdr->cmd);
	u32 crc = 0;

	hdr->len = cpu_to_le32(sctx->base.send_size - sizeof(struct btrfs_cmd_header));
	hdr->crc = cpu_to_le32(0);

	crc = btrfs_crc32c(0, sctx->base.send_buf, sctx->base.send_size);
	hdr->crc = cpu_to_le32(crc);

	user_buffer_assert(sctx, sctx->base.send_size/*l_bytes*/, 0/*r_bytes*/, 1/*check_full*/);
	ret = copy_to_user(sctx->out_buffer + sctx->out_buffer_l_bytes/*to*/,
		               sctx->base.send_buf, sctx->base.send_size);
	if (ret != 0) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: cmd:%u(len=%u) copy_to_user() failed, ret=%d",
			          sctx->base.send_root->objectid, cmd, sctx->base.send_size,
			          ret);
		ret = -EFAULT;
		goto out;
	}

	user_buffer_account_data(sctx, cmd, sctx->base.send_size/*l_data_len*/, 0/*r_data_len*/);

out:
	return ret;
}

/*
 * This replaces the normal "send_cmd" for non-WRITE commands.
 * At this point the command header + data are already set up on send_buf,
 * but the header does not include len and crc.
 * send_size is the total command size.
 */
static int zsend_non_write_cmd(struct send_ctx *base)
{
	int ret = 0;
	struct send_cp_ctx *sctx = container_of(base, struct send_cp_ctx, base);
	u16 cmd = le16_to_cpu(((struct btrfs_cmd_header*)sctx->base.send_buf)->cmd);
	int skipped = 1;

	ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: %s", sctx->base.send_root->objectid, send_cmd_to_str(cmd));

	/* We shouldn't get here with a non-write command */
	ZBTRFS_BUG_ON(cmd == BTRFS_SEND_C_ZWRITE_ALIGNED);

	if (sctx->n_cmds_to_skip == 0) {
		/* We are going to push this command, so assert we have no leftovers from skipping */
		if (ZBTRFS_WARN(sctx->n_cmds_to_skip > 0 || sctx->offset_in_write_cmd_bytes_to_skip > 0,
			"subvol[%llu]: cmd=%s but: n_cmds_to_skip=%llu offset_in_write_cmd_bytes_to_skip=%llu",
			sctx->base.send_root->objectid, send_cmd_to_str(cmd),
			sctx->n_cmds_to_skip, sctx->offset_in_write_cmd_bytes_to_skip)) {
			ret = -EILSEQ;
			goto out;
		}

		/* Sanity check on free space in our buffer */
		user_buffer_assert(sctx, 0/*l*/, 0/*r*/, 1/*check_full*/);

		/* 
		 * For block-virt we are sending only a few of non-WRITE commands, and we treat them very specially:
		 * RENAME: when a new vol is added to the CG (or new CG is created)
		 * UNLINK: when vol is deleted from the CG, but we don't support this right now
		 * END: end-of-stream
		 * UNMAP: chunk was unmapped on the source, need to unmap it on dest as well
		 * Note1: non-WRITE commands are still acounted for checkpointing, even if we don't send this command
		 * Note2: here is why handling of RENAME and UNLINK is enough to handle volume addition and deletion with block-virt:
		 *        - we have only regular files in the top dir of the subvolume, and no other dirs or special files etc.
		 *        - we never rename/move/add hardlinks etc for our block-virt files (only create or delete them)
		 *        - VAM ensures that file names are never re-used during CG lifetime
		 *        So with block-virt we never have issues, like "overwriting first ref" or so, and, therefore, the only cases that we need to handle:
		 *        - new file is created: send-stream will push MKFILE + RENAME commands, of which we only pass the RENAME
		 *        - file is deleted:     send-stream will have simple UNLINK command (no orphanizing etc.)
		 */
		if (cmd == BTRFS_SEND_C_RENAME ||
			cmd == BTRFS_SEND_C_END    ||
			cmd == BTRFS_SEND_C_ZUNMAP) {

			/* Check if command can fit in the user buffer */
			if (!user_buffer_can_push_cmd(sctx, cmd, sctx->base.send_size/*mdata_len_bytes*/)) {
				/*
				 * This command cannot be sent fully, and this is not a WRITE command,
				 * so we must give up, because we cannot break non-WRITE commands.
				 */
				ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: cmd:%s(len=%u) cannot fit, used %u+%u=%u/%u",
				          sctx->base.send_root->objectid, send_cmd_to_str(cmd), sctx->base.send_size,
				          sctx->out_buffer_l_bytes, sctx->out_buffer_r_bytes, sctx->out_buffer_l_bytes + sctx->out_buffer_r_bytes,
				          sctx->out_buffer_size_bytes);
				/* Signal that this is not a real overflow */
				sctx->out_buffer_full = 1;
				ret = -EOVERFLOW;
				goto out;
			}

			/* Send the command */
			ret = __finalize_non_write_cmd(sctx);
			if (ret < 0)
				goto out;
		}

		skipped = 0;
	}

	__cmd_fully_sent(sctx, cmd, skipped);

	/* ---- For testing only --------- */
	if (unlikely(ZSEND_TEST.one_cmd_per_buffer)) {
		if (!skipped && (cmd == BTRFS_SEND_C_RENAME || cmd == BTRFS_SEND_C_ZUNMAP)) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR, "subvol[%llu]: BV<TEST> signalling buffer-full after cmd:%s",
				          sctx->base.send_root->objectid, send_cmd_to_str(cmd));
			sctx->out_buffer_full = 1;
			ret = -EOVERFLOW;
		}
	}
	/* ------------------------------- */

out:
	/* In block-virt mode, if we are done with this buffer, pad it to zero in case we have some right data */
	if ((ret == -EOVERFLOW && sctx->out_buffer_full) ||
		(ret == 0 && cmd == BTRFS_SEND_C_END)) {
		 int pad_ret = 0;

		/*
		 * Do not modify "ret" here, unless user_buffer_pad_to_zero fails.
		 * Also make sure user_buffer_pad_to_zero() doesn't return -EOVERFLOW.
		 */
		pad_ret = user_buffer_pad_to_zero(sctx);
		if (pad_ret != 0) {
			ZBTRFS_BUG_ON(pad_ret == -EOVERFLOW);
			ret = pad_ret;
		}
	}

	return ret;
}

/*
 * Setup the BTRFS_SEND_C_ZWRITE_ALIGNED header, 
 * and all the TLVs, except BTRFS_SEND_A_DATA_SECTORS_FROM_RIGHT.
 * For BTRFS_SEND_A_DATA_SECTORS_FROM_RIGHT: set up only the TLV header with correct tlv_type, but no tlv_len yet.
 * On successful completion, send_size is updated to hold the amount of data on send_buf.
 */
static int __setup_write_cmd_wo_data(struct send_cp_ctx *sctx, u64 offset_in_file_bytes, struct btrfs_tlv_header* *out_data_tlv_hdr)
{
	int ret = 0;
	struct fs_path *p = NULL;

	p = fs_path_alloc();
	if (!p)
		return -ENOMEM;

	/* This sets up the command header */
	ret = begin_cmd(&sctx->base, BTRFS_SEND_C_ZWRITE_ALIGNED);
	if (ret < 0)
		goto out;

	ret = get_cur_path(&sctx->base, sctx->base.cur_ino, sctx->base.cur_inode_gen, p);
	if (ret < 0)
		goto out;

	TLV_PUT_PATH(&sctx->base, BTRFS_SEND_A_PATH, p);
	TLV_PUT_U64(&sctx->base, BTRFS_SEND_A_FILE_OFFSET, offset_in_file_bytes);

	/* Set up TLV header for BTRFS_SEND_A_DATA_SECTORS_FROM_RIGHT */
	{
		struct btrfs_tlv_header *data_hdr = NULL;
		u32 left = (sctx->base.send_max_size > sctx->base.send_size) ? sctx->base.send_max_size - sctx->base.send_size : 0;

		if (unlikely(left < sizeof(struct btrfs_tlv_header))) {
			ret = -EOVERFLOW;
			goto out;
		}

		data_hdr = (struct btrfs_tlv_header*)(sctx->base.send_buf + sctx->base.send_size);
		data_hdr->tlv_type = cpu_to_le16(BTRFS_SEND_A_DATA_SECTORS_FROM_RIGHT);

		*out_data_tlv_hdr = data_hdr;

		sctx->base.send_size += sizeof(struct btrfs_tlv_header);
	}

tlv_put_failure:
out:
	fs_path_free(p);
	return ret;
}

static int __fetch_write_cmd_data_blk_virt(struct send_cp_ctx *sctx, u64 offset_in_file_bytes, u32 nbytes_to_read,
	                                       struct btrfs_key *bfei_key, 
	                                       struct extent_buffer *leaf, int slot, struct btrfs_bv_file_extent_item *bfei,
	                                       u32 incr_crc, u32 *out_incr_crc)
{
	int ret = 0;
	struct btrfs_fs_info *fs_info = sctx->base.send_root->fs_info;
	u64 disk_bytenr = 0;
	u64 physical_bytenr = 0, final_physical_bytenr = 0;
	struct block_device *pool_data_bdev = sctx->base.send_root->fs_info->zfs_info.pool_data_bdev;
	struct bio_list completed_bios;
	struct bio *completed_bio = NULL;
	u32 nbytes_crced = 0;

	disk_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: (%llu %s %llu): d[%llu:%u] READ(%llu:%u)",
		      sctx->base.send_root->objectid,
		      bfei_key->objectid, btrfs_fs_key_type_to_str(btrfs_key_type(bfei_key)), bfei_key->offset,
		      disk_bytenr, fs_info->zfs_info.pool_gran_bytes, offset_in_file_bytes, nbytes_to_read);

	/* Do all the possible sanity checks we can... */
	ret = zbtrfs_blk_virt_check_bv_file_extent_item(sctx->base.send_root, bfei_key->objectid, bfei_key->offset,
				fs_info->zfs_info.pool_gran_bytes, leaf, slot, bfei);
	if (ret != 0)
		goto out;
	/* check that range that we were given is fully within the EXTENT_DATA */
	if (unlikely(offset_in_file_bytes < bfei_key->offset || offset_in_file_bytes + nbytes_to_read > bfei_key->offset + fs_info->zfs_info.pool_gran_bytes)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: (%llu %s %llu): READ(%llu:%u) is outside e[%llu:%u]",
				  sctx->base.send_root->objectid,
				  bfei_key->objectid, btrfs_fs_key_type_to_str(btrfs_key_type(bfei_key)), bfei_key->offset,
				  offset_in_file_bytes, nbytes_to_read, bfei_key->offset, fs_info->zfs_info.pool_gran_bytes);
		ret = -EINVAL;
		goto out;
	}
	if (unlikely(!BYTES_ALIGNED_TO_BLK(nbytes_to_read))) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: READ(%llu:%u) length is not aligned by BLOCK",
				  sctx->base.send_root->objectid,
				  offset_in_file_bytes, nbytes_to_read);
		ret = -EINVAL;
		goto out;
	}

	ret = zbtrfs_blk_virt_map_block(sctx->base.send_root->fs_info, 
				BTRFS_BLOCK_GROUP_DATA,
				disk_bytenr, fs_info->zfs_info.pool_gran_bytes,
				&physical_bytenr);
	if (ret != 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: (%llu %s %llu): d[%llu:%u] zbtrfs_blk_virt_map_block failed, ret=%d",
			      sctx->base.send_root->objectid,
			      bfei_key->objectid, btrfs_fs_key_type_to_str(btrfs_key_type(bfei_key)), bfei_key->offset,
			      disk_bytenr, fs_info->zfs_info.pool_gran_bytes, ret);
		goto out;
	}
	final_physical_bytenr = physical_bytenr + (offset_in_file_bytes - bfei_key->offset);

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: (%llu %s %llu): d[%llu:%u] READ(%llu:%u) mapped p(%llu->%llu:%u)",
			  sctx->base.send_root->objectid,
			  bfei_key->objectid, btrfs_fs_key_type_to_str(btrfs_key_type(bfei_key)), bfei_key->offset,
			  disk_bytenr, fs_info->zfs_info.pool_gran_bytes, offset_in_file_bytes, nbytes_to_read,
			  physical_bytenr, final_physical_bytenr, nbytes_to_read);

	/* Everything should be aligned nicely */
	if (!BYTES_ALIGNED_TO_BLK(final_physical_bytenr)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: (%llu %s %llu): d[%llu:%u] READ(%llu:%u) mapped p(%llu->%llu:%u) not aligned by BLOCK",
				  sctx->base.send_root->objectid,
				  bfei_key->objectid, btrfs_fs_key_type_to_str(btrfs_key_type(bfei_key)), bfei_key->offset,
				  disk_bytenr, fs_info->zfs_info.pool_gran_bytes, offset_in_file_bytes, nbytes_to_read,
				  physical_bytenr, final_physical_bytenr, nbytes_to_read);
		ret = -ECANCELED;
		goto out;
	}

	user_buffer_assert(sctx, 0/*l_bytes*/, nbytes_to_read/*r_bytes*/, 1/*check_full*/);

	/* read the data into user buffer */
	ret = zread_write_ubuff_sync_no_unmap(pool_data_bdev, 
		                         BYTES_TO_BLK(final_physical_bytenr), /*start_sector*/
		                         (sctx->out_buffer + sctx->out_buffer_size_bytes - sctx->out_buffer_r_bytes - nbytes_to_read)/*uaddr*/, nbytes_to_read/*nbytes*/,
		                         false/*bwrite*/, GFP_NOFS,
		                         &completed_bios);
	if (ret != 0) {
		char bname[BDEVNAME_SIZE] = {'\0'};

		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: read(%s:%llu:%u) failed, ret=%d",
			      sctx->base.send_root->objectid, bdevname(pool_data_bdev, bname), final_physical_bytenr, nbytes_to_read, ret);
		zread_write_ubuff_release_mapped_bios(&completed_bios);
		goto out;
	}

	/* account & crc */
	user_buffer_account_data(sctx, BTRFS_SEND_C_ZWRITE_ALIGNED, 0/*l_data_len*/, nbytes_to_read);
	/* 
	 * at this point, the user-space pages are pinned down, but we need to use
	 * kmap/kunmap to touch the buffers; as it turns out we cannot directly
	 * touch the user-space buffer. see documentation of get_user_pages()
	 * and also "Performing Direct I/O" chapter in LLD3.
	 */
	bio_list_for_each(completed_bio, &completed_bios) {
		struct bio_vec *bvec = NULL;
		unsigned int bvec_idx = 0;

		bio_for_each_segment_all(bvec, completed_bio, bvec_idx) {
			u8 *kaddr = kmap(bvec->bv_page);
			incr_crc = btrfs_crc32c(incr_crc, kaddr + bvec->bv_offset, bvec->bv_len);
			kunmap(bvec->bv_page);
			nbytes_crced += bvec->bv_len;
		}
	}
	*out_incr_crc = incr_crc;
	/* unpin the pages */
	zread_write_ubuff_release_mapped_bios(&completed_bios);

	/* this is more of a sanity check */
	if (ZBTRFS_WARN(nbytes_crced != nbytes_to_read,
		            "FS[%s]: subvol[%llu]: (%llu %s %llu): READ(%llu:%u) nbytes_crced(%u)!=nbytes_to_read(%u)",
		            fs_info->sb->s_id, sctx->base.send_root->objectid,
		            bfei_key->objectid, btrfs_fs_key_type_to_str(btrfs_key_type(bfei_key)), bfei_key->offset,
		            offset_in_file_bytes, nbytes_to_read, nbytes_crced, nbytes_to_read))
		ret = -ECANCELED;		            

out:
	return ret;
}

/*
 * This function does the actual work of sending some data from a block-virt file extent.
 * It also handles all the details of checkpointing etc.
 */
static int zsend_write_cmd_bv(struct send_cp_ctx *sctx, struct btrfs_key *bfei_key,
	                          struct extent_buffer *leaf, int slot,
	                          struct btrfs_bv_file_extent_item *bfei)
{
	int ret = 0;
	u64 offset_in_file_bytes = bfei_key->offset;
	u32 len_bytes = sctx->base.send_root->fs_info->zfs_info.pool_gran_bytes;
	struct btrfs_cmd_header *cmd_hdr = NULL;
	struct btrfs_tlv_header *data_hdr = NULL;
	u32 incr_crc = 0, crc_offset_in_user_buff = 0;
	u32 nbytes_to_send = 0;

	ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: ino(%llu,%llu) WR[%llu:%u]",
		          sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
		          offset_in_file_bytes, len_bytes);

	/* Check if we need to skip this command fully */
	if (sctx->n_cmds_to_skip > 0) {
		__cmd_fully_sent(sctx, BTRFS_SEND_C_ZWRITE_ALIGNED, 1/*skipped*/);
		goto out;
	}

	/* Check if we need to skip a part of this command */
	if (sctx->offset_in_write_cmd_bytes_to_skip > 0) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: ino(%llu,%llu) WR[%llu:%u] bytes_to_skip=%llu",
			          sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
			          offset_in_file_bytes, len_bytes,
			          sctx->offset_in_write_cmd_bytes_to_skip);

		/* If we need to skip the full WRITE or more than the WRITE, this is a bug */
		if (sctx->offset_in_write_cmd_bytes_to_skip >= len_bytes) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: ino(%llu,%llu) WR[%llu:%u] bytes_to_skip=%llu BUG???", 
				      sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
				      offset_in_file_bytes, len_bytes, sctx->offset_in_write_cmd_bytes_to_skip);
			ret = -EPROTO;
			goto out;
		}

		offset_in_file_bytes += sctx->offset_in_write_cmd_bytes_to_skip;
		len_bytes -= sctx->offset_in_write_cmd_bytes_to_skip;
	}

	/*
	 * Set up command header and all TLVs, except for BTRFS_SEND_A_DATA;
	 * for this TLV, set up only the TLV header.
	 */
	ret = __setup_write_cmd_wo_data(sctx, offset_in_file_bytes, &data_hdr);
	if (ret < 0)
		goto out;
	/* send_size at this point includes the BTRFS_SEND_A_DATA TLV */

	user_buffer_assert(sctx, 0/*l*/, 0/*r*/, 1/*check_full*/);

	/* 
	 * We need to be able to send command header, all TLVs and "some" data.
	 * If we're unable, signal overflow.
	 * BUT: if we had to skip part of this WRITE, we *should* be able,
	 * otherwise, this is a bug.
	 */
	if (!user_buffer_can_push_cmd(sctx, BTRFS_SEND_C_ZWRITE_ALIGNED, sctx->base.send_size/*mdata_len_bytes*/)) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: ino(%llu,%llu) WR[%llu:%u] cannot fit metadata, used %u+%u=%u/%u",
		          sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
		          offset_in_file_bytes, len_bytes,
		          sctx->out_buffer_l_bytes, sctx->out_buffer_r_bytes, sctx->out_buffer_l_bytes + sctx->out_buffer_r_bytes,
		          sctx->out_buffer_size_bytes);

		if (sctx->offset_in_write_cmd_bytes_to_skip > 0) {
			/* 
			 * We should send a partial WRITE command, and it should be the first 
			 * command for this buffer. So we should be able to send *something*.
			 */
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: cannot fit metadata on partial WRITE", sctx->base.send_root->objectid);
			ret = -EPROTO;
			goto out;
		}

		/* Signal that this is not a real overflow */
		sctx->out_buffer_full = 1;
		ret = -EOVERFLOW;
		goto out;
	}

	/* Check how much data we can actually send */
	nbytes_to_send = user_buffer_get_free_bytes(sctx);
	/* account the metadata */
	ZBTRFS_BUG_ON(nbytes_to_send <= sctx->base.send_size);
	nbytes_to_send -= sctx->base.send_size;
	/* truncate further as needed */
	if (nbytes_to_send > len_bytes)
		nbytes_to_send = len_bytes;
	if (!BYTES_ALIGNED_TO_BLK(nbytes_to_send))
		nbytes_to_send = BYTES_TRUNCATE_TO_BLK(u32, nbytes_to_send);
	ZBTRFS_BUG_ON(nbytes_to_send == 0);
	ZBTRFS_BUG_ON(!BYTES_ALIGNED_TO_BLK(nbytes_to_send));

	/* Update the metadata of the command to reflect the amount of data we are going to send */
	cmd_hdr = (struct btrfs_cmd_header*)sctx->base.send_buf;
	cmd_hdr->len = cpu_to_le32(sctx->base.send_size + nbytes_to_send - sizeof(struct btrfs_cmd_header));
	cmd_hdr->crc = cpu_to_le32(0);
	{
		u32 tlv_len_u32 = 0;

		/* here length is in sectors, data is on the right side */

		/* tlv_len is u16 in the send-stream, make sure we don't overflow it */
		tlv_len_u32 = BYTES_TO_BLK(nbytes_to_send);
		if (unlikely(tlv_len_u32 > MAX_U16)) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR,
				          "subvol[%llu]: ino(%llu,%llu) WR[%llu:%u]: nbytes_to_send=%u won't fit in U16 when convered to blocks(%u)",
				          sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
				          offset_in_file_bytes, len_bytes,
				          nbytes_to_send, tlv_len_u32);
			ret = -ECANCELED;
			goto out;
		}

		data_hdr->tlv_len = cpu_to_le16((u16)tlv_len_u32);
	}

	/* Calculate the incremental crc, up to and including the last TLV, based on the header that still contains crc=0 */
	incr_crc = btrfs_crc32c(0/*seed*/, sctx->base.send_buf, sctx->base.send_size);
	crc_offset_in_user_buff = sctx->out_buffer_l_bytes + offsetof(struct btrfs_cmd_header, crc);

	/* Copy all the metadata onto the user buffer at the correct place */
	user_buffer_assert(sctx, sctx->base.send_size/*l_bytes*/, 0/*r*/, 1/*check_full*/);
	ret = copy_to_user(sctx->out_buffer + sctx->out_buffer_l_bytes, sctx->base.send_buf, sctx->base.send_size);
	if (ret != 0) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: ino%llu,%llu) WR[%llu:%u] copy_to_user(%u) of metadata failed ret=%d",
			      sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
			      offset_in_file_bytes, len_bytes,
			      sctx->base.send_size,
			      ret);
		ret = -EFAULT;
		goto out;
	}
	user_buffer_account_data(sctx, BTRFS_SEND_C_ZWRITE_ALIGNED, sctx->base.send_size/*l_data_len*/, 0/*r_data_len*/);

	/* Read the data from the file, copy onto user buffer, update the crc incrementally */
	ret = __fetch_write_cmd_data_blk_virt(sctx, offset_in_file_bytes, nbytes_to_send, 
	                                      bfei_key, leaf, slot, bfei,
	                                      incr_crc, &incr_crc);
	if (ret < 0)
		goto out;

	/* All the data is on the user buffer, except crc; we need to copy it there */
	incr_crc = cpu_to_le32(incr_crc);
	ret = copy_to_user(sctx->out_buffer + crc_offset_in_user_buff, &incr_crc, sizeof(incr_crc));
	if (ret != 0) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: ino(%llu,%llu) WR[%llu:%u] copy_to_user(%lu) of crc failed ret=%d",
			          sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
			          offset_in_file_bytes, len_bytes,
			          sizeof(incr_crc),
			          ret);
		ret = -EFAULT;
		goto out;
	}

	/* Update checkpoint-related info */
	if (nbytes_to_send < len_bytes) {
		/* 
		 * We haven't completed this WRITE, therefore, we cannot increment n_cmds_since_cp.
		 * We need to set offset_in_write_cmd_bytes correctly and signal to bail out.
		 */
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: ino(%llu,%llu) WR[%llu:%u] sent only %u bytes",
		              sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
		              offset_in_file_bytes, len_bytes,
		              nbytes_to_send);
		sctx->curr_cp.offset_in_write_cmd_bytes = cpu_to_le64(sctx->offset_in_write_cmd_bytes_to_skip + nbytes_to_send);

		/*
		 * We are going to bail out here, so don't bother updating 
		 * n_cmds_to_skip/offset_in_write_cmd_bytes_to_skip here.
		 */
		/* don't bother setting send_size to 0 here, we're bailing out */

		/* Signal that this is not a real overflow */
		sctx->out_buffer_full = 1;
		ret = -EOVERFLOW;
	} else {
		__cmd_fully_sent(sctx, BTRFS_SEND_C_ZWRITE_ALIGNED, 0/*skipped*/);

		/* ---- For testing only --------- */
		if (unlikely(ZSEND_TEST.one_cmd_per_buffer)) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR, "subvol[%llu]: <TEST> signalling buffer-full",
				          sctx->base.send_root->objectid);
			sctx->out_buffer_full = 1;
			ret = -EOVERFLOW;
		}
		/* ------------------------------- */
	}

out:
	if (ret == -EOVERFLOW && sctx->out_buffer_full) {
		int pad_ret = 0;

		/*
		 * Do not modify "ret" here, unless user_buffer_pad_to_zero fails.
		 * Also make sure user_buffer_pad_to_zero() doesn't return -EOVERFLOW.
		 */
		pad_ret = user_buffer_pad_to_zero(sctx);
		if (pad_ret != 0) {
			ZBTRFS_BUG_ON(pad_ret == -EOVERFLOW);
			ret = pad_ret;
		}
	}

	return ret;
}

static int process_bv_extent(struct send_cp_ctx *sctx, struct btrfs_path *left_path, struct btrfs_key *bfei_key)
{
	int ret = 0;
	struct btrfs_bv_file_extent_item *bfei = NULL;

	if (unlikely(!btrfs_is_bv_file_extent_item(left_path->nodes[0], left_path->slots[0]))) {
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu] (%llu EXTENT_DATA %llu) is not a block-virt item!!!",
			          sctx->base.send_root->objectid, bfei_key->objectid, bfei_key->offset);
		ret = -EPROTO;
		goto out;
	}

	if (sctx->base.parent_root && !sctx->base.cur_inode_new) {
		ret = is_bv_extent_unchanged(sctx, left_path, bfei_key);
		if (ret < 0)
			goto out;
		if (ret) {
			ret = 0;
			goto out;
		}
	}

	bfei = btrfs_item_ptr(left_path->nodes[0], left_path->slots[0], struct btrfs_bv_file_extent_item);
	ret = zsend_write_cmd_bv(sctx, bfei_key, left_path->nodes[0], left_path->slots[0], bfei);

out:
	return ret;
}

/*
 * Indicates that a particular (inum, EXTENT_DATA, offset) item exists on the right tree,
 * but is missing on the left tree (and no other EXTENT_DATA sits on the same offset).
 * We need to send an UNMAP command (if we support it).
 */
static int process_deleted_bv_extent(struct send_cp_ctx *sctx, struct btrfs_path *right_path, struct btrfs_key *bfei_key)
{
	int ret = 0;
	u32 pool_gran_bytes = sctx->base.send_root->fs_info->zfs_info.pool_gran_bytes;
	bool unmap_supported = false, replaying_stream = false;
	struct fs_path *p = NULL;

	ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: ino(%llu,%llu) UNMAP(%llu:%u)",
		          sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
		          bfei_key->offset, pool_gran_bytes);

	/* ---- For testing only --------- */
	if (unlikely(ZSEND_TEST.force_cp_version)) {
		if (ZSEND_TEST.force_cp_version < BTRFS_SEND_CHECKPOINT_VERSION_2) {
			ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR,
				      "subvol[%llu]: ino(%llu,%llu) UNMAP(%llu:%u) <TEST> ignore UNMAP!!!",
					  sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen,
					  bfei_key->offset, pool_gran_bytes);
			goto out;
		}
	}
	/* ------------------------------- */

	/* sanity checks */
	if (unlikely(bfei_key->offset % pool_gran_bytes != 0)) {
		ZBTRFSLOG_TAG_RL(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR,
			"subvol[%llu] parent[%llu] bfei_key(%llu %s %llu) but gran=%u",
			sctx->base.send_root->objectid, sctx->base.parent_root->objectid,
			bfei_key->objectid, btrfs_fs_key_type_to_str(bfei_key->type), bfei_key->offset, pool_gran_bytes);
		ret = -EILSEQ;
		goto out;
	}
	if (!btrfs_is_bv_file_extent_item(right_path->nodes[0], right_path->slots[0])) {
		ZBTRFSLOG_TAG_RL(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR,
			"subvol[%llu] bfei_key(%llu %s %llu) but not bv_file_extent_item",
			sctx->base.send_root->objectid, bfei_key->objectid, btrfs_fs_key_type_to_str(bfei_key->type), bfei_key->offset);
		ret = -EILSEQ;
		goto out;
	}

	unmap_supported = ZSENDING_FEATURE_SUPPORTED(sctx, BTRFS_ZIOC_SEND_SUPPORT_UNMAP, &replaying_stream);
	if (replaying_stream && !unmap_supported) {
		/* 
		 * we are replaying a stream genereated by the send that did not support "unmap"
		 * we must behave as we don't support it either.
		 */
		ZBTRFSLOG_TAG_RL(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_CHCKP,
		                 "subvol[%llu] ignore UNMAP(%llu %s %llu) while replaying old send-stream",
		                 sctx->base.send_root->objectid, bfei_key->objectid, btrfs_fs_key_type_to_str(bfei_key->type), bfei_key->offset);
		goto out; /* ret == 0 */
	}

	/* form the UNMAP command */
	p = fs_path_alloc();
	if (p == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = begin_cmd(&sctx->base, BTRFS_SEND_C_ZUNMAP);
	if (ret < 0)
		goto out;

	ret = get_cur_path(&sctx->base, sctx->base.cur_ino, sctx->base.cur_inode_gen, p);
	if (ret < 0)
		goto out;

	TLV_PUT_PATH(&sctx->base, BTRFS_SEND_A_PATH, p);
	TLV_PUT_U64(&sctx->base, BTRFS_SEND_A_FILE_OFFSET, bfei_key->offset);
	TLV_PUT_U64(&sctx->base, BTRFS_SEND_A_CLONE_LEN, pool_gran_bytes);

	if (unmap_supported) {
		/*
		 * we are either replaying stream, produced by sender that accounted for "unmap",
		 * or we are generating new stream, and the receiver is OK to receive "unmap".
		 * this is the normal case.
		 */
		 ret = zsend_non_write_cmd(&sctx->base);
	} else {
		/* 
		 * we are generating a new stream, but the receive does not
		 * support "unmap". we must not put the "unmap" command on the
		 * stream, but we must account for it for checkpointing purposes.
		 */
		ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: only account ZUNMAP", sctx->base.send_root->objectid);
		__cmd_fully_sent(sctx, BTRFS_SEND_C_ZUNMAP, 0/*skipped*/);
	}

tlv_put_failure:	
out:
	fs_path_free(p);

	return ret;
}

static int bv_changed_extent(struct send_cp_ctx *sctx,  enum btrfs_compare_tree_result result)
{
	int ret = 0;
	
	ZBTRFS_BUG_ON(sctx->base.cur_ino != sctx->base.cmp_key->objectid);

	/* we care only for REG inodes here */
	if (unlikely(!S_ISREG(sctx->base.cur_inode_mode))) {
		ZBTRFSLOG_TAG_RL(sctx->base.send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR, "subvol[%llu] ino(%llu,%llu) mode=%llo not S_ISREG",
			             sctx->base.send_root->objectid, sctx->base.cur_ino, sctx->base.cur_inode_gen, sctx->base.cur_inode_mode);
		return 0;
	}

	if (!sctx->base.cur_inode_new_gen && !sctx->base.cur_inode_deleted) {
		if (result != BTRFS_COMPARE_TREE_DELETED)
			ret = process_bv_extent(sctx, sctx->base.left_path, sctx->base.cmp_key);
		else
			ret = process_deleted_bv_extent(sctx, sctx->base.right_path, sctx->base.cmp_key);
	}

	return ret;
}

static int bv_changed_cb(struct btrfs_root *left_root, struct btrfs_root *right_root,
		      struct btrfs_path *left_path, struct btrfs_path *right_path,
		      struct btrfs_key *key,
		      enum btrfs_compare_tree_result result,
		      struct btrfs_compare_trees_checkpoint *tree_cp,
		      void *ctx)
{
	
	int ret = 0;
	struct send_cp_ctx *sctx = ctx;

	ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "key(%llu,%s,%llu): %s",
				  key->objectid, btrfs_fs_key_type_to_str(key->type), key->offset,
				  btrfs_compare_tree_result_to_str(result));

	/* in our case, nothing to do in this case */
	if (result == BTRFS_COMPARE_TREE_SAME)
		return 0;

	sctx->base.left_path = left_path;
	sctx->base.right_path = right_path;
	sctx->base.cmp_key = key;

	ret = simulate_changed_inode_if_needed(sctx);
	if (ret < 0)
		goto out;

	record_checkpoint(sctx, tree_cp);

	ret = finish_inode_if_needed(&sctx->base, 0);
	if (ret < 0)
		goto out;

	/* Ignore non-FS objects */
	if (key->objectid == BTRFS_FREE_INO_OBJECTID ||
		key->objectid == BTRFS_FREE_SPACE_OBJECTID)
		goto out;

	if (key->type == BTRFS_INODE_ITEM_KEY) {
		switch (result) {
			/* for block-virt, we don't even have to handle "CHANGED" for INODE_ITEMs */
			case BTRFS_COMPARE_TREE_NEW:
			case BTRFS_COMPARE_TREE_CHANGED:
				ret = changed_inode(&sctx->base, result);
				break;
			default:
				ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, 
					          "key(%llu INODE_ITEM %llu) result=%s UNSUPPORTED",
					          key->objectid, key->offset, btrfs_compare_tree_result_to_str(result));
				ret = -EPROTO;
				break;
		}
	} else if (key->type == BTRFS_INODE_REF_KEY || key->type == BTRFS_INODE_EXTREF_KEY) {
		switch (result) {
			/* for block-virt only NEW we should have here */
			case BTRFS_COMPARE_TREE_NEW:
				ret = changed_ref(&sctx->base, result);
				break;
			default:
				ZBTRFSLOG_TAG(sctx->base.send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, 
					          "key(%llu %s %llu) result=%s UNSUPPORTED",
					          key->objectid, btrfs_fs_key_type_to_str(key->type), key->offset,
					          btrfs_compare_tree_result_to_str(result));
				ret = -EPROTO;
				break;
		}
	}
	else if (key->type == BTRFS_XATTR_ITEM_KEY) {
		/* just keep moving */
		ret = 0;
	}
	else if (key->type == BTRFS_EXTENT_DATA_KEY) {
		ret = bv_changed_extent(sctx, result);
	}

out:
	return ret;
}

static int send_bv_subvol_with_cp(struct send_cp_ctx *sctx, struct btrfs_compare_trees_checkpoint *tree_cp)
{
	int ret = 0;

#if 0
	We do not need the stream header
	ret = send_header(sctx);
	if (ret < 0)
		goto out;
#endif

#if 0
	We do not need this command.
	The subvolume/snapshot creation on destination will be done as part of Mirror application logic.
	ret = send_subvol_begin(sctx);
	if (ret < 0)
		goto out;
#endif

	if (sctx->base.parent_root) {
		ret = btrfs_compare_trees(sctx->base.send_root, sctx->base.parent_root,
				tree_cp,
				bv_changed_cb, sctx);
		if (ret < 0)
			goto out;
		ret = finish_inode_if_needed(&sctx->base, 1);
		if (ret < 0)
			goto out;
	} else {
		ret = full_send_tree(tree_cp, bv_changed_cb, &sctx->base);
		if (ret < 0)
			goto out;
	}

out:
	free_recorded_refs(&sctx->base);
	return ret;
}

long btrfs_ioctl_send_with_checkpoint(struct file *mnt_file, void __user *user_arg)
{
	int ret = 0;
	void *prev_journal_info = current->journal_info;
	struct btrfs_root *send_root = NULL;
	struct btrfs_ioctl_checkpoint_send_args *arg = NULL;
	struct btrfs_send_checkpoint *cp = NULL;
	struct send_cp_ctx *sctx = NULL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	send_root = BTRFS_I(file_inode(mnt_file))->root;

	/*
	 * The subvolume must remain read-only during send, protect against
	 * making it RW. This also protects against deletion.
	 */
	spin_lock(&send_root->root_item_lock);
	send_root->send_in_progress++;
	spin_unlock(&send_root->root_item_lock);

	/*
	 * This is done when we lookup the root, it should already be complete
	 * by the time we get here.
	 */
	ZBTRFS_WARN_ON(send_root->orphan_cleanup_state != ORPHAN_CLEANUP_DONE);

	/*
	 * Userspace tools do the checks and warn the user if it's
	 * not RO.
	 */
	if (!btrfs_root_readonly(send_root)) {
		ret = -EPERM;
		goto out;
	}

	/*
	 * Unlikely but possible, if the subvolume is marked for deletion but
	 * is slow to remove the directory entry, send can still be started
	 */
	if (btrfs_root_dead(send_root)) {
		ret = -EPERM;
		goto out;
	}

	/* grab the input parameters */
	arg = kmem_cache_alloc(zbtrfs_globals.send_arg_cachep, GFP_NOFS);
	if (unlikely(arg == NULL)) {
		ret = -ENOMEM;
		goto out;
	}
	ret = copy_from_user(arg, user_arg, sizeof(struct btrfs_ioctl_checkpoint_send_args));
	if (unlikely(ret)) {
		ret = -EFAULT;
		goto out;
	}

	ZBTRFSLOG_TAG(send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "SEND subvol[%llu] parent[%llu] fl=0x%llx", send_root->objectid, arg->parent_root, arg->flags);

	/* check the user buffer */
	if (arg->send_buffer == NULL || arg->send_buffer_size_bytes < BTRFS_ZIOC_MIN_SEND_SIZE_BYTES) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: send buffer NULL or too small: send_buff=%p, send_buff_size=%u",
			          send_root->objectid, arg->send_buffer, arg->send_buffer_size_bytes);
		ret = -EINVAL;
		goto out;
	}
	if (!(arg->flags & BTRFS_ZIOC_SEND_BLOCK_VIRT)) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR,
			          "subvol[%llu]: BTRFS_ZIOC_SEND_BLOCK_VIRT flag not set - only block-virt sends are supported!",
			          send_root->objectid);
		ret = -EINVAL;
		goto out;
	}
	/* for block-virt send, the buffer must be aligned by PAGE_SIZE by address and length (see issue #3847) */
	if ((uintptr_t)arg->send_buffer & (~PAGE_MASK) || arg->send_buffer_size_bytes & (~PAGE_MASK)) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: send buffer [%p:%u] not properly aligned by PAGE_SIZE(%lu)", 
				      send_root->objectid, arg->send_buffer, arg->send_buffer_size_bytes, PAGE_SIZE);
		ret = -EINVAL;
		goto out;
	}
	/* For block-virt, we must be properly mounted */
	if (!ZBTRFS_IS_BLKVIRT_MOUNT(send_root->fs_info)) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: not mounted as block-virt", send_root->objectid);
		ret = -ENODEV;
		goto out;
	}
	if (!access_ok(VERIFY_WRITE, arg->send_buffer, arg->send_buffer_size_bytes)) {
		ret = -EFAULT;
		goto out;
	}

	/* Grab the checkpoint if exists */
	if (arg->in_cp != NULL && arg->in_cp_size_bytes > 0) {
		if (arg->in_cp_size_bytes != sizeof(struct btrfs_send_checkpoint)) {
			ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: in_cp_size_bytes(%u)!=sizeof(struct btrfs_send_checkpoint)(%lu)",
				          send_root->objectid, arg->in_cp_size_bytes, sizeof(struct btrfs_send_checkpoint));
			ret = -EILSEQ;
			goto out;
		}

		cp = kmem_cache_alloc(zbtrfs_globals.send_arg_cachep, GFP_NOFS);
		if (unlikely(cp == NULL)) {
			ret = -ENOMEM;
			goto out;
		}
		ret = copy_from_user(cp, arg->in_cp, sizeof(struct btrfs_send_checkpoint));
		if (unlikely(ret)) {
			ret = -EFAULT;
			goto out;
		}
		cp->version = le32_to_cpu(cp->version);
		cp->cp_size_bytes = le32_to_cpu(cp->cp_size_bytes);
		/* various checks */
		if (cp->version > BTRFS_SEND_CHECKPOINT_VERSION ||
			cp->cp_size_bytes != sizeof(struct btrfs_send_checkpoint)) {
			ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: cp->version(%u)>%u or cp->cp_size_bytes(%u)!=%lu",
				          send_root->objectid, cp->version, BTRFS_SEND_CHECKPOINT_VERSION,
				          cp->cp_size_bytes, sizeof(struct btrfs_send_checkpoint));
			ret = -EILSEQ;
			goto out;
		}
		/* ---- For testing only --------- */
		if (unlikely(ZSEND_TEST.force_cp_version)) {
			ZBTRFSLOG_TAG(send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR, "subvol[%llu]: <TEST> force_cp_version=%u",
				          send_root->objectid, ZSEND_TEST.force_cp_version);
			if (cp->version > ZSEND_TEST.force_cp_version) {
				ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: <TEST> cp->version(%u)>force_cp_version(%u)",
					          send_root->objectid, cp->version, ZSEND_TEST.force_cp_version);
				ret = -EILSEQ;
				goto out;
			}
		}
		/* ------------------------------- */
		/* just a to have it in the log, we are designed to handle this */
		if (cp->version < BTRFS_SEND_CHECKPOINT_VERSION)
			ZBTRFSLOG_TAG(send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR, "subvol[%llu]: received cp->version(%u)<%u", send_root->objectid, cp->version, BTRFS_SEND_CHECKPOINT_VERSION);

		/* This should not happen, but we can handle it */
		if (ZBTRFS_WARN_ON(!BTRFS_HAS_SEND_CHECKPOINT(cp))) {
			kmem_cache_free(zbtrfs_globals.send_arg_cachep, cp);
			cp = NULL;
		}
	}

	/* Set up the send context */
	sctx = kmem_cache_zalloc(zbtrfs_globals.send_ctx_cachep, GFP_NOFS);
	if (unlikely(sctx == NULL)) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: failed allocating struct send_cp_ctx", send_root->objectid);
		ret = -ENOMEM;
		goto out;
	}

	/****** set up carefully the versioning info *********/
	/* --- block-virt - always set --- */
	sctx->replay_stream_flags |= BTRFS_ZIOC_SEND_BLOCK_VIRT;
	sctx->gen_stream_flags    |= BTRFS_ZIOC_SEND_BLOCK_VIRT;
	/* --- unmap --- */
	/* 
	 * if cp version>1, then previous sender accounted for unmap commands in the stream.
	 * this does not necessarily mean that he actually sent these commands, but they
	 * were accounted for checkpointing purposes.
	 * if user-space tells us that receiver supports "unmap" commands, we will generate
	 * them. but in any case, we will account for them.
	 */
	if (cp == NULL || cp->version > BTRFS_SEND_CHECKPOINT_VERSION_1)
		sctx->replay_stream_flags |= BTRFS_ZIOC_SEND_SUPPORT_UNMAP;
	sctx->gen_stream_flags |= (arg->flags & BTRFS_ZIOC_SEND_SUPPORT_UNMAP);
	/*****************************************************/

	INIT_LIST_HEAD(&sctx->base.new_refs);
	INIT_LIST_HEAD(&sctx->base.deleted_refs);
	INIT_RADIX_TREE(&sctx->base.name_cache, GFP_NOFS);
	INIT_LIST_HEAD(&sctx->base.name_cache_list);
	sctx->base.name_cache_size = 0; /* Just to be explicit */

	sctx->base.pending_dir_moves = RB_ROOT;
	sctx->base.waiting_dir_moves = RB_ROOT;
	sctx->base.orphan_dirs = RB_ROOT;

	/* This will be our hint, that data should be copied to user buffer */
	sctx->base.send_filp = NULL;

	sctx->base.send_root = send_root;

	sctx->base.send_max_size = BTRFS_SEND_BUF_SIZE;
	sctx->base.send_buf = vmalloc(sctx->base.send_max_size);
	if (sctx->base.send_buf == NULL) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: failed allocating send_buf of %u bytes",
			          send_root->objectid, sctx->base.send_max_size);
		ret = -ENOMEM;
		goto out;
	}
	sctx->base.send_size = 0;         /* Just to be explicit */
	sctx->base.flags = 0;             /* Just to be explicit */

	sctx->base.read_buf = NULL; /* we don't need it */

	/* Find the parent root */
	sctx->base.parent_root = NULL;
	if (arg->parent_root != 0) {
		struct btrfs_key key;
		int index = 0;

		key.objectid = arg->parent_root;
		key.type = BTRFS_ROOT_ITEM_KEY;
		key.offset = (u64)-1;

		index = srcu_read_lock(&send_root->fs_info->subvol_srcu);

		sctx->base.parent_root = btrfs_read_fs_root_no_name(send_root->fs_info, &key);
		if (IS_ERR(sctx->base.parent_root)) {
			srcu_read_unlock(&send_root->fs_info->subvol_srcu, index);
			ZBTRFSLOG_TAG(send_root->fs_info, Z_KERR, ZKLOG_TAG_SR, "subvol[%llu]: failed locating parent_root(%llu)", send_root->objectid, arg->parent_root);
			ret = PTR_ERR(sctx->base.parent_root);
			sctx->base.parent_root = NULL;
			goto out;
		}

		ZBTRFS_WARN_ON(sctx->base.parent_root->orphan_cleanup_state != ORPHAN_CLEANUP_DONE);

		spin_lock(&sctx->base.parent_root->root_item_lock);
		sctx->base.parent_root->send_in_progress++;
		if (!btrfs_root_readonly(sctx->base.parent_root) || btrfs_root_dead(sctx->base.parent_root)) {
			spin_unlock(&sctx->base.parent_root->root_item_lock);
			srcu_read_unlock(&send_root->fs_info->subvol_srcu, index);
			ret = -EPERM;
			goto out;
		}
		spin_unlock(&sctx->base.parent_root->root_item_lock);

		srcu_read_unlock(&send_root->fs_info->subvol_srcu, index);
	}

	/* 
	 * Initialize some other values as well, just to be explicit:
	 * send_off - not really used, just a dummy value for vfs_write() output 
	 * cmd_send_size - used for collecting statistics only
	 * total_send_size = not really used
	 * clone_roots, clone_roots_cnt - we don't use it
	 * ra - we don't use it, fine to have it zeroed
	 */
	sctx->base.left_path = NULL;
	sctx->base.right_path = NULL;
	sctx->base.cmp_key = NULL;

	/* Re-arm the send checkpoint, if any */
	if (cp == NULL) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "subvol[%llu]: no checkpoint", send_root->objectid);
		sctx->base.cur_ino                       = 0;
		sctx->base.cur_inode_gen                 = 0;
		sctx->base.cur_inode_new                 = 0;
		sctx->base.cur_inode_new_gen             = 0;
		sctx->base.cur_inode_deleted             = 0;
		sctx->base.cur_inode_size                = 0;
		sctx->base.cur_inode_mode                = 0;
		sctx->base.cur_inode_rdev                = 0;
		sctx->base.cur_inode_last_extent         = 0;
		
		sctx->base.send_progress                 = 0;

		sctx->n_cmds_to_skip                     = 0;
		sctx->offset_in_write_cmd_bytes_to_skip  = 0;
	} else {
		sctx->base.cur_ino                       = le64_to_cpu(cp->cur_ino);
		sctx->base.cur_inode_gen                 = le64_to_cpu(cp->cur_inode_gen);
		sctx->base.cur_inode_new                 = cp->cur_inode_new;     /* u8 */
		sctx->base.cur_inode_new_gen             = cp->cur_inode_new_gen; /* u8 */
		sctx->base.cur_inode_deleted             = cp->cur_inode_deleted; /* u8 */
		sctx->base.cur_inode_size                = le64_to_cpu(cp->cur_inode_size);
		sctx->base.cur_inode_mode                = le64_to_cpu(cp->cur_inode_mode);
		sctx->base.cur_inode_rdev                = 0; /* not in the checkpoint, but we don't really need it */
		sctx->base.cur_inode_last_extent         = 0; /* not in the checkpoint, but we don't really need it */
		sctx->base.send_progress                 = le64_to_cpu(cp->send_progress);

		sctx->n_cmds_to_skip                     = le64_to_cpu(cp->n_cmds_since_cp);
		sctx->offset_in_write_cmd_bytes_to_skip  = le64_to_cpu(cp->offset_in_write_cmd_bytes);

		ZKLOG_PRINT_CP(send_root->fs_info, Z_KDEB1, ZKLOG_TAG_CHCKP, cp);
	}

	/* 
	 * Initialize constant part of the current checkpoint.
	 * IMPORTANT: we always set our version as our latest version!!!
	 * (unless we are in non-block-virt/TEST mode, which is only for testing)
	 */
	sctx->curr_cp.cp_size_bytes = cpu_to_le32(sizeof(struct btrfs_send_checkpoint));
	/* ---- For testing only --------- */
	if (unlikely(ZSEND_TEST.force_cp_version)) {
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR, "subvol[%llu]: <TEST> force_cp_version=%u", send_root->objectid, ZSEND_TEST.force_cp_version);
		if (ZSEND_TEST.force_cp_version != BTRFS_SEND_CHECKPOINT_VERSION_1) {
			ZBTRFSLOG_TAG(send_root->fs_info, Z_KWARN, ZKLOG_TAG_SR, "subvol[%llu]: <TEST> force_cp_version=%u, but non-block-virt requires %u",
				          send_root->objectid, ZSEND_TEST.force_cp_version, BTRFS_SEND_CHECKPOINT_VERSION_1);
			ret = -EINVAL;
			goto out;
		}
		sctx->curr_cp.version = cpu_to_le32(ZSEND_TEST.force_cp_version);
	/* ------------------------------- */
	} else {
		sctx->curr_cp.version = cpu_to_le32(BTRFS_SEND_CHECKPOINT_VERSION);
	}
	/* 
	 * The rest of curr_cp is left zeroed, so that in record_checkpoint()
	 * we do not assert because of a duplicate checkpoint.
	 * This will also signal to user mode !BTRFS_HAS_SEND_CHECKPOINT() in case
	 * we manage only to send the SUBVOL command (which should not happen).
	 */

	/* Initialize user buffer */
	sctx->out_buffer = arg->send_buffer;
	sctx->out_buffer_size_bytes = arg->send_buffer_size_bytes;
	sctx->out_buffer_l_bytes = 0;
	sctx->out_buffer_r_bytes = 0;
	sctx->out_buffer_full = 0;

	current->journal_info = BTRFS_SEND_TRANS_STUB;
	ret = send_bv_subvol_with_cp(sctx, (cp != NULL) ? &cp->tree_cmp_cp : NULL);
	current->journal_info = prev_journal_info;
	if (ret < 0)
		goto out;

	/* Send also the C_END command, we need it */
	ret = begin_cmd(&sctx->base, BTRFS_SEND_C_END);
	if (ret < 0)
		goto out;
	ret = send_cmd(&sctx->base);
	if (ret < 0)
		goto out;

out:
	if (sctx != NULL) {
		ZBTRFS_BUG_ON(arg == NULL);
		ZBTRFSLOG_TAG(send_root->fs_info, Z_KDEB1, ZKLOG_TAG_SR, "SEND subvol[%llu] parent[%llu] ret=%d out_buffer_full=%d (%u+%u=%u/%u)", 
			          send_root->objectid, 
			          (sctx->base.parent_root == NULL) ? 0 : sctx->base.parent_root->objectid,
			          ret, sctx->out_buffer_full,
			          sctx->out_buffer_l_bytes, sctx->out_buffer_r_bytes, sctx->out_buffer_l_bytes + sctx->out_buffer_r_bytes,
			          sctx->out_buffer_size_bytes);

		if (ret == 0) {
			/* Case1: we completed sending all the data */
			if (sctx->out_buffer_r_bytes > 0)
				arg->send_buffer_size_bytes = sctx->out_buffer_size_bytes;
			else
				arg->send_buffer_size_bytes = sctx->out_buffer_l_bytes;

			/* generate end-of-data checkpoint */
			arg->out_cp.cp_size_bytes = sctx->curr_cp.cp_size_bytes;
			arg->out_cp.version       = sctx->curr_cp.version;
			btrfs_compare_trees_gen_checkpoint(&arg->out_cp.tree_cmp_cp,
				NULL/*left_key*/, 1/*left_end_reached*/,
				NULL/*right_key*/,1/*right_end_reached*/);
			arg->out_cp.cur_ino       = cpu_to_le64((u64)-1);
			arg->out_cp.cur_inode_gen = cpu_to_le64((u64)-1);
			/* Rest of the checkpoint fields should not matter */

			arg->end_of_data = 1; /* Signal end-of-data to user mode */

			ret = copy_to_user(user_arg, arg, sizeof(struct btrfs_ioctl_checkpoint_send_args));
			if (ret != 0)
				ret = -EFAULT;
		} else if (ret == -EOVERFLOW && sctx->out_buffer_full) {
			/* Case2: we filled the current buffer, but still have more data to push */
			if (sctx->out_buffer_r_bytes > 0)
				arg->send_buffer_size_bytes = sctx->out_buffer_size_bytes;
			else
				arg->send_buffer_size_bytes = sctx->out_buffer_l_bytes;

			/* copy the current checkpoint */
			arg->out_cp = sctx->curr_cp;
			arg->end_of_data = 0;
			ret = copy_to_user(user_arg, arg, sizeof(struct btrfs_ioctl_checkpoint_send_args));
			if (ret != 0)
				ret = -EFAULT;
		} else {
			/* Case3: some real error: just return error from ioctl */
		}
	}

	btrfs_root_dec_send_in_progress(send_root);

	/* Cleanup */
	if (arg)
		kmem_cache_free(zbtrfs_globals.send_arg_cachep, arg);
	if (cp)
		kmem_cache_free(zbtrfs_globals.send_arg_cachep, cp);
	if (sctx) {
		/* we should not have anything here - our block-virt subvolume dir structure never changes */
		ZBTRFS_WARN_ON(!RB_EMPTY_ROOT(&sctx->base.pending_dir_moves));
		while (!RB_EMPTY_ROOT(&sctx->base.pending_dir_moves)) {
			struct rb_node *n;
			struct pending_dir_move *pm;
		
			n = rb_first(&sctx->base.pending_dir_moves);
			pm = rb_entry(n, struct pending_dir_move, node);
			while (!list_empty(&pm->list)) {
				struct pending_dir_move *pm2;
		
				pm2 = list_first_entry(&pm->list,
							   struct pending_dir_move, list);
				free_pending_move(&sctx->base, pm2);
			}
			free_pending_move(&sctx->base, pm);
		}
		ZBTRFS_WARN_ON(!RB_EMPTY_ROOT(&sctx->base.waiting_dir_moves));
		while (!RB_EMPTY_ROOT(&sctx->base.waiting_dir_moves)) {
			struct rb_node *n;
			struct waiting_dir_move *dm;
		
			n = rb_first(&sctx->base.waiting_dir_moves);
			dm = rb_entry(n, struct waiting_dir_move, node);
			rb_erase(&dm->node, &sctx->base.waiting_dir_moves);
			kfree(dm);
		}
		ZBTRFS_WARN_ON(!RB_EMPTY_ROOT(&sctx->base.orphan_dirs));
		while (!RB_EMPTY_ROOT(&sctx->base.orphan_dirs)) {
			struct rb_node *n;
			struct orphan_dir_info *odi;
		
			n = rb_first(&sctx->base.orphan_dirs);
			odi = rb_entry(n, struct orphan_dir_info, node);
			free_orphan_dir_info(&sctx->base, odi);
		}

		if (sctx->base.parent_root != NULL)
			btrfs_root_dec_send_in_progress(sctx->base.parent_root);

		vfree(sctx->base.send_buf);

		name_cache_free(&sctx->base);

		kmem_cache_free(zbtrfs_globals.send_ctx_cachep, sctx);
	}

	return ret;
}

void zbtrfs_root_dec_send_in_progress(struct btrfs_root *root)
{
	btrfs_root_dec_send_in_progress(root);
}

struct btrfs_path *zbtrfs_alloc_path_for_send(void)
{
	return alloc_path_for_send();
}

size_t zbtrfs_send_ctx_size(void)
{
	/* keep an eye on this size */
	BUILD_BUG_ON(sizeof(struct send_cp_ctx) > 1000);
	return sizeof(struct send_cp_ctx);
}

size_t zbtrfs_send_arg_size(void)
{
	/* use one kmem_cache for both */
	size_t size = max_t(size_t, sizeof(struct btrfs_ioctl_checkpoint_send_args), sizeof(struct btrfs_send_checkpoint));
	return size;
}

