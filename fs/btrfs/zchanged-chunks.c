#ifdef CONFIG_BTRFS_ZADARA

#include <linux/blkdev.h>
#include <zbio.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "zchanged-chunks.h"

struct changed_chunks_ctx {
	struct btrfs_changed_chunks_checkpoint curr_cp;

	struct zbtrfs_changed_chunks_common_params *common_params;

	u64 __user *changed_chunks_lbas;
	u64 __user *parent_chunks_lbas;

	u64 ino;
	u64 gen;

	unsigned int n_reported_superchunks;

	unsigned int out_buffer_full:1;
	unsigned int higher_inode:1;
};

#define ZKLOG_PRINT_CP(fs_info, log_level, tag, cp)                                                                                   \
({                                                                                                                                    \
	if (zklog_will_print_tag((log_level), (tag))) {                                                                                   \
		char lkey_oid[21] = "-1";                                                                                                     \
		char lkey_off[21] = "-1";                                                                                                     \
		char rkey_oid[21] = "-1";                                                                                                     \
		char rkey_off[21] = "-1";                                                                                                     \
		char last_superchunk[21] = "-1";                                                                                              \
		if (le64_to_cpu((cp)->tree_cmp_cp.left_key__objectid) != (u64)-1)                                                             \
			snprintf(lkey_oid, sizeof(lkey_oid), "%llu", le64_to_cpu((cp)->tree_cmp_cp.left_key__objectid));                          \
		if (le64_to_cpu((cp)->tree_cmp_cp.left_key__offset) != (u64)-1)                                                               \
			snprintf(lkey_off, sizeof(lkey_off), "%llu", le64_to_cpu((cp)->tree_cmp_cp.left_key__offset));                            \
		if (le64_to_cpu((cp)->tree_cmp_cp.right_key__objectid) != (u64)-1)                                                            \
			snprintf(rkey_oid, sizeof(rkey_oid), "%llu", le64_to_cpu((cp)->tree_cmp_cp.right_key__objectid));                         \
		if (le64_to_cpu((cp)->tree_cmp_cp.right_key__offset) != (u64)-1)                                                              \
			snprintf(rkey_off, sizeof(rkey_off), "%llu", le64_to_cpu((cp)->tree_cmp_cp.right_key__offset));                           \
		if (le64_to_cpu((cp)->last_reported_superchunk) != (u64)-1)                                                                   \
			snprintf(last_superchunk, sizeof(last_superchunk), "%llu", le64_to_cpu((cp)->last_reported_superchunk));                  \
		ZBTRFSLOG_TAG((fs_info), (log_level), (tag), "cp ino(%s,%llu): L(%s,%s,%s)R(%s,%s,%s) sc/ch=%u last-sc=%s",                   \
			      lkey_oid, le64_to_cpu((cp)->ino_gen),                                                                               \
			      lkey_oid, btrfs_fs_key_type_to_str((cp)->tree_cmp_cp.left_key__type), lkey_off,                                     \
			      rkey_oid, btrfs_fs_key_type_to_str((cp)->tree_cmp_cp.right_key__type), rkey_off,                                    \
			      le32_to_cpu((cp)->n_chunks_in_superchunk), last_superchunk);                                                        \
	}                                                                                                                                 \
})

/*
 * "root" is a file tree, "key" points at EXTENT_DATA, "path" points at btrfs_bv_file_extent_item.
 * return the physical coordinate of the block-virt chunk on the pool data device.
 */
static int map_blk_virt_chunk(struct btrfs_root *root, struct btrfs_key *key, struct btrfs_path *path,
                              u64 *out_physical_bytenr)
{
	int ret = 0;
	struct extent_buffer *leaf = path->nodes[0];
	struct btrfs_bv_file_extent_item *bfei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_bv_file_extent_item);
	u64 logical = 0;

	ret = zbtrfs_blk_virt_check_bv_file_extent_item(root, key->objectid, key->offset, root->fs_info->zfs_info.pool_gran_bytes,
		                                            leaf, path->slots[0], bfei);
	if (ret)
		goto out;

	logical = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);
	ret = zbtrfs_blk_virt_map_block(root->fs_info, BTRFS_BLOCK_GROUP_DATA, logical, root->fs_info->zfs_info.pool_gran_bytes, out_physical_bytenr);
	if (ret)
		goto out;

	/* should be aligned by sector */
	if (unlikely(!BYTES_ALIGNED_TO_BLK(*out_physical_bytenr))) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "r=%llu key(%llu %s %llu) logical=%llu physical=%llu not aligned by sector",
			          root->objectid, key->objectid, btrfs_fs_key_type_to_str(key->type), key->offset,
			          logical, *out_physical_bytenr);
		ret = -ECANCELED;
	}

out:
	return ret;
}

static int verify_changed_inode(struct btrfs_root *left_root,
		      struct btrfs_root *right_root,
		      struct btrfs_path *left_path,
		      struct btrfs_path *right_path,
		      enum btrfs_compare_tree_result result,
		      struct changed_chunks_ctx *cc_ctx)
{
	int ret = 0;
	struct btrfs_inode_item *left_ii = NULL;
	struct btrfs_inode_item *right_ii = NULL;
	u64 left_gen = 0;
	u64 right_gen = 0;

	/* our inode should not get deleted (and it cannot be same ino with a different gen here!) */
	if (unlikely(result == BTRFS_COMPARE_TREE_DELETED)) {
		right_ii = btrfs_item_ptr(right_path->nodes[0], right_path->slots[0], struct btrfs_inode_item);
		right_gen = btrfs_inode_generation(right_path->nodes[0], right_ii);
		ZBTRFSLOG_TAG(left_root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) on right_root=%llu ino(%llu,%llu) DELETED???",
			          left_root->objectid, cc_ctx->ino, cc_ctx->gen,
			          right_root->objectid, cc_ctx->ino, right_gen);
		ret = -ECANCELED;
		goto out;
	}

	/* for NEW or CHANGED, left ino is in left_path */
	left_ii = btrfs_item_ptr(left_path->nodes[0], left_path->slots[0], struct btrfs_inode_item);
	left_gen = btrfs_inode_generation(left_path->nodes[0], left_ii);
	if (left_gen != cc_ctx->gen) {
		ZBTRFSLOG_TAG(left_root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) but left_gen=%llu",
			          left_root->objectid, cc_ctx->ino, cc_ctx->gen, left_gen);
		ret = -ECANCELED;
		goto out;
	}
	/* right ino is for CHANGED only */
	if (result == BTRFS_COMPARE_TREE_CHANGED) {
		right_ii = btrfs_item_ptr(right_path->nodes[0], right_path->slots[0], struct btrfs_inode_item);
		right_gen = btrfs_inode_generation(right_path->nodes[0], right_ii);
		if (right_gen != cc_ctx->gen) {
			ZBTRFSLOG_TAG(left_root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) but right_gen=%llu",
				          left_root->objectid, cc_ctx->ino, cc_ctx->gen, right_gen);
			ret = -ECANCELED;
			goto out;
		}
	}

out:
	return ret;
}

static int changed_chunks_cb(struct btrfs_root *left_root,
		      struct btrfs_root *right_root,
		      struct btrfs_path *left_path,
		      struct btrfs_path *right_path,
		      struct btrfs_key *key,
		      enum btrfs_compare_tree_result result,
			  struct btrfs_compare_trees_checkpoint *tree_cp,
		      void *ctx)
{
	int ret = 0;
	struct changed_chunks_ctx *cc_ctx = ctx;
	struct btrfs_fs_info *fs_info = left_root->fs_info;
	struct zbtrfs_changed_chunks_common_params *common_params = cc_ctx->common_params;
	u64 chunk_index = 0, superchunk_index = 0, last_reported_superchunk = 0;
	u64 left_physical_lba = ULONG_MAX, right_physical_lba = ULONG_MAX;

	ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): key(%llu,%s,%llu): %s",
		          left_root->objectid, cc_ctx->ino, cc_ctx->gen,
	              key->objectid, btrfs_fs_key_type_to_str(key->type), key->offset,
	              btrfs_compare_tree_result_to_str(result));

	/* we should not see keys below our ino, but if we do, let's just continue */
	if (ZBTRFS_WARN(key->objectid < cc_ctx->ino, "FS[%s]: left_i(r=%llu|%llu,%llu) key(%llu<ino,%s,%llu): %s",
		            fs_info->sb->s_id, left_root->objectid, cc_ctx->ino, cc_ctx->gen,
		            key->objectid, btrfs_fs_key_type_to_str(key->type), key->offset,
		            btrfs_compare_tree_result_to_str(result)))
		goto out;
	/* if we see a key above our ino, we are done, because we care only about comparing our ino */
	if (key->objectid > cc_ctx->ino) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): key(%llu>ino,%s,%llu): %s",
				      left_root->objectid, cc_ctx->ino, cc_ctx->gen,
				      key->objectid, btrfs_fs_key_type_to_str(key->type), key->offset,
				      btrfs_compare_tree_result_to_str(result));
		/* abort the scan */
		cc_ctx->higher_inode = 1;
		ret = -ENODATA; 
		goto out;
	}

	/* in our case, nothing to do in this case */
	if (result == BTRFS_COMPARE_TREE_SAME)
		return 0;

	switch (key->type) {
		case BTRFS_INODE_ITEM_KEY:
			ret = verify_changed_inode(left_root, right_root, left_path, right_path, result, cc_ctx);
			goto out;
		case BTRFS_EXTENT_DATA_KEY:
			/* handle it */
			break;
		default:
			/* any other type - just ignore and continue scan */
			goto out;
	}

	chunk_index = key->offset / fs_info->zfs_info.pool_gran_bytes;
	superchunk_index = chunk_index / le32_to_cpu(cc_ctx->curr_cp.n_chunks_in_superchunk);
	last_reported_superchunk = le64_to_cpu(cc_ctx->curr_cp.last_reported_superchunk);
	/* if we have already reported this superchunk, don't take checkpoint */
	if (last_reported_superchunk != (u64)-1 && last_reported_superchunk >= superchunk_index) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): key(%llu,%s,%llu): %s ch=%llu sc(%llu)<=last_sc(%llu) CONT",
			          left_root->objectid, cc_ctx->ino, cc_ctx->gen,
			          key->objectid, btrfs_fs_key_type_to_str(key->type), key->offset,
			          btrfs_compare_tree_result_to_str(result),
			          chunk_index, superchunk_index, last_reported_superchunk);
		goto out;
	}

	/* report this superchunk */
	ZBTRFS_BUG_ON(cc_ctx->n_reported_superchunks >= common_params->n_changed_superchunks);
	ret = copy_to_user(&common_params->changed_superchunks[cc_ctx->n_reported_superchunks],
		               &superchunk_index, sizeof(u64));
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	if (cc_ctx->changed_chunks_lbas || cc_ctx->parent_chunks_lbas) {
		/*
		 * we need also to report the chunk mappings.
		 * note that here we know that n_chunks_in_superchunk==1, i.e., chunk_index==superchunk_index
		 *
		 * BTRFS_COMPARE_TREE_NEW:
		 * left_root has the chunk mapped, right_root has no mapping for this chunk.
		 * "key" points at "left_path"
		 *
		 * BTRFS_COMPARE_TREE_DELETED:
		 * left_root has no mapping for this chunk, right_root has the chunk mapped.
		 * "key" points at "right_path"
		 *
		 * BTRFS_COMPARE_TREE_CHANGED:
		 * both left_root and right_root have the chunk mapped.
		 * "key" is identical for both "left_path" and "right_path".
		 */
		if (result == BTRFS_COMPARE_TREE_NEW || result == BTRFS_COMPARE_TREE_CHANGED) {
			ret = map_blk_virt_chunk(left_root, key, left_path, &left_physical_lba);
			if (ret)
				goto out;
			left_physical_lba = BYTES_TO_BLK(left_physical_lba);
		}
		if (result == BTRFS_COMPARE_TREE_DELETED || result == BTRFS_COMPARE_TREE_CHANGED) {
			ret = map_blk_virt_chunk(right_root, key, right_path, &right_physical_lba);
			if (ret)
				goto out;
			right_physical_lba = BYTES_TO_BLK(right_physical_lba);
		}
		if (cc_ctx->changed_chunks_lbas) {
			ret = copy_to_user(&cc_ctx->changed_chunks_lbas[cc_ctx->n_reported_superchunks], &left_physical_lba, sizeof(u64));
			if (ret) {
				ret = -EFAULT;
				goto out;
			}
		}
		if (cc_ctx->parent_chunks_lbas) {
			ret = copy_to_user(&cc_ctx->parent_chunks_lbas[cc_ctx->n_reported_superchunks], &right_physical_lba, sizeof(u64));
			if (ret) {
				ret = -EFAULT;
				goto out;
			}
		}

		/* print */
		if (zklog_will_print_tag(Z_KDEB1, ZKLOG_TAG_CH_CHUNKS)) {
			char l_lba_str[24] = "UNMAPPED", l_bytenr_str[24] = "UNMAPPED";
			char r_lba_str[24] = "UNMAPPED", r_bytenr_str[24] = "UNMAPPED";

			if (left_physical_lba != ULONG_MAX) {
				snprintf(l_lba_str, sizeof(l_lba_str), "%llu", left_physical_lba);
				snprintf(l_bytenr_str, sizeof(l_bytenr_str), "%llu", BLK_TO_BYTES(left_physical_lba));
			}
			if (right_physical_lba != ULONG_MAX) {
				snprintf(r_lba_str, sizeof(r_lba_str), "%llu", right_physical_lba);
				snprintf(r_bytenr_str, sizeof(r_bytenr_str), "%llu", BLK_TO_BYTES(right_physical_lba));
			}
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): %s sc=%llu l=%s(%s) r=%s(%s)",
				          left_root->objectid, cc_ctx->ino, cc_ctx->gen, 
				          btrfs_compare_tree_result_to_str(result), superchunk_index,
				          l_lba_str, l_bytenr_str, r_lba_str, r_bytenr_str);
		}
	} else {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): %s sc=%llu",
			          left_root->objectid, cc_ctx->ino, cc_ctx->gen,
			          btrfs_compare_tree_result_to_str(result), superchunk_index);
	}
	++cc_ctx->n_reported_superchunks;

	/* take checkpoint */
	cc_ctx->curr_cp.tree_cmp_cp = *tree_cp;
	cc_ctx->curr_cp.last_reported_superchunk = cpu_to_le64(superchunk_index);
	ZKLOG_PRINT_CP(fs_info, Z_KDEB2, ZKLOG_TAG_CH_CHUNKS, &cc_ctx->curr_cp);

	/* decide if we need to continue scan */
	if (cc_ctx->n_reported_superchunks >= common_params->n_changed_superchunks) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): n_reported_sc=%u EXIT",
			          left_root->objectid, cc_ctx->ino, cc_ctx->gen,
			          cc_ctx->n_reported_superchunks);
		ret = -EOVERFLOW;
		cc_ctx->out_buffer_full = 1;
	}

out:
	return ret;
}

static int changed_chunks_full_tree(struct btrfs_root *left_root, struct btrfs_compare_trees_checkpoint *tree_cp,
	                                struct changed_chunks_ctx *ctx)
{
	int ret = 0;
	struct btrfs_path *path = NULL;
	struct btrfs_key key;

	/* we must receive a checkpoint */
	if (ZBTRFS_WARN_ON(tree_cp == NULL)) {
		ret = -EINVAL;
		goto out;
	}

	path = zbtrfs_alloc_path_for_send();
	if (path == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* setup our search key according to checkpoint */
	key.objectid = le64_to_cpu(tree_cp->left_key__objectid);
	key.type     = tree_cp->left_key__type;
	key.offset   = le64_to_cpu(tree_cp->left_key__offset);

	/* we need to be able to find "key", because it is coming from checkpoint */
	ret = btrfs_search_slot(NULL, left_root, &key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret < 0) {
		ZBTRFSLOG_TAG(left_root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) btrfs_search_slot() failed, ret=%d",
			          left_root->objectid, ctx->ino, ctx->gen, ret);
		goto out;
	}
	if (ret) {
		ZBTRFSLOG_TAG(left_root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) btrfs_search_slot(%llu %s %llu) not found!",
			          left_root->objectid, ctx->ino, ctx->gen,
			          key.objectid, btrfs_fs_key_type_to_str(key.type), key.offset);
		ret = -ECANCELED;
		goto out;
	}

	while (1) {
		struct btrfs_key found_key;
		struct btrfs_compare_trees_checkpoint curr_cp;

		/*
		 * at this point, "path" points at an item that we need
		 * to report to "changed_chunks_cb".
		 */
		btrfs_item_key_to_cpu(path->nodes[0], &found_key, path->slots[0]);

		ret = changed_chunks_cb(left_root, NULL/*right_root*/,
			                    path/*left_path*/, NULL/*right_path*/,
			                    &found_key, BTRFS_COMPARE_TREE_NEW,
			                    btrfs_compare_trees_gen_checkpoint(&curr_cp,
			                    		&found_key, 0/*left_end_reached*/,
			                    		NULL/*right_key*/, 1/*right_end_reached*/),
			                    ctx);
		if (ret < 0)
			goto out;

		ret = btrfs_next_item(left_root, path);
		if (ret < 0) {
			ZBTRFSLOG_TAG(left_root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) btrfs_next_item(1) failed, ret=%d",
					      left_root->objectid, ctx->ino, ctx->gen, ret);
			goto out;
		}
		if (ret) {
			/* no more items in the tree */
			ret = 0;
			break;
		}

		/* 
		 * at this point "path" points at the next item
		 *  we need to report. this is exactly what
		 * the start of the loop expects.
		 */
	}

out:
	btrfs_free_path(path);

	return ret;
}

int zbtrfs_changed_chunks(struct inode *left_i, struct inode *right_i,
	                      struct zbtrfs_changed_chunks_common_params *common_params,
	                      struct zbtrfs_changed_chunks_addtnl_params *addtnl_params)
{
	int ret = 0;
	void *prev_journal_info = current->journal_info;
	u64 ino = btrfs_ino(left_i);
	struct btrfs_root *left_root = BTRFS_I(left_i)->root;
	struct btrfs_root *right_root = right_i ? BTRFS_I(right_i)->root : NULL;
	struct btrfs_fs_info *fs_info = left_root->fs_info;
	struct changed_chunks_ctx *cc_ctx = NULL;

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) right_i(r=%llu|%llu,%llu)",
		      left_root->objectid, ino, BTRFS_I(left_i)->generation,
		      right_i ? right_root->objectid : 0, 
		      right_i ? btrfs_ino(right_i) : 0,
		      right_i ? BTRFS_I(right_i)->generation : 0);

	/* this protects the left root from deletion */
	spin_lock(&left_root->root_item_lock);
	left_root->send_in_progress++;
	spin_unlock(&left_root->root_item_lock);

	ZBTRFS_WARN_ON(left_root->orphan_cleanup_state != ORPHAN_CLEANUP_DONE);

	if (unlikely(!ZBTRFS_IS_BLKVIRT_MOUNT(fs_info))) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "not a block-virt mount!!!");
		ret = -EINVAL;
		goto out;
	}
	if (unlikely(addtnl_params->n_chunks_in_superchunk == 0)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "n_chunks_in_superchunk==0");
		ret = -EINVAL;
		goto out;
	}
	/* if somebody asks for physical coordinates, they cannot use real superchunks */
	if (unlikely(addtnl_params->n_chunks_in_superchunk > 1 && (addtnl_params->changed_chunks_lbas || addtnl_params->parent_chunks_lbas))) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "n_chunks_in_superchunk=%u, but changed_chunks_lbas=%p,parent_chunks_lbas=%p (non NULL)",
			          addtnl_params->n_chunks_in_superchunk, addtnl_params->changed_chunks_lbas, addtnl_params->parent_chunks_lbas);
		ret = -EINVAL;
		goto out;
	}
	/* check input */
	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID || btrfs_is_free_space_inode(left_i) || !S_ISREG(left_i->i_mode))) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) doesn't look like a blk-virt file, mode=0%o",
			          left_root->objectid, ino, BTRFS_I(left_i)->generation, left_i->i_mode);
		ret = -EINVAL;
		goto out;
	}
	/*
	 * unfortunately, we cannot check that left-root is RO,
	 * because Volume Migration leaves the working snapshot of
	 * the source volume as Read-Write.
	 * if (!btrfs_root_readonly(left_root) {
	 * 		...
	 */
	if (btrfs_root_dead(left_root)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_root=%llu root_dead", left_root->objectid);
		ret = -EPERM;
		goto out;
	}

	/* right_inode must have the same (inode,gen) but come from a different subvolume */
	if (right_i) {
		u64 right_ino = btrfs_ino(right_i);

		/* this protects the right root from deletion and from being set to RW */
		spin_lock(&right_root->root_item_lock);
		right_root->send_in_progress++;
		spin_unlock(&right_root->root_item_lock);

		ZBTRFS_WARN_ON(right_root->orphan_cleanup_state != ORPHAN_CLEANUP_DONE);

		if (unlikely(right_ino != ino || BTRFS_I(right_i)->generation != BTRFS_I(left_i)->generation ||
			         btrfs_is_free_space_inode(right_i) || !S_ISREG(right_i->i_mode))) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) right_i(r=%llu|%llu,%llu) right_i doesn't look the same as left_i, rmode=0%o", 
				          left_root->objectid, ino, BTRFS_I(left_i)->generation,
				          right_root->objectid, right_ino, BTRFS_I(right_i)->generation, right_i->i_mode);
			ret = -EINVAL;
			goto out;
		}

		/* right root must be read-only */
		if (!btrfs_root_readonly(right_root)) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "right_root=%llu not RO", right_root->objectid);
			ret = -EPERM;
			goto out;
		}
		if (btrfs_root_dead(right_root)) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "right_root=%llu root_dead", right_root->objectid);
			ret = -EPERM;
			goto out;
		}
		
		if (unlikely(left_root == right_root || left_root->objectid == right_root->objectid)) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_root(%p/%llu)==right_root(%p/%llu)",
				          left_root, left_root->objectid, right_root, right_root->objectid);
			ret = -EINVAL;
			goto out;
		}
	}

	cc_ctx = kmem_cache_zalloc(zbtrfs_globals.changed_chunks_ctx_cachep, GFP_NOFS);
	if (unlikely(cc_ctx == NULL)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) kmem_cache_zalloc(changed_chunks_ctx_cachep) failed",
			          left_root->objectid, ino, BTRFS_I(left_i)->generation);
		ret = -ENOMEM;
		goto out;
	}

	/* grab the input checkpoint, if given */
	if (common_params->in_cp != NULL && common_params->in_cp_size_bytes > 0) {
		u32 cp_version = 0, cp_size_bytes = 0;

		if (!access_ok(VERIFY_READ, common_params->in_cp, common_params->in_cp_size_bytes)) {
			ret = -EFAULT;
			goto out;
		}
		if (common_params->in_cp_size_bytes < sizeof(struct btrfs_changed_chunks_checkpoint)) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): in_cp_size_bytes(%u)<sizeof(struct btrfs_changed_chunks_checkpoint)(%lu)",
				      left_root->objectid, ino, BTRFS_I(left_i)->generation,
				      common_params->in_cp_size_bytes, sizeof(struct btrfs_changed_chunks_checkpoint));
			ret = -EILSEQ;
			goto out;
		}

		/* copy the checkpoint from user-space into our context */
		ret = copy_from_user(&cc_ctx->curr_cp, common_params->in_cp, sizeof(struct btrfs_changed_chunks_checkpoint));
		if (unlikely(ret)) {
			ret = -EFAULT;
			goto out;
		}

		/* make sure we can accept this checkpoint */
		cp_version = le32_to_cpu(cc_ctx->curr_cp.version);
		cp_size_bytes = le32_to_cpu(cc_ctx->curr_cp.cp_size_bytes);
		if (cp_version > BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION || cp_size_bytes != sizeof(struct btrfs_changed_chunks_checkpoint)) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, 
				      "left_i(r=%llu|%llu,%llu): cp->version(%u)>%u or cp->cp_size_bytes(%u)!=%lu",
				      left_root->objectid, ino, BTRFS_I(left_i)->generation,
				      cp_version, BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION,
				      cp_size_bytes, sizeof(struct btrfs_changed_chunks_checkpoint));
			ret = -EILSEQ;
			goto out;
		}

		/* just a print to have this in the log, we are designed to handle this */
		if (unlikely(cp_version < BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION))
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_CHCKP, "left_i(r=%llu|%llu,%llu): received cp->version(%u)<%u",
			          left_root->objectid, ino, BTRFS_I(left_i)->generation,
			          cp_version, BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION);

		/* This should not happen, but we can handle it */
		if (ZBTRFS_WARN_ON(!BTRFS_HAS_CHANGED_CHUNKS_CHECKPOINT(&cc_ctx->curr_cp)))
			memset(&cc_ctx->curr_cp, 0, sizeof(cc_ctx->curr_cp));
	}

	/* continue verifying input */
	if (unlikely(common_params->n_changed_superchunks == 0) ||
		!access_ok(VERIFY_WRITE, common_params->changed_superchunks, sizeof(u64)*common_params->n_changed_superchunks)) {
		ret = -EFAULT;
		goto out;
	}
	if (unlikely(common_params->out_cp_size_bytes < sizeof(struct btrfs_changed_chunks_checkpoint)) ||
		!access_ok(VERIFY_WRITE, common_params->out_cp, common_params->out_cp_size_bytes)) {
		ret = -EFAULT;
		goto out;
	}
	if (unlikely(addtnl_params->changed_chunks_lbas &&
		         !access_ok(VERIFY_WRITE, addtnl_params->changed_chunks_lbas, sizeof(u64)*common_params->n_changed_superchunks))) {
		ret = -EFAULT;
		goto out;
	}
	if (unlikely(addtnl_params->parent_chunks_lbas &&
		         !access_ok(VERIFY_WRITE, addtnl_params->parent_chunks_lbas, sizeof(u64)*common_params->n_changed_superchunks))) {
		ret = -EFAULT;
		goto out;
	}

	/* set up our context */
	cc_ctx->common_params = common_params;
	cc_ctx->changed_chunks_lbas = addtnl_params->changed_chunks_lbas;
	cc_ctx->parent_chunks_lbas = addtnl_params->parent_chunks_lbas;
	cc_ctx->ino = ino;
	cc_ctx->gen = BTRFS_I(left_i)->generation;

	/* re-arm the checkpoint */
	if (BTRFS_HAS_CHANGED_CHUNKS_CHECKPOINT(&cc_ctx->curr_cp)) {
		struct btrfs_key key;
		bool key_ok = false;
		u64 gen = 0;

		ZKLOG_PRINT_CP(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, &cc_ctx->curr_cp);

		/* make sure the left key points either at a EXTENT_DATA of our inode or at tree end */
		key.objectid = le64_to_cpu(cc_ctx->curr_cp.tree_cmp_cp.left_key__objectid);
		key.type = cc_ctx->curr_cp.tree_cmp_cp.left_key__type;
		key.offset = le64_to_cpu(cc_ctx->curr_cp.tree_cmp_cp.left_key__offset);
		key_ok = (key.objectid == ino && key.type == BTRFS_EXTENT_DATA_KEY) || btrfs_compare_trees_key_tree_end_reached(&key);
		if (!key_ok) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): bad cp->left_key(%llu %s %llu)",
				      left_root->objectid, ino, BTRFS_I(left_i)->generation,
				      key.objectid, btrfs_fs_key_type_to_str(key.type), key.offset);
			ret = -EILSEQ;
			goto out;
		}
		/* make sure inode generation matches */
		gen = le64_to_cpu(cc_ctx->curr_cp.ino_gen);
		if (gen != BTRFS_I(left_i)->generation) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): but cp->gen=%llu",
				          left_root->objectid, ino, BTRFS_I(left_i)->generation, gen);
			ret = -EILSEQ;
			goto out;
		}

		/* same for right key */
		if (right_i) {
			key.objectid = le64_to_cpu(cc_ctx->curr_cp.tree_cmp_cp.right_key__objectid);
			key.type = cc_ctx->curr_cp.tree_cmp_cp.right_key__type;
			key.offset = le64_to_cpu(cc_ctx->curr_cp.tree_cmp_cp.right_key__offset);
			key_ok = (key.objectid == ino && key.type == BTRFS_EXTENT_DATA_KEY) || btrfs_compare_trees_key_tree_end_reached(&key);
			if (!key_ok) {
				ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "right_i(r=%llu|%llu,%llu): bad cp->right_key(%llu %s %llu)",
					      right_root->objectid, ino, BTRFS_I(right_i)->generation,
						  key.objectid, btrfs_fs_key_type_to_str(key.type), key.offset);
				ret = -EILSEQ;
				goto out;
			}
		}

		/* make sure n_chunks_in_superchunk did not change, and we have last_reported_superchunk */
		if (le32_to_cpu(cc_ctx->curr_cp.n_chunks_in_superchunk) != addtnl_params->n_chunks_in_superchunk ||
			le64_to_cpu(cc_ctx->curr_cp.last_reported_superchunk) == (u64)-1) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu): cp->sc/ch=%u(%u) last-sc=%llu",
				      left_root->objectid, ino, BTRFS_I(left_i)->generation,
				      le32_to_cpu(cc_ctx->curr_cp.n_chunks_in_superchunk), addtnl_params->n_chunks_in_superchunk,
				      le64_to_cpu(cc_ctx->curr_cp.last_reported_superchunk));
			ret = -EILSEQ;
			goto out;
		}
	} else {
		/* rearm the checkpoint to INODE_ITEMs */
		cc_ctx->curr_cp.tree_cmp_cp.left_key__objectid = cpu_to_le64(ino);
		cc_ctx->curr_cp.tree_cmp_cp.left_key__type = BTRFS_INODE_ITEM_KEY;
		cc_ctx->curr_cp.tree_cmp_cp.left_key__offset = cpu_to_le64(0);

		cc_ctx->curr_cp.ino_gen = cpu_to_le64(BTRFS_I(left_i)->generation);
		cc_ctx->curr_cp.n_chunks_in_superchunk = cpu_to_le32(addtnl_params->n_chunks_in_superchunk);
		cc_ctx->curr_cp.last_reported_superchunk = cpu_to_le64((u64)-1);

		/* if we have right inode, rearm, otherwise don't bother, because full-tree send code will init them to (-1) */
		if (right_i) {
			cc_ctx->curr_cp.tree_cmp_cp.right_key__objectid = cpu_to_le64(ino);
			cc_ctx->curr_cp.tree_cmp_cp.right_key__type = BTRFS_INODE_ITEM_KEY;
			cc_ctx->curr_cp.tree_cmp_cp.right_key__offset = cpu_to_le64(0);
		}

		ZKLOG_PRINT_CP(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, &cc_ctx->curr_cp);
	}

	/* we can launch the diff */
	current->journal_info = BTRFS_SEND_TRANS_STUB;
	if (right_i) {
		ret = btrfs_compare_trees(left_root, right_root, &cc_ctx->curr_cp.tree_cmp_cp,
			                      changed_chunks_cb, cc_ctx);
	} else {
		ret = changed_chunks_full_tree(left_root, &cc_ctx->curr_cp.tree_cmp_cp, cc_ctx);
	}
	current->journal_info = prev_journal_info;

out:
	if (cc_ctx != NULL) {
		/* in case of success, set output values */
		if (ret == 0 || (ret == -ENODATA && cc_ctx->higher_inode)) {
			/* Case1: we completed sending all the data */
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CH_CHUNKS, "left_i(r=%llu|%llu,%llu) DONE",
					      left_root->objectid, ino, BTRFS_I(left_i)->generation);
			common_params->n_changed_superchunks = cc_ctx->n_reported_superchunks;
			/* 
			 * generate end-of-stream checkpoint - probably not needed,
			 * as we will signal explicitly to user-space that we are done.
			 */
			cc_ctx->curr_cp.cp_size_bytes = cpu_to_le32(sizeof(struct btrfs_changed_chunks_checkpoint));
			cc_ctx->curr_cp.version = cpu_to_le32(BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION);
			btrfs_compare_trees_gen_checkpoint(&cc_ctx->curr_cp.tree_cmp_cp,
					NULL/*left_key*/, 1/*left_end_reached*/,
					NULL/*right_key*/, 1/*right_end_reached*/);
			cc_ctx->curr_cp.ino_gen = cpu_to_le64((u64)-1);
			ret = copy_to_user(common_params->out_cp, &cc_ctx->curr_cp, sizeof(struct btrfs_changed_chunks_checkpoint));
			if (ret)
				ret = -EFAULT;
			common_params->out_cp_size_bytes = sizeof(struct btrfs_changed_chunks_checkpoint);
			common_params->end_of_data = 1; /* signal explicitly that we are done */
		} else if (ret == -EOVERFLOW && cc_ctx->out_buffer_full) {
			/* Case2: we reported as many changed chunks as we could, but we need to continue scanning */
			common_params->n_changed_superchunks = cc_ctx->n_reported_superchunks;
			/* copy the latest checkpoint that we have */
			cc_ctx->curr_cp.cp_size_bytes = cpu_to_le32(sizeof(struct btrfs_changed_chunks_checkpoint));
			cc_ctx->curr_cp.version = cpu_to_le32(BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION);
			ret = copy_to_user(common_params->out_cp, &cc_ctx->curr_cp, sizeof(struct btrfs_changed_chunks_checkpoint));
			if (ret)
				ret = -EFAULT;
			common_params->out_cp_size_bytes = sizeof(struct btrfs_changed_chunks_checkpoint);
			common_params->end_of_data = 0;
		} else {
			/* Case3: some real error: just return error from ioctl */
		}

		kmem_cache_free(zbtrfs_globals.changed_chunks_ctx_cachep, cc_ctx);
	}

	zbtrfs_root_dec_send_in_progress(left_root);
	if (right_root)
		zbtrfs_root_dec_send_in_progress(right_root);

	return ret;
}

size_t zbtrfs_changed_chunks_ctx_size(void)
{
	return sizeof(struct changed_chunks_ctx);
}

#endif /*CONFIG_BTRFS_ZADARA*/

