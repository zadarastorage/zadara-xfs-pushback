#ifdef CONFIG_BTRFS_ZADARA
#include <linux/dm-kcopyd.h>
#include <linux/blkdev.h>
#include <zbio.h>
#include "ctree.h"
#include "volumes.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "disk-io.h"
#include "zbtrfs-block-virt.h"
#include "zbtrfs-exported.h"
#include "zchanged-chunks.h"

/********Core block-virt APIs *********************************/

/*
 * A stripped-down version of __btrfs_map_block.
 * It assumes:
 *   - all block groups have a "SINGLE" profile
 *   - btrfs is mounted on a single device
 */
int zbtrfs_blk_virt_map_block(struct btrfs_fs_info *fs_info, u64 type, u64 logical, u64 length, u64 *physical)
{
	int ret = 0;
	struct extent_map_tree *em_tree = &fs_info->mapping_tree.map_tree;
	struct extent_map *em = NULL;
	struct map_lookup *map = NULL;
	u64 offset = 0;

	read_lock(&em_tree->lock);
	em = lookup_extent_mapping(em_tree, logical, length);
	read_unlock(&em_tree->lock);

	if (unlikely(!em)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "Unable to find extent_map for [%llu:%llu]", logical, length);
		ret = -ECANCELED;
		goto out;
	}
	if (unlikely(em->start > logical || em->start + em->len < logical)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "Found extent_map[%llu:%llu] for [%llu:%llu]", em->start, em->len, logical, length);
		ret = -ECANCELED;
		goto out;
	}
	/* check that length does not overrun the mapping */
	offset = logical - em->start;
	if (unlikely(offset + length > em->len)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "requested[%llu:%llu] overruns extent_map[%llu:%llu]", logical, length, em->start, em->len);
		ret = -ECANCELED;
		goto out;
	}

	map = (struct map_lookup *)em->bdev;
	/* check SINGLE profile and block-group type */
	if (unlikely((map->type & BTRFS_BLOCK_GROUP_PROFILE_MASK) ||
		         !(map->type & type) ||
		         map->num_stripes != 1)) {
		/*
		 * map->sub_stripes is supposed to be 1, but btrfs-progs sets it to 0:( 
		 * so sometimes it's 0 and sometimes it's 1...
		 * anyways, it is only relevant for raid0/10
		 */
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT,
		    "illegal extent_map[%llu:%llu] for [%llu:%llu]: map_type(%llu)-vs-type(%llu) strp_len=%d sec_size=%d num_stripes=%d sub_stripes=%d",
			em->start, em->len, logical, length, 
			map->type, type,
			map->stripe_len, map->sector_size, map->num_stripes, map->sub_stripes);
		ret = -ECANCELED;
		goto out;
	}

	/* at this point we can map; this is simple for SINGLE profile */
	*physical = map->stripes[0].physical + offset;
	ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu] inside [%llu:%llu] stripe[0].phys=%llu offs=%llu mapped to [%llu:%llu]",
		logical, length, em->start, em->len, map->stripes[0].physical, offset,
		*physical, length);

out:
	if (em)
		free_extent_map(em);
	return ret;
}

int zbtrfs_blk_virt_check_bv_file_extent_item(struct btrfs_root *root, u64 ino, u64 offset, unsigned int gran_bytes,
	struct extent_buffer *leaf, int slot, struct btrfs_bv_file_extent_item *bfei)
{
	int ret = 0;
	u64 ei_bytenr = 0;

	if (unlikely(!btrfs_is_bv_file_extent_item(leaf, slot))) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu ino=%llu extent[%llu/%llu]: not btrfs_bv_file_extent_item!",
			root->objectid, ino, offset, offset / gran_bytes);
		ret = -EILSEQ;
		goto out;
	}

	ei_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);
	if (ei_bytenr % PAGE_CACHE_SIZE != 0 ||
		ei_bytenr == 0 || ei_bytenr == ULONG_MAX) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu ino=%llu extent[%llu/%llu]: bad disk_bytenr=%llu",
			root->objectid, ino, offset, offset / gran_bytes, ei_bytenr);
		ret = -EILSEQ;
	}

out:
	WARN_ON(ret);

	return ret;
}

static int zbtrfs_check_extent_item_key(struct btrfs_root *root, u64 ino, unsigned int gran_bytes, struct btrfs_key *key)
{
	int ret = 0;

	if (key->objectid % PAGE_CACHE_SIZE != 0 || 
		key->objectid == 0 || key->objectid == ULONG_MAX) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu ino=%llu EXTENT_ITEM(%llu %u %llu) objectid=%llu is bad",
			      root->objectid, ino,
			      key->objectid, btrfs_key_type(key), key->offset, 
			      key->objectid);
		ret = EILSEQ;
	}
	if (key->type != BTRFS_EXTENT_ITEM_KEY) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu ino=%llu EXTENT_ITEM(%llu %u %llu) type(%u)!=EXTENT_ITEM(%u)", root->objectid, ino,
			key->objectid, key->type, key->offset,
			key->type, BTRFS_EXTENT_ITEM_KEY);
		ret = -EILSEQ;
	}
	if (key->offset != gran_bytes) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu ino=%llu EXTENT_ITEM(%llu %u %llu) offset!=gran_bytes(%u)", root->objectid, ino,
			key->objectid, key->type, key->offset, gran_bytes);
		ret = -EILSEQ;
	}

	return ret;
}

int zbtrfs_blk_virt_get_file_info(struct file *file, struct zbtrfs_blk_virt_file_info *info)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;

	info->pool_id = root->fs_info->zfs_info.pool_id;
	info->subvol_treeid = root->objectid;
	info->inode_num = btrfs_ino(inode);
	info->inode_gen = BTRFS_I(inode)->generation;

	ZBTRFSLOG_TAG(root->fs_info, Z_KINFO, ZKLOG_TAG_BLKVIRT, "pool_id=%d r=%llu ino(%llu,%llu)", info->pool_id, info->subvol_treeid, info->inode_num, info->inode_gen);

	return 0;
}

EXPORT_SYMBOL(zbtrfs_blk_virt_get_file_info);

int zbtrfs_blk_virt_resolve_read(struct file *file, u64 chunk_index, unsigned int gran_bytes, u64 *out_phys_bytenr)
{
	int ret = 0;
	u64 ino = btrfs_ino(file_inode(file));
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_path *path = NULL;
	struct btrfs_key ed_key;

	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu(%llu)]", root->objectid, ino, chunk_index, chunk_index * gran_bytes);

	if (unlikely(gran_bytes != root->fs_info->zfs_info.pool_gran_bytes)) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu]: gran_bytes(%u)!=pool_gran_bytes(%u)",
			             root->objectid, ino, chunk_index, gran_bytes, root->fs_info->zfs_info.pool_gran_bytes);
		ret = -EPROTO;
		goto out;
	}

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	ed_key.objectid = ino;
	ed_key.type = BTRFS_EXTENT_DATA_KEY;
	ed_key.offset = chunk_index * gran_bytes;

	ret = btrfs_search_slot(NULL/*trans*/, root, &ed_key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret < 0) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu(%llu)] btrfs_search_slot() failed err=%d",
			          root->objectid, ino, chunk_index, chunk_index * gran_bytes, ret);
		goto out;
	}
	if (ret) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] NOT FOUND", root->objectid, ino, chunk_index);
		ret = 1; /* not found */
	} else {
		struct extent_buffer *leaf = path->nodes[0];
		struct btrfs_bv_file_extent_item *bfei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_bv_file_extent_item);
		u64 ei_bytenr = ULONG_MAX;
		
		ret = zbtrfs_blk_virt_check_bv_file_extent_item(root, ino, ed_key.offset, gran_bytes, leaf, path->slots[0], bfei);
		if (ret < 0)
			goto out;

		ei_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);

		ret = zbtrfs_blk_virt_map_block(root->fs_info, BTRFS_BLOCK_GROUP_DATA,
				ei_bytenr, gran_bytes, out_phys_bytenr);
		if (ret < 0)
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] failed mapping[%llu:%u]", root->objectid, ino, chunk_index, ei_bytenr, gran_bytes);
		else
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] resolved[%llu:%u] mapped[%llu:%u]", root->objectid, ino, chunk_index,
					      ei_bytenr, gran_bytes, *out_phys_bytenr, gran_bytes);
	}

out:
	btrfs_free_path(path);
	return ret;
}
EXPORT_SYMBOL(zbtrfs_blk_virt_resolve_read);

/*
 * Check whether the chunk needs COW.
 * @return <0 on error, 0 if chunk does not need COW, 1 if chunk needs COW
 * @param out_bytenr if return value is 0: this is resolved chunk location, cannot be ULONG_MAX,
 *                   if return value is 1: can be ULONG_MAX if chunk is not mapped.
 * @param out_trans relevant only if return value is 1, so in that case caller needs 
 *                   to call btrfs_end_transaction() eventually
 * @param alr_migr_cb will be called in case the chunk is already migrated (i.e., the function
 *                         will most probably return 0), while still attached to a transaction
 * @param cb_arg parameter to the alr_migr_cb function
 * @note caller needs to save current->journal_info before calling this function, and restore it
 *       after this function returns
 * @note this function returns virtual bytenr and does not map to physical!!!
 */
static int zbtrfs_blk_virt_chunk_needs_cow(struct btrfs_root *root, u64 ino, 
			u64 chunk_index, unsigned int gran_bytes, int chunk_is_locked,
			u64 *out_bytenr, struct btrfs_trans_handle* *out_trans,
			zbtrfs_blk_virt_chunk_already_migrated_fn alr_migr_cb, void *cb_arg)
{
	int ret = 0;
	struct btrfs_path *path = NULL;
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_key ed_key;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	current->journal_info = NULL; /* btrfs_join_transaction() expects this */
	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_join_transaction() ret=%d", root->objectid, ino, chunk_index, ret);
		trans = NULL;
		goto out;
	}

	/* Lookup the chunk in the file tree - we want exact match */
	ed_key.objectid = ino;
	ed_key.type = BTRFS_EXTENT_DATA_KEY;
	ed_key.offset = chunk_index * gran_bytes;

	ret = btrfs_search_slot(trans, root, &ed_key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret < 0) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_search_slot() ret=%d", root->objectid, ino, chunk_index, ret);
		goto out;
	}
	if (ret) {
		btrfs_release_path(path);
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] NOT FOUND NEED COW", root->objectid, ino, chunk_index);
		/* chunk is not mapped, we need COW */
		*out_bytenr = ULONG_MAX;
		*out_trans = trans;
		ret = 1;

	} else {
		/* chunk is mapped, check if this extent is shared by anybody else */
		struct extent_buffer *leaf = path->nodes[0];
		struct btrfs_bv_file_extent_item *bfei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_bv_file_extent_item);
		u64 existing_bytenr = ULONG_MAX;

		ret = zbtrfs_blk_virt_check_bv_file_extent_item(root, ino, ed_key.offset, gran_bytes, leaf, path->slots[0], bfei);
		if (ret < 0) {
			btrfs_release_path(path);
			goto out;
		}

		existing_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);
		btrfs_release_path(path);

		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] found EXTENT_DATA bytenr=%llu", root->objectid, ino, chunk_index, existing_bytenr);

		ret = btrfs_cross_ref_exist(trans, root, ino, ed_key.offset, existing_bytenr);
		if (ret < 0) {
			/* 
			 * If we are called from "chunk-unlocked" path, it may happen that 
			 * somebody else is migrating the chunk on the "chunk-locked" path.
			 * In that case, it may happen, that he already inserted the EXTENT_DATA, but
			 * hasn't yet added a delayed ref for an EXTENT_ITEM.
			 * In that case, btrfs_cross_ref_exist() will complain with ENOENT.
			 * So if this is the case, don't issue the error print (but still return
			 * error to the caller, which then go via the "chunk-locked" path).
			 */
			ZBTRFSLOG_TAG(root->fs_info, (!chunk_is_locked && ret == -ENOENT) ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_BLKVIRT, 
			              "[%llu:%llu:%llu] btrfs_cross_ref_exist() ret=%d", root->objectid, ino, chunk_index, ret);
			goto out;
		}

		if (ret == 0) {
			/* COW not needed, just return the mapping */
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] found EXTENT_DATA bytenr=%llu NOCOW", root->objectid, ino, chunk_index, existing_bytenr);
			*out_bytenr = existing_bytenr;
			*out_trans = NULL;

			/* 
			 * Chunk is already mapped, COW not needed, we are still attached to a transaction,
			 * so call the callback. Note that we can still return failure from this function.
			 */
			alr_migr_cb(cb_arg);
		} else {
			/* COW is needed */
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] found EXTENT_DATA bytenr=%llu NEED COW ret=%d", root->objectid, ino, chunk_index, existing_bytenr, ret);
			*out_bytenr = existing_bytenr;
			*out_trans = trans;
			ret = 1;
		}
	}

out:
	btrfs_free_path(path);

	if (ret <= 0) {
		/* detach from transaction, if we have one */
		if (trans) {
			int end_trans_ret = btrfs_end_transaction(trans, root);
			if (end_trans_ret && ret == 0) {
				ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_end_transaction() ret=%d", root->objectid, ino, chunk_index, ret);
				ret = end_trans_ret;
			}
		}
	}

	return ret;
}

int zbtrfs_blk_virt_resolve_write_unlocked(struct file *file, u64 chunk_index, unsigned int gran_bytes, u64 *out_phys_bytenr,
		zbtrfs_blk_virt_chunk_already_migrated_fn alr_migr_cb, void *cb_arg)
{
	int ret = 0;
	void *current_journal_info = current->journal_info;
	u64 ino = btrfs_ino(file_inode(file));
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_trans_handle *trans = NULL;
	u64 existing_ei_bytenr = ULONG_MAX;

	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu(%llu)]", root->objectid, ino, chunk_index, chunk_index * gran_bytes);	

	if (unlikely(gran_bytes != root->fs_info->zfs_info.pool_gran_bytes)) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu]: gran_bytes(%u)!=pool_gran_bytes(%u)",
			             root->objectid, ino, chunk_index, gran_bytes, root->fs_info->zfs_info.pool_gran_bytes);
		ret = -EPROTO;
		goto out;
	}

	if (unlikely(ZBTRFS_FS_ERROR(root->fs_info))) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] FS ERROR", root->objectid, ino, chunk_index);
		ret = -EROFS;
		goto out;
	}
	if (unlikely(btrfs_root_readonly(root))) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] root=%llu RO", root->objectid, ino, chunk_index, root->objectid);
		ret = -EROFS;
		goto out;
	}
	/* MS_RDONLY will be detected in zbtrfs_blk_virt_chunk_needs_cow(), which attempts to join a transaction */

	ret = zbtrfs_blk_virt_chunk_needs_cow(root, ino, chunk_index, gran_bytes, 0/*locked*/, &existing_ei_bytenr, &trans,
		                                  alr_migr_cb, cb_arg);
	ZBTRFS_BUG_ON(ret <= 0 && trans);
	if (ret < 0)
		goto out;
	if (ret > 0) {
		/* COW needed, just detach from transaction, do not return mapping */
		int end_trans_ret = btrfs_end_transaction(trans, root);
		if (end_trans_ret) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_end_transaction() ret=%d", root->objectid, ino, chunk_index, end_trans_ret);
			ret = end_trans_ret;
		}
		goto out;
	}

	/* COW not required, map the chunk */
	ret = zbtrfs_blk_virt_map_block(root->fs_info, BTRFS_BLOCK_GROUP_DATA,
			existing_ei_bytenr, gran_bytes, out_phys_bytenr);
	if (ret < 0)
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] failed mapping[%llu:%u]", root->objectid, ino, chunk_index, existing_ei_bytenr, gran_bytes);
	else
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] resolved[%llu:%u] mapped[%llu:%u]", root->objectid, ino, chunk_index,
				existing_ei_bytenr, gran_bytes, *out_phys_bytenr, gran_bytes);

out:
	current->journal_info = current_journal_info;
	return ret;
}
EXPORT_SYMBOL(zbtrfs_blk_virt_resolve_write_unlocked);

int zbtrfs_blk_virt_resolve_write_locked(struct file *file, u64 chunk_index, unsigned int gran_bytes,
		u64 *out_old_phys_bytenr, u64 *out_phys_bytenr, struct zbtrfs_blk_virt_resolve_wr_ctx *out_ctx,
		zbtrfs_blk_virt_chunk_already_migrated_fn alr_migr_cb, void *cb_arg)
{
	int ret = 0;
	void *current_journal_info = current->journal_info;
	u64 ino = btrfs_ino(file_inode(file));
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_trans_handle *trans = NULL;
	u64 existing_ei_bytenr = ULONG_MAX;
	struct btrfs_key ei_key;

	/* fill context with invalid data, just to hit bugs early */
	out_ctx->old_ei_bytenr = ULONG_MAX;
	out_ctx->ei_bytenr = ULONG_MAX;
	out_ctx->trans_handle = NULL;
	out_ctx->transid = ULONG_MAX;

	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu(%llu)]", root->objectid, ino, chunk_index, chunk_index * gran_bytes);	

	if (unlikely(gran_bytes != root->fs_info->zfs_info.pool_gran_bytes)) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu]: gran_bytes(%u)!=pool_gran_bytes(%u)",
			             root->objectid, ino, chunk_index, gran_bytes, root->fs_info->zfs_info.pool_gran_bytes);
		ret = -EPROTO;
		goto out;
	}

	if (unlikely(ZBTRFS_FS_ERROR(root->fs_info))) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] FS ERROR", root->objectid, ino, chunk_index);
		ret = -EROFS;
		goto out;
	}
	if (unlikely(btrfs_root_readonly(root))) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] root=%llu RO", root->objectid, ino, chunk_index, root->objectid);
		ret = -EROFS;
		goto out;
	}
	/* MS_RDONLY will be detected in zbtrfs_blk_virt_chunk_needs_cow(), which attempts to join a transaction */

	ret = zbtrfs_blk_virt_chunk_needs_cow(root, ino, chunk_index, gran_bytes, 1/*locked*/, &existing_ei_bytenr, &trans,
		                                  alr_migr_cb, cb_arg);
	ZBTRFS_BUG_ON(ret <= 0 && trans);
	if (ret < 0)
		goto out;
	if (ret == 0) {
		/* COW not needed, just map the chunk */
		ret = zbtrfs_blk_virt_map_block(root->fs_info, BTRFS_BLOCK_GROUP_DATA,
				existing_ei_bytenr, gran_bytes, out_phys_bytenr);
		if (ret < 0)
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] failed mapping[%llu:%u]", root->objectid, ino, chunk_index, existing_ei_bytenr, gran_bytes);
		else
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] resolved[%llu:%u] mapped[%llu:%u]", root->objectid, ino, chunk_index,
			              existing_ei_bytenr, gran_bytes, *out_phys_bytenr, gran_bytes);
		goto out;
	}

	/* COW is needed */
	/* map old chunk location, if it has one */
	if (existing_ei_bytenr != ULONG_MAX) {
		ret = zbtrfs_blk_virt_map_block(root->fs_info, BTRFS_BLOCK_GROUP_DATA, 
				existing_ei_bytenr, gran_bytes, out_old_phys_bytenr);
		if (ret < 0) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] failed old mapping[%llu:%u]", root->objectid, ino, chunk_index, existing_ei_bytenr, gran_bytes);
			goto out;
		}
	} else {
		*out_old_phys_bytenr = ULONG_MAX;
	}
	out_ctx->old_ei_bytenr = existing_ei_bytenr;

	/* allocate new chunk location */
	ret = btrfs_reserve_extent(root, gran_bytes/*num_bytes*/, gran_bytes/*num_bytes*/,
	                           0/*empty_size*/,  0/*hint_byte*/,
	                           &ei_key, 1/*is_data*/, 0/*delalloc*/);
	if (ZBTRFS_WARN_ON(ret > 0))
		ret = -ECANCELED;
	if (ret < 0) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_reserve_extent() ret=%d", root->objectid, ino, chunk_index, ret);
		goto out;
	}
	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] reserved EXTENT_ITEM(%llu,%u,%llu)", root->objectid, ino, chunk_index,
		          ei_key.objectid, ei_key.type, ei_key.offset);
	ret = zbtrfs_check_extent_item_key(root, ino, gran_bytes, &ei_key);
	if (ret < 0)
		goto out;

	/* map the new chunk */
	ret = zbtrfs_blk_virt_map_block(root->fs_info, BTRFS_BLOCK_GROUP_DATA,
			ei_key.objectid, gran_bytes, out_phys_bytenr);
	if (ret < 0) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] failed new mapping[%llu:%u]", root->objectid, ino, chunk_index, ei_key.objectid, gran_bytes);
		goto out;
	}

	/* fill the rest of our context and tell the caller he needs to COW */
	out_ctx->ei_bytenr = ei_key.objectid;
	out_ctx->trans_handle = trans;
	out_ctx->transid = trans->transid;
	ret = 1;

out:
	/*
	 * ret == 0: we have already detached from trans
	 * ret > 0:  we return the transaction back to the caller
	 * ret < 0:  maybe we need to detach from trans
	 */
	ZBTRFS_BUG_ON(ret == 0 && trans);
	if (ret < 0) {
		/* detach from transaction, if we have one */
		if (trans)
			btrfs_end_transaction(trans, root);
	}

	current->journal_info = current_journal_info;
	return ret;
}
EXPORT_SYMBOL(zbtrfs_blk_virt_resolve_write_locked);

int zbtrfs_blk_virt_chunk_migr_completed(struct file *file, u64 chunk_index, unsigned int gran_bytes, u16 tenant_id,
		struct zbtrfs_blk_virt_resolve_wr_ctx *ctx, int migr_ret)
{
	int ret = 0;
	void *current_journal_info = current->journal_info;
	struct inode *inode = file_inode(file);
	u64 ino = btrfs_ino(inode);
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_trans_handle *trans = ctx->trans_handle;
	struct btrfs_key ei_key;

	if (unlikely(gran_bytes != root->fs_info->zfs_info.pool_gran_bytes)) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu]: gran_bytes(%u)!=pool_gran_bytes(%u)",
			             root->objectid, ino, chunk_index, gran_bytes, root->fs_info->zfs_info.pool_gran_bytes);
		ret = -EPROTO;
		goto out;
	}

	if (zklog_will_print_tag(Z_KDEB2, ZKLOG_TAG_BLKVIRT)) {
		if (ctx->old_ei_bytenr == ULONG_MAX)
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] old_ei_bytenr=ULONG_MAX ei_bytenr=%llu tenant=%u migr_ret=%d", 
			              root->objectid, ino, chunk_index, ctx->ei_bytenr, tenant_id, migr_ret);
		else
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] old_ei_bytenr=%llu ei_bytenr=%llu tenant=%u migr_ret=%d",
			              root->objectid, ino, chunk_index, ctx->old_ei_bytenr, ctx->ei_bytenr, tenant_id, migr_ret);
	}

	/* account the COW */
	if (ctx->old_ei_bytenr == ULONG_MAX)
		ZBTRFS_ZSTATS_COW_UNMAPPED(root->fs_info);
	 else
		ZBTRFS_ZSTATS_COW_MAPPED(root->fs_info);

	/* detaching from transaction expects to find this */
	current->journal_info = trans;

	if (unlikely(migr_ret)) {
		/* migration failed - we need to free whatever we have allocated */
		ZBTRFSLOG_TAG(root->fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] free EXTENT_ITEM(%llu %u %llu) migr_ret=%d",
		          root->objectid, ino, chunk_index, ctx->ei_bytenr, BTRFS_EXTENT_ITEM_KEY, (u64)gran_bytes, migr_ret);
		btrfs_free_reserved_extent(root, ctx->ei_bytenr, gran_bytes, 0/*delalloc*/);
		/* note that we return ret==0 in this case */
		goto out;
	}

	if (ctx->old_ei_bytenr == ULONG_MAX) {
		/* there was no previous mapping, we need a new EXTENT_DATA */
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] insert EXTENT_DATA(%llu,%u,%llu)", ino, chunk_index,
		              root->objectid, ino, BTRFS_EXTENT_DATA_KEY, chunk_index * gran_bytes);

		ret = btrfs_insert_bv_file_extent(trans, root, ino, chunk_index * gran_bytes, ctx->ei_bytenr/*disk_bytenr*/);
		if (ret) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_insert_bv_file_extent() failed, ret=%d", root->objectid, ino, chunk_index, ret);
			btrfs_free_reserved_extent(root, ctx->ei_bytenr, gran_bytes, 0/*delalloc*/);
			goto out;
		}

		/* 
		 * we changed the file tree - update ctransid.
		 * also, previously chunk was not mapped, so
		 * we need to count this chunk towards "mapped capacity".
		 */
		zbtrfs_update_blk_virt_inode_on_cow(trans, root, inode, 1/*mod_chunk_alloc*/);

	} else {
		struct btrfs_path *path = NULL;
		struct btrfs_key ed_key;
		struct extent_buffer *leaf = NULL;
		struct btrfs_bv_file_extent_item *bfei = NULL;

		/* We need to modify existing EXTENT_DATA - re-search with COW */
		ed_key.objectid = ino;
		ed_key.type = BTRFS_EXTENT_DATA_KEY;
		ed_key.offset = chunk_index * gran_bytes;

		path = btrfs_alloc_path();
		if (!path) {
			ret = -ENOMEM;
			goto out;
		}

		ret = btrfs_search_slot(trans, root, &ed_key, path, 0/*ins_len*/, 1/*cow*/);
		if (ret > 0) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] on re-search EXTENT_DATA(%llu,%u,%llu) not found!", root->objectid, ino, chunk_index,
				          ino, BTRFS_EXTENT_DATA_KEY, chunk_index * gran_bytes);
			ret = -ENOENT;
		} else if (ret < 0) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] on re-search EXTENT_DATA(%llu,%u,%llu) ret=%d", root->objectid, ino, chunk_index,
				          ino, BTRFS_EXTENT_DATA_KEY, chunk_index * gran_bytes, ret);
		}
		if (ret) {
			btrfs_free_path(path);
			btrfs_free_reserved_extent(root, ctx->ei_bytenr, gran_bytes, 0/*delalloc*/);
			goto out;
		}

		leaf = path->nodes[0];
		bfei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_bv_file_extent_item);

		zbtrfs_blk_virt_check_bv_file_extent_item(root, ino, ed_key.offset, gran_bytes, leaf, path->slots[0], bfei);
		ZBTRFS_WARN_ON(ctx->old_ei_bytenr != btrfs_bv_file_extent_disk_bytenr(leaf, bfei));
		ctx->old_ei_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);

		btrfs_set_bv_file_extent_disk_bytenr(leaf, bfei, ctx->ei_bytenr);

		btrfs_mark_buffer_dirty(leaf);
		btrfs_free_path(path);

		/* 
		 * we changed the file tree - update ctransid.
		 * previously chunk was mapped, so we don't count it
		 * towards "mapped capacity".
		 */
		zbtrfs_update_blk_virt_inode_on_cow(trans, root, inode, 0/*mod_chunk_alloc*/);

		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] modify EXTENT_DATA(%llu,%u,%llu) gen=%llu bytenr:%llu=>%llu", root->objectid, ino, chunk_index,
			          ino, BTRFS_EXTENT_DATA_KEY, ed_key.offset,
			          trans->transid, ctx->old_ei_bytenr, ctx->ei_bytenr);

		ret = btrfs_free_extent(trans, root, ctx->old_ei_bytenr, gran_bytes,
				0/*parent*/, root->objectid, ino, ed_key.offset,
				1/*no_quota*/);
		if (ret) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_free_extent(%llu,%u,%u) ret=%d ABORT", root->objectid, ino, chunk_index,
				      ctx->old_ei_bytenr, BTRFS_EXTENT_ITEM_KEY, gran_bytes, ret);
			/* 
			 * We have modified the file tree, but failed to add a delayed ref,
			 * so we need to abort the transaction.
			 */
			btrfs_abort_transaction(trans, root, ret);
			goto out;
		}
	}

	/* insert EXTENT_ITEM - add delayed ref */
	ei_key.objectid = ctx->ei_bytenr;
	ei_key.type = BTRFS_EXTENT_ITEM_KEY;
	ei_key.offset = gran_bytes;

	ret = zbtrfs_alloc_reserved_file_extent(trans, root, 
			root->objectid, ino, chunk_index * gran_bytes,
			&ei_key,
			tenant_id);
	if (ret) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] zbtrfs_alloc_reserved_file_extent(%llu,%u,%llu) tenant=%u ret=%d ABORT", root->objectid, ino, chunk_index,
			      ctx->ei_bytenr, BTRFS_EXTENT_ITEM_KEY, (u64)gran_bytes, tenant_id, ret);
		/* 
		 * We have modified the file tree, but failed to add a delayed ref,
		 * so we need to abort the transaction.
		 */
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

out:
	/* detach from transaction */
	{
		int end_trans_ret = btrfs_end_transaction(trans, root);
		if (end_trans_ret && ret == 0)
			ret = end_trans_ret;
	}

	current->journal_info = current_journal_info;
	return ret;
}
EXPORT_SYMBOL(zbtrfs_blk_virt_chunk_migr_completed);

int zbtrfs_blk_virt_unmap_chunk_locked(struct file *file, u64 chunk_index, unsigned int gran_bytes, u64 *out_old_phys_bytenr)
{
	int ret = 0;
	void *current_journal_info = current->journal_info;
	struct inode *inode = file_inode(file);
	u64 ino = btrfs_ino(inode);
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_path *path = NULL;
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_key ed_key;
	struct extent_buffer *leaf = NULL;
	struct btrfs_bv_file_extent_item *bfei = NULL;
	u64 old_ei_bytenr = ULONG_MAX;

	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu(%llu)]", root->objectid, ino, chunk_index, chunk_index * gran_bytes);

	if (unlikely(gran_bytes != root->fs_info->zfs_info.pool_gran_bytes)) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu]: gran_bytes(%u)!=pool_gran_bytes(%u)",
			             root->objectid, ino, chunk_index, gran_bytes, root->fs_info->zfs_info.pool_gran_bytes);
		ret = -EPROTO;
		goto out;
	}

	if (unlikely(ZBTRFS_FS_ERROR(root->fs_info))) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] FS ERROR", root->objectid, ino, chunk_index);
		ret = -EROFS;
		goto out;
	}
	if (unlikely(btrfs_root_readonly(root))) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] root=%llu RO", root->objectid, ino, chunk_index, root->objectid);
		ret = -EROFS;
		goto out;
	}
	/* MS_RDONLY will be detected in btrfs_join_transaction() */

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	current->journal_info = NULL; /* btrfs_join_transaction() expects this */
	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_join_transaction() ret=%d", root->objectid, ino, chunk_index, ret);
		trans = NULL;
		goto out;
	}

	/* Lookup the chunk in the file tree - we want exact match */
	ed_key.objectid = ino;
	ed_key.type = BTRFS_EXTENT_DATA_KEY;
	ed_key.offset = chunk_index * gran_bytes;

	ret = btrfs_search_slot(trans, root, &ed_key, path, -1/*ins_len*/, 1/*cow*/);
	if (ret < 0) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_search_slot() ret=%d", root->objectid, ino, chunk_index, ret);
		goto out;
	}
	if (ret) {
		/* we haven't found the chunk - nothing to unmap */
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] not found => nothing to unmap", root->objectid, ino, chunk_index);
		*out_old_phys_bytenr = ULONG_MAX;
		ret = 0;
		goto out;
	}

	/* we found our btrfs_bv_file_extent_item */
	leaf = path->nodes[0];
	bfei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_bv_file_extent_item);
	ret = zbtrfs_blk_virt_check_bv_file_extent_item(root, ino, ed_key.offset, gran_bytes, leaf, path->slots[0], bfei);
	/* 
	 * we need to delete appropriate EXTENT_ITEM.
	 * but if this check went wrong, we cannot pull its coordinate safely,
	 * therefore, we cannot proceed.
	 */
	if (ret)
		goto out;

	old_ei_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);
	ret = zbtrfs_blk_virt_map_block(root->fs_info, BTRFS_BLOCK_GROUP_DATA, old_ei_bytenr, gran_bytes, out_old_phys_bytenr);
	/* if this fails, we can still proceed */
	if (ret)
		*out_old_phys_bytenr = ULONG_MAX;

	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] UNMAP (%llu EXTENT_ITEM %llu) phys=%llu", 
		          root->objectid, ino, chunk_index,
		          old_ei_bytenr, (u64)gran_bytes, *out_old_phys_bytenr);

	ret = btrfs_del_item(trans, root, path);
	if (ret) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_del_item(%llu EXTENT_DATA %llu) failed, ret=%d",
			          root->objectid, ino, chunk_index,
			          ino, ed_key.offset, ret);
		goto out;
	}

	btrfs_release_path(path);

	/*
	 * note1: at this point if anything goes wrong, we must abort the transaction
	 * note2: btrfs_mark_buffer_dirty() is not needed after btrfs_del_item()
	 */
	ret = btrfs_free_extent(trans, root, old_ei_bytenr/*bytenr*/, gran_bytes/*num_bytes*/,
			0/*parent*/, root->objectid, ino/*owner*/, chunk_index * gran_bytes/*offset*/,
			1/*no_quota*/);
	if (ret) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_free_extent(%llu,%u,%u) ret=%d ABORT", root->objectid, ino, chunk_index,
			          old_ei_bytenr, BTRFS_EXTENT_ITEM_KEY, gran_bytes, ret);
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

	/* we have modified the tree, so account */
	zbtrfs_update_blk_virt_inode_on_cow(trans, root, inode, -1/*mod_chunk_alloc*/);

	ZBTRFS_ZSTATS_UNMAP(root->fs_info);

out:
	btrfs_free_path(path);
	if (trans) {
		int end_ret = btrfs_end_transaction(trans, root);
		if (end_ret && ret == 0)
			ret = end_ret;
	}
	current->journal_info = current_journal_info;
	return ret;
}
EXPORT_SYMBOL(zbtrfs_blk_virt_unmap_chunk_locked);

void zbtrfs_blk_virt_account_nocow(struct file *file, unsigned int count)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	ZBTRFS_ZSTATS_NOCOW(root->fs_info, count);
}
EXPORT_SYMBOL(zbtrfs_blk_virt_account_nocow);

int zbtrfs_blk_virt_changed_superchunks(struct file *left_file, struct file *right_file,
		struct zbtrfs_blk_virt_changed_chunks_params *params,
		unsigned int n_chunks_in_superchunk)
{
	int ret = 0;
	struct inode *left_i = file_inode(left_file);
	struct inode *right_i = right_file ? file_inode(right_file) : NULL;
	struct zbtrfs_changed_chunks_addtnl_params addtnl_params = {
		.n_chunks_in_superchunk = n_chunks_in_superchunk,
		.changed_chunks_lbas = NULL,
		.parent_chunks_lbas = NULL
	};

	BUILD_BUG_ON(sizeof(struct zbtrfs_blk_virt_changed_chunks_params)                           != sizeof(struct zbtrfs_changed_chunks_common_params));
	SAME_OFFSET_AND_SIZE(struct zbtrfs_blk_virt_changed_chunks_params, in_cp,                   struct zbtrfs_changed_chunks_common_params, in_cp);
	SAME_OFFSET_AND_SIZE(struct zbtrfs_blk_virt_changed_chunks_params, in_cp_size_bytes,        struct zbtrfs_changed_chunks_common_params, in_cp_size_bytes);
	SAME_OFFSET_AND_SIZE(struct zbtrfs_blk_virt_changed_chunks_params, changed_superchunks,     struct zbtrfs_changed_chunks_common_params, changed_superchunks);
	SAME_OFFSET_AND_SIZE(struct zbtrfs_blk_virt_changed_chunks_params, n_changed_superchunks,   struct zbtrfs_changed_chunks_common_params, n_changed_superchunks);
	SAME_OFFSET_AND_SIZE(struct zbtrfs_blk_virt_changed_chunks_params, out_cp,                  struct zbtrfs_changed_chunks_common_params, out_cp);
	SAME_OFFSET_AND_SIZE(struct zbtrfs_blk_virt_changed_chunks_params, out_cp_size_bytes,       struct zbtrfs_changed_chunks_common_params, out_cp_size_bytes);
	SAME_OFFSET_AND_SIZE(struct zbtrfs_blk_virt_changed_chunks_params, end_of_data,             struct zbtrfs_changed_chunks_common_params, end_of_data);

	/* 
	 * we don't check here that both files are from BTRFS FS,
	 * (as we never do in the block-virt layer),
	 * but we do check that they are both from the same FS.
	 */
	if (ZBTRFS_WARN(right_i && left_i->i_sb != right_i->i_sb,
		            "FS[%s]: left_ino(%llu:%llu) but right_ino(%llu:%llu) is from FS[%s]",
		            left_i->i_sb->s_id,
		            btrfs_ino(left_i), BTRFS_I(left_i)->generation,
		            btrfs_ino(right_i), BTRFS_I(right_i)->generation,
		            right_i->i_sb->s_id)) {
		ret = -EINVAL;
		goto out;
	}

	ret = zbtrfs_changed_chunks(left_i, right_i, (struct zbtrfs_changed_chunks_common_params*)params, &addtnl_params);

out:
	return ret;
}
EXPORT_SYMBOL(zbtrfs_blk_virt_changed_superchunks);

/********Snap creation******************************************/

int zbtrfs_blk_virt_cre_snap_ctx_init(struct zbtrfs_blk_virt_cre_snap_ctx *ctx, const char *dm_btrfs_devpath, u32 flush_writes_ioctl_cmd)
{
	int ret = 0;

	ctx->dm_btrfs_bdev = NULL;
	ctx->flush_writes_ioctl_cmd = 0;

	if (dm_btrfs_devpath == NULL || dm_btrfs_devpath[0] == '\0')
		goto out;

	ctx->dm_btrfs_bdev = blkdev_get_by_path(dm_btrfs_devpath, FMODE_READ|FMODE_WRITE,
		                     NULL/*holder - needed only for exclusive get*/);
	if (IS_ERR(ctx->dm_btrfs_bdev)) {
		ret = PTR_ERR(ctx->dm_btrfs_bdev);
		zklog_tag(Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "blkdev_get_by_path(%s) failed, ret=%d", dm_btrfs_devpath, ret);
		ctx->dm_btrfs_bdev = NULL;
		goto out;
	}

	ctx->flush_writes_ioctl_cmd = flush_writes_ioctl_cmd;

out:
	return ret;
}

int zbtrfs_blk_virt_cre_snap_flush_writes(struct btrfs_fs_info *fs_info, struct btrfs_transaction *trans, struct zbtrfs_blk_virt_cre_snap_ctx *ctx)
{
	int ret = 0;

	if (ctx && ctx->dm_btrfs_bdev) {
		char bname[BDEVNAME_SIZE] = {'\0'};
		ktime_t start_time = ZTIME_START();
		u64 elapsed_ms = 0;

		ret = ioctl_by_bdev(ctx->dm_btrfs_bdev, ctx->flush_writes_ioctl_cmd, 0/*no arguments for this ioctl*/);
		
		elapsed_ms = ZTIME_MS_ELAPSED(start_time);
		ZBTRFSLOG_TAG(fs_info, ret == 0 ? Z_KINFO : Z_KERR, ZKLOG_TAG_SUBVOL_CRE, 
			          "txn[%llu] flush[%s] took %llums, ret=%d",
			          trans->transid, bdevname(ctx->dm_btrfs_bdev, bname), elapsed_ms, ret);
	}

	return ret;
}

void zbtrfs_blk_virt_cre_snap_ctx_fini(struct zbtrfs_blk_virt_cre_snap_ctx *ctx)
{
	if (ctx->dm_btrfs_bdev)
		blkdev_put(ctx->dm_btrfs_bdev, FMODE_READ|FMODE_WRITE);
}

/********Journal replay*****************************************/

struct zbtrfs_replay_copy_ctx {
	struct completion	wait;
	int	ret;
};

struct zbtrfs_replay_ctx {
	u64 old_ei_bytenr;
	u64 ei_bytenr;
	void *trans_handle;
	u64 transid;
	u64 tree_id;
};

/*
 * Verify that chunk to be replayed realy needs "COW".
 * If chunk is mapped, return its mapping via *out_bytenr.
 * @return 0 if chunk can be replayed (COW'ed), <0 on error
 * @note this function returns virtual bytenr and does not map to physical!!!
 */
static int zbtrfs_blk_virt_check_chunk_for_replay(struct btrfs_root *root, u64 ino, 
			u64 chunk_index, unsigned int gran_bytes, 
			u64 *out_bytenr, struct btrfs_trans_handle* trans)
{
	int ret = 0;
	struct btrfs_path *path = NULL;
	struct btrfs_key ed_key;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	/* Lookup the chunk in the file tree - we want exact match */
	ed_key.objectid = ino;
	ed_key.type = BTRFS_EXTENT_DATA_KEY;
	ed_key.offset = chunk_index * gran_bytes;

	ret = btrfs_search_slot(trans, root, &ed_key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret < 0) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_search_slot() ret=%d", root->objectid, ino, chunk_index, ret);
		goto out;
	}
	if (ret) {
		btrfs_release_path(path);
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] NOT FOUND NEED COW", root->objectid, ino, chunk_index);
		/* chunk is not mapped, we need COW */
		*out_bytenr = ULONG_MAX;
		ret = 0;
	} else {
		/* chunk is mapped, check if this extent is shared by anybody else */
		struct extent_buffer *leaf = path->nodes[0];
		struct btrfs_bv_file_extent_item *bfei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_bv_file_extent_item);
		u64 existing_bytenr = ULONG_MAX;

		ret = zbtrfs_blk_virt_check_bv_file_extent_item(root, ino, ed_key.offset, gran_bytes, leaf, path->slots[0], bfei);
		if (ret < 0) {
			btrfs_release_path(path);
			goto out;
		}

		existing_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] found EXTENT_DATA bytenr=%llu", root->objectid, ino, chunk_index, existing_bytenr);
		btrfs_release_path(path);

		ret = btrfs_cross_ref_exist(trans, root, ino, ed_key.offset, existing_bytenr);
		if (ret < 0) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_cross_ref_exist() ret=%d", root->objectid, ino, chunk_index, ret);
			goto out;
		}

		/*
		 * In general, if we have a journal entry, this means
		 * we had to COW this chunk before the crash. but now
		 * btrfs_cross_ref_exist() says we shouldn't have cow'ed.
		 * This might happen in several cases:
		 * 1) OBSOLETE: our allocator could have told us to COW. 
		 *    so ask the allocator if we should still go ahead and
		 *    do what the journal tells us, or we should declare this to be
		 *    an error.
		 * 2) this can also happen without a special allocator:
		 *   - chunk X is mapped and COW is not required
		 *   - chunk X is unmapped (DISCARDed)
		 *   - WRITE comes to chunk X in the same transaction,
		 *     so COW is performed and journalled
		 *   - we crash before the transaction commits
		 *   ==> after we come up, we see chunk X properly mapped and COW
		 *       is not required, but our journal tells us we need to COW.
		 * 3) another case:
		 *   - btrfs commits transaction X
		 *   - btrfs starts committing transaction X+1, in which a snapshot is created
		 *   - commits goes into the writeout section, and transaction X+2 opens
		 *   - a particular chunk is COW'ed due to snapshot that has been created in transaction X+1 
		 *     (although this transaction is not fully on-disk yet)
		 *   - we crash
		 *   ==> When we come up, we have journal entries for two uncommitted transactions - X+1 and X+2.
		 *       And the snapshot has not been created. Luckily, journal is smart enough to replay the proper 
		 *       entries from both transactions. Now, we see that journal asks us to COW a chunk, but extent 
		 *       tree tells us that COW is not needed. This is because COW was needed after we created a snapshot in 
		 *       transaction X+1, but we haven't committed it, so snapshot has not been really created. 
		 *       So now COW is not needed. 
		 *
		 * See issue https://github.com/zadarastorage/Zadara-VC/issues/3322 for more details.
		 * Bottom line is that if journal tells us to COW, we need to COW.
		 */
		if (ret == 0)
			ZBTRFSLOG_TAG(root->fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] found EXTENT_DATA bytenr=%llu NOCOW, but journal wants COW => COW",
			              root->objectid, ino, chunk_index, existing_bytenr);
		/* COW is needed */
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] found EXTENT_DATA bytenr=%llu NEED COW", root->objectid, ino, chunk_index, existing_bytenr);
		*out_bytenr = existing_bytenr;
		ret = 0;
	}

out:
	btrfs_free_path(path);
	return ret;
}

/*
 * This API is used during journal replay, and it is assumed that the FS
 * is fully static, e.g., no snapshot deletion is going on right now, and no
 * IO is being submitted through block-virt APIs or through standard FS APIs.
 * We check whether there exists an EXTENT_ITEM that (even if partially) overlaps (physical_bytenr, len_bytes)
 * @return <0 on error, 
 *         0 if physical_bytenr is not in use (and thus data can be read from there),
 *         1 if physical bytenr is in use, and needs to be left alone.
 * Update: This API actually was not working properly, because it was searching for EXTENT_ITEMs,
 *         but there could be delayed references, for EXTENT_ITEMs which are not inserted yet into
 *         the extent tree.
 *         Also in kernel 3.18, when a new btrfs-chunk is allocated, we only create an in-memory block-group
 *         and update the mapping tree. So searching through the extent-tree/device-tree we will not find
 *         the new chunk until transaction commits.
 * So disable this API; if journal has an address, let's assume we can read from there.
 */
static int zbtrfs_blk_virt_is_physical_chunk_in_use(struct btrfs_fs_info *fs_info, u64 physical_bytenr, u64 len_bytes)
{
#if 1
	return 0;
#else
	int ret = 0;
	struct btrfs_key key;
	struct btrfs_path *path = NULL;
	struct btrfs_dev_extent *dev_extent_item = NULL;
	u64 dev_extent_offset = 0;
	u64 dev_extent_len = 0;
	u64 blk_group_bytenr = 0;
	struct btrfs_block_group_cache *cache = NULL;
	u64 chunk_start_ei_bytenr = 0;

	if (len_bytes == 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "physical_bytenr=%llu len_bytes==0", physical_bytenr);
		ret = -EINVAL;
		goto out;
	}

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	/* 
	 * Step 1 - lookup the DEV_EXTENT item.
	 */
	key.objectid = 1; /* we should have only one device, which is never replaced, otherwise, we need to lookup the dev id */
	key.type = BTRFS_DEV_EXTENT_KEY;
	key.offset = physical_bytenr + (len_bytes - 1);

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu) btrfs_search_slot_for_read(%llu DEV_EXTENT %llu)", physical_bytenr, len_bytes, key.objectid, key.offset);
	ret = btrfs_search_slot_for_read(fs_info->dev_root, &key, path, 0/*find_higher*/, 0/*return_any*/);
	if (ret < 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "btrfs_search_slot_for_read(%llu DEV_EXTENT %llu) failed, ret=%d", key.objectid, key.offset, ret);
		goto out;
	}
	if (ret) {
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "btrfs_search_slot_for_read(%llu DEV_EXTENT %llu) ret=1", key.objectid, key.offset);
		/* 
		 * this should not happen, because there should always be lowest DEV_EXTENT item
		 * for SYSTEM chunk and also the DEV_STATS item; but if it happens somehow, 
		 * we can probably assume that this physical address is not in use.
		 */
		ret = 0;
		goto out;
	}

	/* we have found the DEV_EXTENT item, do further checks */
	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
	if (key.type != BTRFS_DEV_EXTENT_KEY) {
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu) found (%llu %u %llu)", physical_bytenr, len_bytes,
			          key.objectid, btrfs_key_type(&key), key.offset);
		/* 
		 * this is probably DEV_STATS item, so somehow the lowest SYSTEM DEV_EXTENT item does not exist.
		 * probably also ok to assume that this physical address is not in use.
		 */
		ret = 0;
		goto out;
	}

	dev_extent_item = btrfs_item_ptr(path->nodes[0], path->slots[0], struct btrfs_dev_extent);
	dev_extent_offset = key.offset;
	dev_extent_len = btrfs_dev_extent_length(path->nodes[0], dev_extent_item);
	blk_group_bytenr = btrfs_dev_extent_chunk_offset(path->nodes[0], dev_extent_item);
	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu) found (%llu DEV_EXTENT %llu) BLOCK_GROUP[%llu:%llu]", 
		          physical_bytenr, len_bytes,
			      key.objectid, key.offset,
			      blk_group_bytenr, dev_extent_len);

	/* this really should not happen  - bug in btrfs_search_slot_for_read() */
	if (dev_extent_offset > physical_bytenr + (len_bytes - 1)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu) found (%llu DEV_EXTENT %llu too high)", physical_bytenr, len_bytes,
			          key.objectid, key.offset);
		WARN_ON(key.offset > physical_bytenr);
		ret = -ECANCELED;
		goto out;
	}

	/* if the physical chunk is fully outside the DEV_EXTENT, it is not in use */
	if (dev_extent_offset + dev_extent_len <= physical_bytenr) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu) not within (%llu DEV_EXTENT %llu) dev_ext_len=%llu",
				      physical_bytenr, len_bytes,
				      key.objectid, key.offset, dev_extent_len);
		ret = 0;
		goto out;
	}

	/* otherwise, the physical chunk should be fully inside the DEV_EXTENT, i.e., not partially overlapping */
	if (!(physical_bytenr >= dev_extent_offset && physical_bytenr + len_bytes <= dev_extent_offset + dev_extent_len)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu) not fully within (%llu DEV_EXTENT %llu) dev_ext_len=%llu",
			          physical_bytenr, len_bytes,
			          key.objectid, key.offset, dev_extent_len);
		ret = -ECANCELED;
		goto out;	      
	}

	btrfs_release_path(path);
	memset(path, 0, sizeof(struct btrfs_path));

	/*
	 * Step 2 - lookup the BLOCK_GROUP_ITEM, we need exact match here.
	 * Since the BLOCK_GROUP_ITEM is inserted only during transaction commit,
	 * we search the in-memory structures and not the extent tree.
	 */
	cache = btrfs_lookup_block_group(fs_info, blk_group_bytenr);
	if (cache == NULL) {
		/* if we have DEV_EXTENT, we should have the BLOCK_GROUP */
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): btrfs_lookup_block_group(%llu) not found", 
			          physical_bytenr, len_bytes, blk_group_bytenr);
		ret = -ENOKEY;
		goto out;
	}
	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): block_group(%llu:%llu) flags=%llu(0x%llx)", 
		          physical_bytenr, len_bytes,
		          blk_group_bytenr, dev_extent_len, cache->flags, cache->flags);

	/* 
	 * Check that our profile is DATA/"single".
	 * If not, this means that we are really unlucky, and the DATA chunk allocation that
	 * happened before crash, is not valid anymore, and there is some other, non-DATA
	 * chunk allocated. It can still be ok to read from that physical address, 
	 * but translation of physical address to EXTENT_ITEM address might be more complicated.
	 * For now, let's not read from there.
	 */
	if (cache->flags != BTRFS_BLOCK_GROUP_DATA) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): block_group(%llu:%llu) flags=%llu(0x%llx) not %llu(0x%llx)", 
			          physical_bytenr, len_bytes,
				      blk_group_bytenr, dev_extent_len, cache->flags, cache->flags, BTRFS_BLOCK_GROUP_DATA, BTRFS_BLOCK_GROUP_DATA);
		WARN_ON(cache->flags != BTRFS_BLOCK_GROUP_DATA);
		ret = 1;
		goto out;
	}
	btrfs_put_block_group(cache);
	cache = NULL;

	/* At this point, we can map the physical address to EXTENT_ITEM and lookup it up */
	/* ALEXL-TODO: handle skinny metadata or not needed??? */
	chunk_start_ei_bytenr = blk_group_bytenr + (physical_bytenr - dev_extent_offset);
	key.objectid =  chunk_start_ei_bytenr + (len_bytes - 1);
	key.type = BTRFS_EXTENT_ITEM_KEY;
	key.offset = (u64)-1;

	while (true) {
		u64 search_ei_bytenr = key.objectid;

		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): btrfs_search_slot_for_read(%llu EXTENT_ITEM -1)", 
			          physical_bytenr, len_bytes, search_ei_bytenr);
		ret = btrfs_search_slot_for_read(fs_info->extent_root, &key, path, 0/*find_higher*/, 0/*return_any*/);
		if (ret < 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): btrfs_search_slot_for_read(%llu EXTENT_ITEM -1) ret=%d", 
				          physical_bytenr, len_bytes, search_ei_bytenr, ret);
			goto out;
		}
		if (ret) {
			/* nothing found? assume extent not in use */
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): btrfs_search_slot_for_read(%llu EXTENT_ITEM -1) not found", 
			              physical_bytenr, len_bytes, search_ei_bytenr);
			ret = 0;
			goto out;
		}

		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): btrfs_search_slot_for_read(%llu EXTENT_ITEM -1) found (%llu %u %llu)",
			          physical_bytenr, len_bytes,
			          search_ei_bytenr, 
			          key.objectid, btrfs_key_type(&key), key.offset);
		/* this really should not happen - bug in btrfs_search_slot_for_read() */
		if (key.objectid > search_ei_bytenr) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): btrfs_search_slot_for_read(%llu EXTENT_ITEM -1) found (%llu too high %u %llu)",
				          physical_bytenr, len_bytes,
				          search_ei_bytenr, 
				          key.objectid, btrfs_key_type(&key), key.offset);
			WARN_ON(key.objectid > search_ei_bytenr);
			ret = -ECANCELED;
			goto out;
		}

		/*
		 * if we have found a BLOCK_GROUP item, we need to continue searching, 
		 * because BTRFS_EXTENT_ITEM_KEY < BTRFS_BLOCK_GROUP_ITEM_KEY, and there might be
		 * a BTRFS_EXTENT_ITEM_KEY with the same objectid as BTRFS_BLOCK_GROUP_ITEM_KEY right
		 * behind us
		 */
		if (key.type == BTRFS_BLOCK_GROUP_ITEM_KEY) {
			/* key.objectid is fine here */
			key.type = BTRFS_EXTENT_ITEM_KEY;
			key.offset = (u64)-1;

			btrfs_release_path(path);
			memset(path, 0, sizeof(struct btrfs_path));

			continue;
		}

		/* this should not happen actually */
		if (key.type != BTRFS_EXTENT_ITEM_KEY) {
			/* not in use */
			ret = 0;
			goto out;
		}

		/* there is only one way for us to be outside the EXTENT_ITEM fully, otherwise, there is some overlap */
		if (key.objectid + key.offset <= chunk_start_ei_bytenr) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): ei(%llu:%llu) NOT within (%llu EXTENT_ITEM %llu)",
				          physical_bytenr, len_bytes,
				          chunk_start_ei_bytenr, len_bytes, key.objectid, key.offset);
			ret = 0;
		} else {
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "physical(%llu:%llu): ei(%llu:%llu) OVERLAPS (%llu EXTENT_ITEM %llu)",
				          physical_bytenr, len_bytes,
				          chunk_start_ei_bytenr, len_bytes, key.objectid, key.offset);
			ret = 1;
		}

		break;
	}

out:
	if (cache)
		btrfs_put_block_group(cache);
	if (path)
		btrfs_free_path(path);

	return ret;
#endif
}

int zbtrfs_blk_virt_get_chunk_for_replay(struct btrfs_fs_info *fs_info, u64 tree_id,
							   u64 *out_phys_bytenr, void **replay_ctx)
{
	int ret = 0;
	void *current_journal_info = current->journal_info;
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_key ei_key;
	struct btrfs_root *root = NULL;
	u32 gran_bytes = fs_info->zfs_info.pool_gran_bytes;
	struct zbtrfs_replay_ctx *ctx = NULL;

	/* we should not be called here in case of read-only mount */
	if (ZBTRFS_WARN(fs_info->sb->s_flags & MS_RDONLY, "FS[%s]: should not be called on read-only mount!", fs_info->sb->s_id)) {
		ret = -EROFS;
		goto out;
	}

	ctx = kmem_cache_zalloc(zbtrfs_globals.replay_ctx_cachep, GFP_NOFS);
	if (ctx == NULL) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "Cannot allocate zbtrfs_replay_ctx");
		ret = -ENOMEM;
		goto out;
	}

	*replay_ctx = ctx;
	ctx->tree_id = tree_id;
	/* fill context with invalid data, just to hit bugs early */
	ctx->old_ei_bytenr = ULONG_MAX;
	ctx->ei_bytenr = ULONG_MAX;
	ctx->trans_handle = NULL;
	ctx->transid = ULONG_MAX;

	/* find root*/
	ei_key.objectid = tree_id;
	ei_key.type = BTRFS_ROOT_ITEM_KEY;
	ei_key.offset = (u64)-1;
	root = btrfs_read_fs_root_no_name(fs_info, &ei_key);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "could not find root %llu ret=%d", tree_id, ret);
		root = NULL;
		goto out;
	}

	ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "root=%llu gran=%u", root->objectid, gran_bytes);	

	if (unlikely(ZBTRFS_FS_ERROR(fs_info))) {
		ZBTRFSLOG_TAG_RL(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu FS ERROR", root->objectid);
		ret = -EROFS;
		goto out;
	}
	if (unlikely(btrfs_root_readonly(root))) {
		ZBTRFSLOG_TAG_RL(fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "root=%llu RO", root->objectid);
		ret = -EROFS;
		goto out;
	}

	current->journal_info = NULL; /* btrfs_join_transaction() expects this */
	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu btrfs_join_transaction() ret=%d", root->objectid, ret);
		trans = NULL;
		goto out;
	}

	/* allocate new chunk location */
	ret = btrfs_reserve_extent(root, gran_bytes/*num_bytes*/, gran_bytes/*min_alloc_size*/,
			0/*empty_size*/, 0/*hint_byte*/, &ei_key, 1/*is_data*/, 0/*delalloc*/);
	if (ZBTRFS_WARN_ON(ret > 0))
		ret = -ECANCELED;
	if (ret < 0) {
		ZBTRFSLOG_TAG_RL(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu zbtrfs_reserve_data_extent() ret=%d", root->objectid, ret);
		goto out;
	}
	ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "root=%llu reserved EXTENT_ITEM(%llu,%u,%llu)", root->objectid,
		          ei_key.objectid, ei_key.type, ei_key.offset);
	ret = zbtrfs_check_extent_item_key(root, 0/*ino*/, gran_bytes, &ei_key);
	if (ret < 0)
		goto out;

	/* map the new chunk */
	ret = zbtrfs_blk_virt_map_block(fs_info, BTRFS_BLOCK_GROUP_DATA, 
			ei_key.objectid, gran_bytes, out_phys_bytenr);
	if (ret < 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu] failed new mapping[%llu:%u]", root->objectid, ei_key.objectid, gran_bytes);
		goto out;
	}

	/* fill the rest of our context and tell the caller chunk allocated */
	ctx->ei_bytenr = ei_key.objectid;
	ctx->trans_handle = trans;
	ctx->transid = trans->transid;
	ret = 0;

out:
	/*
	 * ret == 0:  we return the transaction back to the caller
	 * ret < 0:  maybe we need to detach from trans
	 */
	if (ret < 0) {
		if (ctx) {
			if (ctx->ei_bytenr != ULONG_MAX)
				btrfs_free_reserved_extent(root, ctx->ei_bytenr, gran_bytes, 0/*delalloc*/);
			kmem_cache_free(zbtrfs_globals.replay_ctx_cachep, ctx);
		}
		/* detach from transaction, if we have one */
		if (trans)
			btrfs_end_transaction(trans, root);
	}

	current->journal_info = current_journal_info;
	return ret;
}

static int zbtrfs_blk_virt_journal_chunk_migr_completed(struct btrfs_fs_info *fs_info, struct btrfs_root *root, u64 ino, u64 tree_id, u64 chunk_index, u16 tenant_id,
		struct zbtrfs_replay_ctx *ctx, int migr_ret)
{
	int ret = 0;
	struct btrfs_trans_handle *trans = ctx->trans_handle;
	struct btrfs_key ei_key;
	u32 gran_bytes = fs_info->zfs_info.pool_gran_bytes;

	if (ctx->old_ei_bytenr == ULONG_MAX)
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] old_ei_bytenr=ULONG_MAX ei_bytenr=%llu tenant=%u migr_ret=%d", 
		              root->objectid, ino, chunk_index, ctx->ei_bytenr, tenant_id, migr_ret);
	else
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] old_ei_bytenr=%llu ei_bytenr=%llu tenant=%u migr_ret=%d",
		              root->objectid, ino, chunk_index, ctx->old_ei_bytenr, ctx->ei_bytenr, tenant_id, migr_ret);

	/* detaching from transaction expects to find this */
	current->journal_info = trans;

	if (unlikely(migr_ret)) {
		/* migration failed - we need to free whatever we have allocated */
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] free EXTENT_ITEM(%llu %u %llu) migr_ret=%d",
		              root->objectid, ino, chunk_index, ctx->ei_bytenr, BTRFS_EXTENT_ITEM_KEY, (u64)gran_bytes, migr_ret);
		btrfs_free_reserved_extent(root, ctx->ei_bytenr, gran_bytes, 0/*delalloc*/);
		goto out;
	}

	if (ctx->old_ei_bytenr == ULONG_MAX) {
		struct btrfs_key inode_key;
		struct inode *inode = NULL;
		int new_inode = 0;

		/* there was no previous mapping, we need a new EXTENT_DATA */
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] insert EXTENT_DATA(%llu,%u,%llu)", ino, chunk_index,
		              root->objectid, ino, BTRFS_EXTENT_DATA_KEY, chunk_index * gran_bytes);

		ret = btrfs_insert_bv_file_extent(trans, root, ino, chunk_index * gran_bytes,
				ctx->ei_bytenr/*disk_bytenr*/);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_insert_file_extent() failed, ret=%d", root->objectid, ino, chunk_index, ret);
			btrfs_free_reserved_extent(root, ctx->ei_bytenr, gran_bytes, 0/*delalloc*/);
			goto out;
		}

		/* 
		 * we changed the file tree - update ctransid.
		 * also, previously chunk was not mapped, so
		 * we need to count this chunk towards "mapped capacity".
		 */
		inode_key.objectid = ino;
		inode_key.type = BTRFS_INODE_ITEM_KEY;
		inode_key.offset = 0;
		inode = btrfs_iget(fs_info->sb,  &inode_key, root, &new_inode);
		if (unlikely(IS_ERR(inode))) {
			int iget_ret = PTR_ERR(inode);
			ZBTRFS_WARN(iget_ret, "FS[%s]: [%llu:%llu:%llu] btrfs_iget() failed ret=%d", 
				        fs_info->sb->s_id, root->objectid, ino, chunk_index, iget_ret);
			/* let's not fail the replay, it's only for statistics */
			inode = NULL;
		}
		zbtrfs_update_blk_virt_inode_on_cow(trans, root, inode/*can be NULL*/, 1/*mod_chunk_alloc*/);
		iput(inode); /* it's ok to pass NULL */

	} else {
		struct btrfs_path *path = NULL;
		struct btrfs_key ed_key;
		struct extent_buffer *leaf = NULL;
		struct btrfs_bv_file_extent_item *bfei = NULL;

		/* We need to modify existing EXTENT_DATA - re-search with COW */
		ed_key.objectid = ino;
		ed_key.type = BTRFS_EXTENT_DATA_KEY;
		ed_key.offset = chunk_index * gran_bytes;

		path = btrfs_alloc_path();
		if (!path) {
			ret = -ENOMEM;
			goto out;
		}

		ret = btrfs_search_slot(trans, root, &ed_key, path, 0/*ins_len*/, 1/*cow*/);
		if (ret > 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] on re-search EXTENT_DATA(%llu,%u,%llu) not found!", root->objectid, ino, chunk_index,
				          ino, BTRFS_EXTENT_DATA_KEY, chunk_index * gran_bytes);
			ret = -ENOENT;
		} else if (ret < 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] on re-search EXTENT_DATA(%llu,%u,%llu) ret=%d", root->objectid, ino, chunk_index,
				          ino, BTRFS_EXTENT_DATA_KEY, chunk_index * gran_bytes, ret);
		}
		if (ret) {
			btrfs_free_path(path);
			btrfs_free_reserved_extent(root, ctx->ei_bytenr, gran_bytes, 0/*delalloc*/);
			goto out;
		}

		leaf = path->nodes[0];
		bfei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_bv_file_extent_item);

		zbtrfs_blk_virt_check_bv_file_extent_item(root, ino, ed_key.offset, gran_bytes, leaf, path->slots[0], bfei);
		WARN_ON(ctx->old_ei_bytenr != btrfs_bv_file_extent_disk_bytenr(leaf, bfei));
		ctx->old_ei_bytenr = btrfs_bv_file_extent_disk_bytenr(leaf, bfei);

		btrfs_set_bv_file_extent_disk_bytenr(leaf, bfei, ctx->ei_bytenr);

		btrfs_mark_buffer_dirty(leaf);
		btrfs_free_path(path);

		/* 
		 * we changed the file tree - update ctransid
		 * previously chunk was mapped, so we don't count it
		 * towards "mapped capacity".
		 * since we don't count chunk allocation, 
		 * we don't need the inode.
		 */
		zbtrfs_update_blk_virt_inode_on_cow(trans, root, NULL/*inode*/, 0/*mod_chunk_alloc*/);

		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] modify EXTENT_DATA(%llu,%u,%llu) gen=%llu bytenr:%llu=>%llu", root->objectid, ino, chunk_index,
			          ino, BTRFS_EXTENT_DATA_KEY, ed_key.offset,
			          trans->transid, ctx->old_ei_bytenr, ctx->ei_bytenr);

		ret = btrfs_free_extent(trans, root, ctx->old_ei_bytenr, gran_bytes, 
				0/*parent*/, root->objectid, ino, ed_key.offset,
				1/*no_quota*/);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_free_extent(%llu,%u,%u) ret=%d ABORT", root->objectid, ino, chunk_index,
				          ctx->old_ei_bytenr, BTRFS_EXTENT_ITEM_KEY, gran_bytes, ret);
			/* 
			 * We have modified the file tree, but failed to add a delayed ref,
			 * so we need to abort the transaction.
			 */
			btrfs_abort_transaction(trans, root, ret);
			goto out;
		}
	}

	/* insert EXTENT_ITEM - add delayed ref */
	ei_key.objectid = ctx->ei_bytenr;
	ei_key.type = BTRFS_EXTENT_ITEM_KEY;
	ei_key.offset = gran_bytes;

	ret = zbtrfs_alloc_reserved_file_extent(trans, root, 
			root->objectid, ino, chunk_index * gran_bytes,
			&ei_key,
			tenant_id);
	if (ret) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_alloc_reserved_file_extent(%llu,%u,%llu) tenant=%u ret=%d ABORT", root->objectid, ino, chunk_index,
			          ctx->ei_bytenr, BTRFS_EXTENT_ITEM_KEY, (u64)gran_bytes, tenant_id, ret);
		/* 
		 * We have modified the file tree, but failed to add a delayed ref,
		 * so we need to abort the transaction.
		 */
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

out:
	/* detach from transaction */
	{
		int end_trans_ret = btrfs_end_transaction(trans, root);
		if (end_trans_ret && ret == 0)
			ret = end_trans_ret;
	}

	return ret;
}

static void zbtrfs_blk_virt_journal_copy_callback(int read_err, unsigned long write_err, void *ctx)
{
	struct zbtrfs_replay_copy_ctx *copy_ctx = (struct zbtrfs_replay_copy_ctx *)ctx;
	if (read_err || write_err)
		copy_ctx->ret = -EIO;
	complete(&copy_ctx->wait);
}

int zbtrfs_blk_virt_journal_replay_entry(struct btrfs_fs_info *fs_info, const struct zjournal_entry *entry, u64 allocated_address, u16 tenant_id, void *replay_ctx)
{
	u64 ino = entry->inode_num;
	u64 generation = entry->inode_gen;
	u64 tree_id = entry->subvol_treeid;
	u64 file_offset = entry->file_offset;
	u64 chunk_address = entry->address;

	int ret = 0;
	struct zbtrfs_replay_copy_ctx copy_ctx;
	u32 gran_bytes = fs_info->zfs_info.pool_gran_bytes;
	struct zbtrfs_replay_ctx *ctx = (struct zbtrfs_replay_ctx *)replay_ctx;
	struct btrfs_trans_handle *trans = ctx->trans_handle;
	struct btrfs_key key;
	struct btrfs_root *root, *new_root;
	struct btrfs_path *path = NULL;
	struct btrfs_inode_item *ini = NULL;
	struct extent_buffer *leaf = NULL;
	void *current_journal_info = current->journal_info;
	u64 chunk_index = file_offset / gran_bytes;
	u64 inode_generation;

	/* we checked earlier for read-only mount */
	ZBTRFS_WARN(fs_info->sb->s_flags & MS_RDONLY, "FS[%s]: should not be called for read-only mount!", fs_info->sb->s_id);

	key.objectid = ctx->tree_id;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(root)) {
		copy_ctx.ret = PTR_ERR(root);
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "could not find root %llu ret=%d", ctx->tree_id, copy_ctx.ret);
		root = NULL;
		goto out;
	}

	if (file_offset % gran_bytes != 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "root=%llu file_offset=%llu is not on chunk boundary (%u)", ctx->tree_id, file_offset, gran_bytes);
		copy_ctx.ret = 1;
		goto out;
	}

	/* check if this entry is in same tree as allocated */
	if (tree_id != ctx->tree_id) {
		/* find new root*/
		key.objectid = tree_id;
		key.type = BTRFS_ROOT_ITEM_KEY;
		key.offset = (u64)-1;
		new_root = btrfs_read_fs_root_no_name(fs_info, &key);
		if (IS_ERR(new_root)) {
			copy_ctx.ret = PTR_ERR(new_root);
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "could not find new root %llu ret=%d", tree_id, copy_ctx.ret);
			new_root = NULL;
			goto out;
		}

		/* join transaction with correct tree_id */
		current->journal_info = NULL; /* btrfs_join_transaction() expects this */
		trans = btrfs_join_transaction(new_root);
		if (IS_ERR(trans)) {
			copy_ctx.ret = PTR_ERR(trans);
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_join_transaction() ret=%d", new_root->objectid, ino, chunk_index, copy_ctx.ret);
			trans = NULL;
			goto out;
		}
		if (ctx->transid != trans->transid) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] transid %llu != %llu", new_root->objectid, ino, chunk_index, ctx->transid, trans->transid);
			copy_ctx.ret = 1;
			goto out;
		}
		/* end old transaction */
		/* detaching from transaction expects to find this */
		current->journal_info = ctx->trans_handle;
		copy_ctx.ret = btrfs_end_transaction(ctx->trans_handle, root);
		ctx->trans_handle = trans;
		root = new_root;
		if (copy_ctx.ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] btrfs_end_transaction() ret=%d",
				          root->objectid, ino, chunk_index, copy_ctx.ret);
			goto out;
		}
	}
	copy_ctx.ret = 0;

	/* verify generation */
	path = btrfs_alloc_path();
	if (!path) {
		copy_ctx.ret = -ENOMEM;
		goto out;
	}

	key.objectid = ino;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;

	copy_ctx.ret = btrfs_search_slot(NULL/*trans*/, root, &key, path, 0/*ins_len*/, 0/*cow*/);
	if (copy_ctx.ret) {
		btrfs_free_path(path);
		if (copy_ctx.ret > 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] search INODE_ITEM(%llu,%u,0) not found!", root->objectid, ino, chunk_index,
				          ino, BTRFS_INODE_ITEM_KEY);
			ret = -ENOENT;
		} else {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] search INODE_ITEM(%llu,%u,0) ret=%d", root->objectid, ino, chunk_index,
				          ino, BTRFS_INODE_ITEM_KEY, ret);
		}
		goto out;
	}

	leaf = path->nodes[0];
	ini = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_inode_item);
	inode_generation = btrfs_inode_generation(leaf, ini);
	btrfs_free_path(path);
	if (inode_generation != generation) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] generation changed %llu->%llu", root->objectid, ino, chunk_index,
			          generation, inode_generation);
		copy_ctx.ret = 1;
		goto out;
	}

	copy_ctx.ret = zbtrfs_blk_virt_is_physical_chunk_in_use(fs_info, chunk_address, gran_bytes);
	if (unlikely(copy_ctx.ret)) {
		if (copy_ctx.ret < 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] failed to check if chunk in use ret=%d",
				          root->objectid, ino, chunk_index, -copy_ctx.ret);
		} else {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] Address %llu is allocated",
				          root->objectid, ino, chunk_index, chunk_address);
		}
		goto out;
	}

	copy_ctx.ret = zbtrfs_blk_virt_check_chunk_for_replay(root, ino, chunk_index, gran_bytes, &ctx->old_ei_bytenr, trans);
	if (unlikely(copy_ctx.ret)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, " Chunk don't require COW or can't verify, [%llu:%llu:%llu] ei_bytenr=%llu migr_ret=%d", 
			          root->objectid, ino, chunk_index, ctx->ei_bytenr, copy_ctx.ret);
		goto out;
	}
	if (ctx->old_ei_bytenr == ULONG_MAX)
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] old_ei_bytenr=ULONG_MAX ei_bytenr=%llu", 
		              root->objectid, ino, chunk_index, ctx->ei_bytenr);
	else
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_BLKVIRT, "[%llu:%llu:%llu] old_ei_bytenr=%llu ei_bytenr=%llu",
		              root->objectid, ino, chunk_index, ctx->old_ei_bytenr, ctx->ei_bytenr);

	if (chunk_address != allocated_address) {
		/* migrate this chunk */
		struct dm_io_region src, dest;
		src.bdev = fs_info->zfs_info.pool_data_bdev;
		src.sector = BYTES_TO_BLK(chunk_address);
		src.count = BYTES_TO_BLK(gran_bytes);

		dest.bdev = fs_info->zfs_info.pool_data_bdev;
		dest.sector = BYTES_TO_BLK(allocated_address);
		dest.count = src.count;

		/* Hand over to kcopyd */
		init_completion(&copy_ctx.wait); 
		dm_kcopyd_copy(zbtrfs_globals.kcopyd_client, &src, 1, &dest, 0, zbtrfs_blk_virt_journal_copy_callback, &copy_ctx);
		wait_for_completion(&copy_ctx.wait);
	}
out:
	ret = zbtrfs_blk_virt_journal_chunk_migr_completed(fs_info, root, ino, tree_id, chunk_index, tenant_id, ctx, copy_ctx.ret);
	current->journal_info = current_journal_info;
	kmem_cache_free(zbtrfs_globals.replay_ctx_cachep, ctx);
	if (ret == 0)
		ret = copy_ctx.ret;
	return ret;
}

int zbtrfs_blk_virt_cancel_journal_replay_entry(struct btrfs_fs_info *fs_info, void *replay_ctx)
{
	int ret = 1;
	struct zbtrfs_replay_ctx *ctx = (struct zbtrfs_replay_ctx *)replay_ctx;
	struct btrfs_key key;
	struct btrfs_root *root;
	void *current_journal_info = current->journal_info;

	/* we checked earlier for read-only mount */
	ZBTRFS_WARN(fs_info->sb->s_flags & MS_RDONLY, "FS[%s]: should not be called for read-only mount!", fs_info->sb->s_id);

	key.objectid = ctx->tree_id;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_BLKVIRT, "could not find root %llu ret=%d", ctx->tree_id, ret);
		root = NULL;
	}

	/* 
	 * we are failing chunk migration here, so we don't need real values for:
	 * - inode number
	 * - chunk_index
	 * - tenant_id
	 */
	ZBTRFS_BUG_ON(ret == 0);
	ret = zbtrfs_blk_virt_journal_chunk_migr_completed(fs_info, root, 0/*ino*/, ctx->tree_id, ULONG_MAX/*chunk_index*/, ZBTRFS_ZTENANT_SYSTEM_ID, ctx, ret/*migr_ret*/);
	current->journal_info = current_journal_info;
	kmem_cache_free(zbtrfs_globals.replay_ctx_cachep, ctx);
	if (ret == 0)
		ret = 1;

	return ret;
}

size_t zbtrfs_replay_ctx_size(void)
{
	return sizeof(struct zbtrfs_replay_ctx);
}
#endif /*CONFIG_BTRFS_ZADARA*/

