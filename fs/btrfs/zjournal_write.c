#ifdef CONFIG_BTRFS_ZADARA
#include "zjournal.h"

static int zjournal_map_get_next_item(void);
static void zjournal_write_end_io(struct bio *bio, int error);

void zjournal_write(u16 pool_id, u64 subvol_treeid, u64 inode_num, u64 inode_gen, u64 file_offset, u64 address, u64 transid, u16 tenant_id, zjournal_end_io_func cb_func, void *cb_arg)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];
	struct zjournal_disk_item *disk_item = NULL;
	struct bio *bio = NULL;
	int item_idx = -1;
	struct blk_plug plug;
	int rc;

	/* ZJOURNAL_CHECK_ARGS(pool_id); */
	if (unlikely(!globals.enable)) {
		zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: disabled", globals.jpath, pool_id);
		cb_func(cb_arg, 0);
		return;
	}
	if (unlikely(pool_id<ZJOURNAL_MIN_POOL_ID || pool_id>ZJOURNAL_MAX_POOL_ID)) {
		zklog_tag(pool_id==0 ? Z_KDEB1 : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: invalid pool_id", globals.jpath, pool_id);
		if(pool_id==0) {
			cb_func(cb_arg, 0);
			return;
		}
		rc = -EINVAL;
		goto end_err;
	}
	if (unlikely(globals.jdev==NULL)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: journal was not opened", globals.jpath, pool_id);
		rc = -EBADF;
		goto end_err;
	}
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);

	if (unlikely(!pool->mounted)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: was not replayed yet", globals.jpath, pool_id);
		rc = -EBADF;
		goto end_err;
	}

	if (unlikely(!pool->replayed)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: was not replayed yet", globals.jpath, pool_id);
		rc = -EAGAIN;
		goto end_err;
	}

	item_idx = zjournal_map_get_next_item();
	if (unlikely(item_idx==-1)) {
		/* TODO: insert request into queue, on any commit/umount try to resubmit the entire queue */
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: no free item", globals.jpath, pool_id);
		rc = -ENOSPC;
		goto end_err;
	}
	ZJOURNAL_ASSERT(item_idx>=0 && item_idx<globals.jmap_size, "item_idx=%d, jmap_size=%d", item_idx, globals.jmap_size);

	/* Store the disk item */
	disk_item = kzalloc(ZJOURNAL_DISK_ITEM_SIZE, GFP_NOIO);
	if (unlikely(disk_item==NULL)) {
		rc = -ENOMEM;
		goto end_err;
	}

	zjournal_disk_item_init(disk_item, 
							pool_id, pool->generation, transid, atomic64_inc_return(&pool->io_cnt), tenant_id,
							subvol_treeid, inode_num, inode_gen, file_offset, 
							address);

	disk_item->cb_func = cb_func;
	disk_item->cb_arg = cb_arg;
	disk_item->item_idx = item_idx;
	
	bio = zjournal_bio_map_kern(disk_item, ZJOURNAL_DISK_ITEM_SIZE, GFP_NOIO, &rc);
	if (unlikely(rc!=0))
		goto end_err;

	zklog_tag(Z_KDEB2, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: " FMT_DISK_ITEM,
			  globals.jpath, pool_id, item_idx, PRI_DISK_ITEM(disk_item));

	bio->bi_iter.bi_sector = ZJOURNAL_SUPERBLOCK_SIZE_BLK + item_idx;
	bio->bi_end_io = zjournal_write_end_io;
	bio->bi_private = disk_item;

	blk_start_plug(&plug);
	submit_bio(WRITE, bio);
	blk_finish_plug(&plug);

	return;

end_err:

	BUG_ON(rc==0);

	if(item_idx!=-1) {
		zjournal_map_item_reset(item_idx);
		zjournal_map_item_unlock(item_idx);
	}

	if(disk_item!=NULL)
		kfree(disk_item);

	if(bio!=NULL)
		bio_put(bio);

	cb_func(cb_arg, rc);
}
EXPORT_SYMBOL(zjournal_write);

static void zjournal_write_end_io(struct bio *bio, int error)
{
	struct zjournal_disk_item *disk_item = bio->bi_private;
	zjournal_end_io_func cb_func = disk_item->cb_func;
	void *cb_arg = disk_item->cb_arg;
	int item_idx = disk_item->item_idx;

	if (likely(error==0)) {
		zjournal_map_item_set(item_idx, disk_item);
	}
	else {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: write("FMT_DISK_ITEM") failed, rc=%d",
				  globals.jpath, disk_item->pool_id, item_idx, PRI_DISK_ITEM(disk_item), error);
		zjournal_map_item_reset(item_idx);
	}
	zjournal_map_item_unlock(item_idx);

	bio_put(bio);
	kfree(disk_item);

	cb_func(cb_arg, error);
}

/** 
 * Look for the next available item
 * @return item index on success; -1, if no free item available 
 * @note user has to unlock the item after use 
 */
static int zjournal_map_get_next_item(void)
{
	const struct zjournal_pool *pool;
	struct zjournal_item *item;
	int i, item_idx;
	
	for (i=0; i<globals.jmap_size; i++) {
		item_idx = atomic_inc_return(&globals.jmap_idx);
		item_idx %= globals.jmap_size;
		if(item_idx<0)	/* item_idx may become negative if globals.jmap_idx<0 */
			item_idx += globals.jmap_size;

		item = &globals.jmap[item_idx];

		if(!zjournal_map_item_try_lock(item_idx)) {
			/* This item is locked by another thread, try next one */
			continue;
		}

		if (item->pool_id==0) {
			/* This item is not in use */
			break;
		}

		pool = &globals.pools[item->pool_id];
		ZJOURNAL_ASSERT(pool->pool_id == item->pool_id, "pool->pool_id=%d, item->pool_id=%d", pool->pool_id, item->pool_id);
		if (!pool->created) {
			/* This pool is not in use */
			break;
		}

		if (!pool->mounted) {
			/* This pool was created but not mounted - do not touch its items */
			zjournal_map_item_unlock(item_idx);
			continue;
		}
		
		if (!pool->replayed) {
			/* This pool was mounted but not replayed - do not touch its items */
			zjournal_map_item_unlock(item_idx);
			continue;
		}

		if (pool->max_transid >= item->transid) {
			/* Transaction in this item was already commited */
			break;
		}

		/* This item is in use. Unlock and try next one */
		zjournal_map_item_unlock(item_idx);
	}

	if (i<globals.jmap_size)
		return item_idx;
	else
		return -1;
}

/****************************************************************/
/** COMMIT														*/
/****************************************************************/

int zjournal_commit(u16 pool_id, u64 transid)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];

	ZJOURNAL_CHECK_ARGS(pool_id, true);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);

	/* if we completed mount and are now committing, we should have replayed the journal */
	if (unlikely(pool->fs_info &&
		         pool->fs_info->sb && pool->fs_info->sb->s_root && (pool->fs_info->sb->s_flags & MS_BORN) &&
		         !pool->replayed)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: not replayed", globals.jpath, pool_id);
		return -EINVAL;
	}

	if (unlikely(transid==0)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: invalid transid %llu", globals.jpath, pool_id, transid);
		return -EINVAL;
	}

	if (unlikely(transid <= pool->max_transid)) {
		zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: transid=%llu <= max_transid=%llu", globals.jpath, pool_id, transid, pool->max_transid);
		return 0;
	}

    zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: set max_transid=%llu", globals.jpath, pool_id, transid);
	pool->max_transid = transid;

    return 0;
}
#endif /*CONFIG_BTRFS_ZADARA*/

