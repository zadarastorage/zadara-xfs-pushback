#ifdef CONFIG_BTRFS_ZADARA
#include "zjournal.h"
static int __zjournal_replay_pool(struct zjournal_pool *pool);
static int __zjournal_replay_pool__get_chunks(struct zjournal_pool *pool, u64 *replay_addr_arr, void **replay_ctx_arr, int *replay_addr_cnt);
static void __zjournal_replay_pool__build_migration_list(struct zjournal_pool *pool, const u64 *replay_addr_arr, void **replay_ctx_arr, int replay_addr_cnt);
static int __zjournal_replay_pool__replay_all(struct zjournal_pool *pool);
static void __zjournal_replay_pool__replay_one(struct btrfs_work *work);

int zjournal_replay(u16 pool_id)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];
	int rc;
	
	ZJOURNAL_CHECK_ARGS(pool_id, true);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: replay %d chunks, tree_height=%d", globals.jpath, pool_id, pool->replay_tree_cnt, pool->replay_tree.height);

	if (unlikely(pool->replayed)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: has been already replayed", globals.jpath, pool_id);
		return -EEXIST;
	}

	if (unlikely(!pool->mounted)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: not mounted", globals.jpath, pool_id);
		return -EINVAL;
	}

	if (unlikely(!pool->replay_tree_valid)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: invalid replay tree, remount", globals.jpath, pool_id);
		return -EINVAL;
	}

	if (likely(pool->replay_tree_cnt==0)) {
		rc = 0;
		goto end;
	}

	rc = __zjournal_replay_pool(pool);
	if (unlikely(rc!=0))
		goto end;

	rc = 0;

end:

	if (rc==0) {
		/*
		 * don't call this here, because commit was not done
		 * yet, and it may fail.
		 * zjournal_map_item_reset_pool(pool_id);
		 */
		pool->replayed = true;
	}

	pool->replay_tree_valid = false;

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: replay done, rc=%d", globals.jpath, pool_id, rc);

	return rc;
}

static int __zjournal_replay_pool(struct zjournal_pool *pool)
{
	struct timeval tv1, tv2;
	u64 *replay_addr_arr = NULL;
	void **replay_ctx_arr = NULL;
	int	replay_addr_cnt = 0;
	int rc;

	replay_addr_arr = vmalloc(pool->replay_tree_cnt*sizeof(u64));
	replay_ctx_arr = vmalloc(pool->replay_tree_cnt*sizeof(void*));
	if (unlikely(replay_addr_arr==NULL || replay_ctx_arr==NULL)) {
		rc = -ENOMEM;
		goto end;
	}

	TM_GET(&tv1);
	rc = __zjournal_replay_pool__get_chunks(pool, replay_addr_arr, replay_ctx_arr, &replay_addr_cnt);
	TM_GET(&tv2);
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: __zjournal_replay_pool__get_chunks() took %ld us, rc=%d", 
			  globals.jpath, pool->pool_id, TM_DELTA(&tv2, &tv1), rc);
	if (unlikely(rc!=0))
		goto end;

	TM_GET(&tv1);
	__zjournal_replay_pool__build_migration_list(pool, replay_addr_arr, replay_ctx_arr, replay_addr_cnt);
	TM_GET(&tv2);
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: __zjournal_replay_pool__build_migration_list() took %ld us", 
			  globals.jpath, pool->pool_id, TM_DELTA(&tv2, &tv1));

	{
		/* Validate replay_tree is empty */
		struct zjournal_replay_item *ritem = NULL;
		ritem = zjournal_pool_replay_tree_get_first(pool);
		BUG_ON(ritem!=NULL);
		BUG_ON(pool->replay_tree_cnt!=0);
	}

	TM_GET(&tv1);
	rc = __zjournal_replay_pool__replay_all(pool);
	TM_GET(&tv2);
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: __zjournal_replay_pool__replay_all() took %ld us, rc=%d", 
			  globals.jpath, pool->pool_id, TM_DELTA(&tv2, &tv1), rc);
	if (unlikely(rc!=0))
		goto end;

	rc = 0;

end:

	TM_GET(&tv1);
	zjournal_pool_free_replay_tree(pool);
	zjournal_pool_free_replay_list(pool);
	TM_GET(&tv2);
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: __zjournal_free_replay_*() took %ld us", 
			  globals.jpath, pool->pool_id, TM_DELTA(&tv2, &tv1));

	vfree(replay_addr_arr);
	vfree(replay_ctx_arr);

	return rc;
}

/** 
 *  @note __zjournal_replay_pool__get_chunks() must be single threaded - see comment at zjournal_get_unreplayed_addresses()
 */ 
static int __zjournal_replay_pool__get_chunks(struct zjournal_pool *pool, u64 *replay_addr_arr, void **replay_ctx_arr, int *replay_addr_cnt)
{
	struct zjournal_replay_item *ritem1, *ritem2;
	void *replay_ctx;
	u64 address;
	int i, rc;
	int reuse_cnt, migr_cnt;
	int replay_tree_cnt;

	rc = 0;
	reuse_cnt = 0;
	migr_cnt = 0;
	ritem1 = NULL;

	/* Store initial replay_tree_cnt, as pool->replay_tree_cnt is decreasing in the loop, when item is removed from the tree */
	replay_tree_cnt = pool->replay_tree_cnt;

	for (i=0; i<replay_tree_cnt; i++) {

		if(ritem1==NULL) {
			/* Look for any item in the tree */
			ritem1 = zjournal_pool_replay_tree_get_first(pool);
			BUG_ON(ritem1==NULL);	/* Why ritem1 is NULL, and i < replay_tree_cnt? */
		}

		/* Get chunk for replay based on ritem1 */
		if (likely(pool->fs_info!=NULL && ZBTRFS_IS_FULL_BLKVIRT_MOUNT(pool->fs_info))) {
			rc = zbtrfs_blk_virt_get_chunk_for_replay(pool->fs_info, ritem1->entry.subvol_treeid, &address, &replay_ctx);
			if (unlikely(rc!=0)) {
				zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: zbtrfs_blk_virt_get_chunk_for_replay(treeid=%llu) failed, rc=%d", 
						  globals.jpath, pool->pool_id, ritem1->entry.subvol_treeid, rc);
				break;
			}
			if (unlikely(replay_ctx==NULL)) {
				zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: zbtrfs_blk_virt_get_chunk_for_replay(treeid=%llu) failed, replay_ctx=NULL", 
						  globals.jpath, pool->pool_id, ritem1->entry.subvol_treeid);
				rc = -ECANCELED;
				break;
			}
		}
		else {
			/* unit test */
			address = ritem1->entry.address;
			replay_ctx = NULL;
		}

		zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: dst_address=%llu", globals.jpath, pool->pool_id, address);

		/* Check if address is in use */
		ritem2 = radix_tree_lookup(&pool->replay_tree, address);
		if (ritem2!=NULL) {
			/* Move ritem2 from the tree to the list */
			zjournal_pool_replay_tree_delete_item(pool, ritem2);
			ritem2->new_address = address;
			ritem2->replay_ctx = replay_ctx;
			list_add_tail(&ritem2->lnode, &pool->replay_list);
			if(ritem1==ritem2)
				ritem1 = NULL;
			reuse_cnt++;
		}
		else {
			/* New address, some item will be migrated to it */
			replay_addr_arr[*replay_addr_cnt] = address;
			replay_ctx_arr[*replay_addr_cnt] = replay_ctx;
			(*replay_addr_cnt)++;
			migr_cnt++;
		}
	} /* for (i=0; i<replay_tree_cnt; i++) */

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: migr_cnt=%d, reuse_cnt=%d, replay_tree_cnt=%d", 
			  globals.jpath, pool->pool_id, migr_cnt, reuse_cnt, pool->replay_tree_cnt);

	if(rc==0) {
		/* All item that left in the tree should be migrated */
		ZJOURNAL_ASSERT(pool->replay_tree_cnt==migr_cnt, "pool->replay_tree_cnt=%d, migr_cnt=%d", pool->replay_tree_cnt, migr_cnt);
	}
	else {
		struct zjournal_replay_item *ritem;

		zklog_tag(Z_KERR, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: releasing all allocated chunks", globals.jpath, pool->pool_id);

		list_for_each_entry(ritem, &pool->replay_list, lnode)
			zbtrfs_blk_virt_cancel_journal_replay_entry(pool->fs_info, ritem->replay_ctx);

		for (i = 0; i < *replay_addr_cnt; i++) {
			replay_ctx = replay_ctx_arr[*replay_addr_cnt];
			zbtrfs_blk_virt_cancel_journal_replay_entry(pool->fs_info, replay_ctx);
		}
	}

	return rc;
}

static void __zjournal_replay_pool__build_migration_list(struct zjournal_pool *pool, const u64 *replay_addr_arr, void **replay_ctx_arr, int replay_addr_cnt)
{
	struct zjournal_replay_item *ritem;
	int i;

	for (i=0; i<replay_addr_cnt; i++) {
		/* Look for next item in the tree to replay */
		ritem = zjournal_pool_replay_tree_get_first(pool);
		BUG_ON(ritem==NULL);			/* Why we have allocated address but no ritem? */

		/* Move ritem from the tree to the list */
		zjournal_pool_replay_tree_delete_item(pool, ritem);
		ritem->new_address = replay_addr_arr[i];
		ritem->replay_ctx = replay_ctx_arr[i];
		list_add_tail(&ritem->lnode, &pool->replay_list);
	}
}

static int __zjournal_replay_pool__replay_all(struct zjournal_pool *pool)
{
	struct zjournal_replay_item *ritem;
	struct removelock rl;
	atomic_t arc;
	int rc;
	u64 replay_time_reuse_ms = 0;
	u64 replay_time_migr_ms = 0;
	u64 update_time_migr_ms = 0;
	int migr_cnt = 0;
	int reuse_cnt = 0;
	bool migr;

	/* Start from 1 to ensure rl.cnt doesn't become 0 too early */
	removelock_init(&rl);
	removelock_acquire(&rl);
	atomic_set(&arc, 0);
	rc = 0;

	list_for_each_entry(ritem, &pool->replay_list, lnode) {
		zjournal_work_init(&ritem->jwork, __zjournal_replay_pool__replay_one, &rl, &arc, ritem);
		zjournal_work_enqueue(&ritem->jwork);
	}

	removelock_release(&rl);
	removelock_wait(&rl);

	if (likely(rc==0))
		rc = atomic_read(&arc);

	list_for_each_entry(ritem, &pool->replay_list, lnode) {
		migr = (ritem->entry.address != ritem->new_address);
		if(migr) {
			replay_time_migr_ms += ritem->replay_time_ms;
			update_time_migr_ms += ritem->update_time_ms;
			migr_cnt++;
		}
		else  {
			replay_time_reuse_ms += ritem->replay_time_ms;
			ZJOURNAL_ASSERT(ritem->update_time_ms==0, "ritem->update_time_ms=%lld", ritem->update_time_ms);
			reuse_cnt++;
		}
	}
	
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: zbtrfs_blk_virt_journal_replay_entry(reuse) took %lld us/entry, rc=%d, cnt=%d",
			  globals.jpath, pool->pool_id, reuse_cnt!=0 ? replay_time_reuse_ms/reuse_cnt : 0, rc, reuse_cnt);
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: zbtrfs_blk_virt_journal_replay_entry(migration) took %lld us/entry, cnt=%d",
			  globals.jpath, pool->pool_id, migr_cnt!=0 ? replay_time_migr_ms/migr_cnt : 0, migr_cnt);
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: submit_bio_sync(migration) took %lld us/entry, cnt=%d, ",
			  globals.jpath, pool->pool_id, migr_cnt!=0 ? update_time_migr_ms/migr_cnt : 0, migr_cnt);

	return rc;
}

static void __zjournal_replay_pool__replay_one(struct btrfs_work *work)
{
	struct zjournal_work *jwork = container_of(work, struct zjournal_work, bwork);
	struct zjournal_replay_item *ritem = (struct zjournal_replay_item*)jwork->arg;
	struct zjournal_pool *pool = ritem->pool;
	struct zjournal_disk_item disk_item;
	struct timeval tv1, tv2;
	sector_t bi_sector;
	int rc = -1;
	bool migr;

	zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: replay entry " FMT_REPLAY_ITEM ", new_address=%llu",
			  globals.jpath, pool->pool_id, ritem->item_idx, PRI_REPLAY_ITEM(ritem), ritem->new_address);

	migr = (ritem->entry.address != ritem->new_address);

	if (unlikely(pool->fs_info==NULL || !ZBTRFS_IS_FULL_BLKVIRT_MOUNT(pool->fs_info))) {
		/* unit test */
		BUG_ON(migr);
		rc = 0;
		goto end;
	}

	TM_GET(&tv1);
	rc = zbtrfs_blk_virt_journal_replay_entry(pool->fs_info, &ritem->entry, ritem->new_address, ritem->tenant_id, ritem->replay_ctx);
	TM_GET(&tv2);
	ritem->replay_time_ms = TM_DELTA(&tv2, &tv1);

	if (likely(rc==0)) {
		if (migr) {
			/* Data was copied from ritem->entry.address into ritem->new_address. Update the disk_item. */
			struct bio *bio;

			bio = zjournal_bio_map_kern(&disk_item, ZJOURNAL_DISK_ITEM_SIZE, GFP_NOFS, &rc);
			if (unlikely(rc!=0))
				goto end;
			
			zjournal_disk_item_init(&disk_item, pool->pool_id, ritem->generation, ritem->transid, ritem->io_cnt, ritem->tenant_id, 
									ritem->entry.subvol_treeid, ritem->entry.inode_num, ritem->entry.inode_gen, ritem->entry.file_offset, 
									ritem->new_address);
			
			TM_GET(&tv1);
			bi_sector = ZJOURNAL_SUPERBLOCK_SIZE_BLK + ritem->item_idx;
			rc = submit_bio_sync(WRITE, bio, bi_sector);
			TM_GET(&tv2);
			ritem->update_time_ms = TM_DELTA(&tv2, &tv1);

			bio_put(bio);
		}
		ritem->replay_ctx = NULL;
	}
	else {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: zbtrfs_blk_virt_journal_replay_entry("FMT_REPLAY_ITEM", new_address=%llu) failed, rc=%d",
				  globals.jpath, pool->pool_id, PRI_REPLAY_ITEM(ritem), ritem->new_address, rc);
		if (rc > 0) {
			zjournal_report_corruption(pool->pool_id, "invalid replay entry");
			rc = 0;
		}
	}

end:
	zjournal_work_set_rc(jwork, rc);
	zjournal_work_done(jwork);
	/* Do not call zjournal_work_free(jwork), as jwork is part of ritem! */
}

int zjournal_is_replayed(u16 pool_id, bool *replayed)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];

	*replayed = false;

	ZJOURNAL_CHECK_ARGS(pool_id, true);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);

	zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: replayed=%d", globals.jpath, pool_id, pool->replayed);

	if(pool->replayed)
		*replayed = true;
	else
		*replayed = false;

	return 0;
}

/** 
 * @note zjournal_get_unreplayed_addresses() can be called either from withing __zjournal_replay_pool__get_chunks or from 
 *  	 __zjournal_replay_pool__replay_all(). __zjournal_replay_pool__get_chunks() is single threaded, so no protection for replay_list and
 *  	 replay_tree is needed. __zjournal_replay_pool__replay_all() is multithreaded, but at that moment replay_tree is alredy empty and replay_list
 *  	 doesn't change.
 */ 
int zjournal_get_unreplayed_addresses(u16 pool_id, u64 start_addr, u64 num_addr, u64 *pmin_addr, u64 *pmax_addr)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];
	struct zjournal_replay_item *ritem;
	struct radix_tree_iter iter;
	void **slot;
	u64 min_addr, max_addr;

	min_addr = (u64)-1;
	max_addr = (u64)0;
	if (pmin_addr!=NULL)
		*pmin_addr = min_addr;
	if (pmax_addr!=NULL)
		*pmax_addr = max_addr;

	ZJOURNAL_CHECK_ARGS(pool_id, true);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);

	if (unlikely(!pool->mounted)) {
		zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: not mounted", globals.jpath, pool_id);
		return -EINVAL;
	}
	if (unlikely(pool->replayed)) {
		zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: already replayed", globals.jpath, pool_id);
		return -EEXIST;
	}

	/* Check replay_list */
	list_for_each_entry(ritem, &pool->replay_list, lnode) {
		if (ritem->replay_ctx==NULL)
			continue;	/* ritem was already replayed */
		if (ritem->entry.address < start_addr)
			continue;
		if (ritem->entry.address >= start_addr+num_addr)
			continue;
		if (ritem->entry.address < min_addr)
			min_addr = ritem->entry.address;
		if (ritem->entry.address > max_addr)
			max_addr = ritem->entry.address;
	}

	/* Check replay_tree */

	/* lockdep expects radix_tree_deref_slot() to be called under RCU */
	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &pool->replay_tree, &iter, 0/*start*/) {
		ritem = radix_tree_deref_slot(slot);
		if (unlikely(ritem==NULL))
			continue;
		if (radix_tree_exception(ritem)) {
			if (radix_tree_deref_retry(ritem)) {
				WARN(1, "zjournal_get_unreplayed_addresses: radix_tree_exception + retry");
				goto restart;
			}
			WARN(1, "zjournal_get_unreplayed_addresses: radix_tree_exception + no-retry");
			continue;
		}
		if (ritem->entry.address < start_addr)
			continue;
		if (ritem->entry.address >= start_addr+num_addr)
			continue;
		if (ritem->entry.address < min_addr)
			min_addr = ritem->entry.address;
		if (ritem->entry.address > max_addr)
			max_addr = ritem->entry.address;
	}
	rcu_read_unlock();

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: range [%llu..%llu), min_addr=%llu, max_addr=%llu", 
			  globals.jpath, pool_id, start_addr, start_addr+num_addr, min_addr, max_addr);

	if(pmin_addr!=NULL)
		*pmin_addr = min_addr;
	if(pmax_addr!=NULL)
		*pmax_addr = max_addr;

	return 0;
}
#endif /*CONFIG_BTRFS_ZADARA*/

