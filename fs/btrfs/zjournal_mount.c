#ifdef CONFIG_BTRFS_ZADARA
#include "zjournal.h"
static int __zjournal_build_replay_tree(struct zjournal_pool *pool, u64 last_commited_transid);
static struct zjournal_replay_item* __zjournal_vaddr_tree_insert_item(struct rb_root *vaddr_tree, struct zjournal_replay_item *ritem, const struct zjournal_pool *pool);
static void __zjournal_vaddr_tree_delete_item(struct rb_root *vaddr_tree, struct zjournal_replay_item *ritem);
static int __zjournal_vaddr_replay_item_cmp(struct zjournal_replay_item *ritem1, struct zjournal_replay_item *ritem2);
static void __zjournal_vaddr_tree_clean(struct zjournal_pool *pool);

int zjournal_mount(u16 pool_id, u64 last_commited_transid, struct btrfs_fs_info *fs_info)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];
	struct timeval tv1, tv2;
	int rc;
	
	ZJOURNAL_CHECK_ARGS(pool_id, true);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: mount(last_commited_transid=%llu)", globals.jpath, pool_id, last_commited_transid);

	if (unlikely(!pool->created)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: not created", globals.jpath, pool_id);
		return -ENOENT;
	}

	if (unlikely(pool->mounted)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: already mounted, max_transid=%llu", globals.jpath, pool_id, pool->max_transid);
		return -EBUSY;
	}

	BUG_ON(pool->replayed);

	if (unlikely(last_commited_transid==0)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: invalid transid %llu", globals.jpath, pool_id, last_commited_transid);
		return -EINVAL;
	}

	pool->fs_info = fs_info;

	TM_GET(&tv1);
	rc = __zjournal_build_replay_tree(pool, last_commited_transid);
	TM_GET(&tv2);
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: __zjournal_build_replay_tree() took %ld us, rc=%d, replay_tree_cnt=%d, last_commited_transid=%llu", 
			  globals.jpath, pool_id, TM_DELTA(&tv2, &tv1), rc, pool->replay_tree_cnt, last_commited_transid);
	if (unlikely(rc!=0))
		return rc;

	pool->mounted = true;

	return 0;
}

int zjournal_umount(u16 pool_id)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];

	ZJOURNAL_CHECK_ARGS(pool_id, false);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: umount", globals.jpath, pool_id);

	if (unlikely(!pool->mounted)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: not mounted", globals.jpath, pool_id);
	}

	/* Notice that we can get zjournal_umount() even for not-created pool! */
	zjournal_pool_reset(pool, pool->created);

	return 0;
}

static int __zjournal_build_replay_tree(struct zjournal_pool *pool, u64 last_commited_transid)
{
	struct rb_root vaddr_tree = RB_ROOT;
	struct zjournal_disk_item disk_item;
	struct zjournal_replay_item *ritem = NULL;
	struct zjournal_item *item = NULL;
	struct zjournal_replay_item *ritem2 = NULL;
	int rc = 0, item_idx;
	sector_t bi_sector;
	bool in_use;

	for (item_idx=0; item_idx<globals.jmap_size; item_idx++) {
		struct bio *bio = NULL;

		item = &globals.jmap[item_idx];
		if (item->pool_id!=pool->pool_id)
			continue;

		if (item->transid <= last_commited_transid) {
			zklog_tag(Z_KDEB2, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: transid=%llu - already commited", 
					  globals.jpath, pool->pool_id, item_idx, item->transid);
			zjournal_map_item_reset(item_idx);
			continue;
		}

		bio = zjournal_bio_map_kern(&disk_item, ZJOURNAL_DISK_ITEM_SIZE, GFP_NOFS, &rc);
		if (unlikely(rc!=0))
			goto end;

		/* Read disk item */
		bi_sector = ZJOURNAL_SUPERBLOCK_SIZE_BLK + item_idx;
		rc = submit_bio_sync(READ, bio, bi_sector);
		bio_put(bio);
		if (unlikely(rc!=0))
			goto end;

		rc = zjournal_disk_item_version_convert(item_idx, &disk_item);
		if (unlikely(rc!=0))
			goto end;

		/* item and disk_item data must match */
		ZJOURNAL_ASSERT(item->pool_id==disk_item.pool_id, "item_idx=%d, item->pool_id=%d, disk_item.pool_id=%d", item_idx, item->pool_id, disk_item.pool_id);
		ZJOURNAL_ASSERT(item->transid==disk_item.transid, "item_idx=%d, item->transid=%llu, disk_item.transid=%llu", item_idx, item->transid, disk_item.transid);

		in_use = zjournal_disk_item_in_use(item_idx, &disk_item);
		if(!in_use) {
			/* Item can be not-in-use if for example pool was deleted and then another pool was createdwith the same pool_id.
			   In this case item will not be in use because of generation */
			zjournal_map_item_reset(item_idx);
			continue;
		}
		ZJOURNAL_ASSERT(in_use, FMT_DISK_ITEM, PRI_DISK_ITEM(&disk_item));	/* Otherwise why item is in the map? */
		
		ritem = kzalloc(sizeof(struct zjournal_replay_item), GFP_NOFS);
		if (unlikely(ritem==NULL)) {
		   rc = -ENOMEM;
		   goto end;
		}

		ritem->item_idx = item_idx;
		ritem->generation = disk_item.generation;
		ritem->transid = disk_item.transid;
		ritem->io_cnt = disk_item.io_cnt;
		ritem->tenant_id = disk_item.tenant_id;
		ritem->entry = disk_item.entry;
		ritem->pool = pool;

		/* Try to insert ritem into vaddr_tree */
		ritem2 = __zjournal_vaddr_tree_insert_item(&vaddr_tree, ritem, pool);
		if(ritem2 == ritem) {
			/* ritem was not inserted into vaddr_tree. There is another newer item with same virtual address, that is already in the vaddr_tree. Delete ritem. */
			zjournal_map_item_reset(item_idx);
			kfree(ritem);
			continue;
		}
		else if (ritem2!=NULL) {
			/* ritem replaced in the vaddr_tree ritem2, that had the same virtual address, but is older. Remove ritem2 also from pool->replay_tree and delete. */
			zjournal_pool_replay_tree_delete_item(pool, ritem2);
			zjournal_map_item_reset(ritem2->item_idx);
			kfree(ritem2);
		}
		else {
			/* ritem was inserted into the vaddr_tree. There is no other item with the same virtual address */
		}

		/* Try to insert ritem info pool->replay_tree */
		rc = zjournal_pool_replay_tree_insert_item(pool, ritem);
		if (unlikely(rc!=0)) {
			__zjournal_vaddr_tree_delete_item(&vaddr_tree, ritem);

			if (rc!=-EEXIST) {
				kfree(ritem);
				goto end;
			}

			ritem2 = radix_tree_lookup(&pool->replay_tree, disk_item.entry.address);
			ZJOURNAL_ASSERT(ritem2!=NULL, "address=%llu", disk_item.entry.address);	/* why we got EEXIST, if physical address is not in a tree? */
			zklog_tag(Z_KERR, ZKLOG_TAG_JOURNAL, 
					  "zjournal %s: pool[%d]: duplicate paddr: new item[%d]: "FMT_REPLAY_ITEM", existing item[%d]: "FMT_REPLAY_ITEM,
					  globals.jpath, pool->pool_id, ritem->item_idx, PRI_REPLAY_ITEM(ritem), ritem2->item_idx, PRI_REPLAY_ITEM(ritem2));

			kfree(ritem);
			zjournal_map_item_reset(item_idx);
			zjournal_report_corruption(pool->pool_id, "duplicate physical address");

			rc = 0;
			continue;
		}
	}

end:
	__zjournal_vaddr_tree_clean(pool);

	if (rc==0)
		pool->replay_tree_valid = true;
	else
		zjournal_pool_free_replay_tree(pool);

	return rc;
}

/** 
 * @return NULL			if ritem has new virtual address that is not in the tree. ritem is inserted in the tree.
 * @return ritem		if ritem has virtual address that is already in the tree, and item in the tree is more updated. ritem is not inserted in the
 *  	   tree.
 * @return curr!=ritem	if ritem has virtual address that is already in the tree, and ritem is more updated. ritem replaces curr in the tree.
 */ 
static struct zjournal_replay_item* __zjournal_vaddr_tree_insert_item(struct rb_root *vaddr_tree, struct zjournal_replay_item *ritem, const struct zjournal_pool *pool)
{
	struct rb_node *parent_node = NULL;
	struct rb_node **plink = &vaddr_tree->rb_node;
	struct zjournal_replay_item *curr = NULL;
	int cmp;

  	/* Figure out where to put new node */
  	while (*plink != NULL) {
  		curr = container_of(*plink, struct zjournal_replay_item, rbnode);
  		cmp = __zjournal_vaddr_replay_item_cmp(ritem, curr);

		parent_node = *plink;
  		if (cmp < 0)
  			plink = &(*plink)->rb_left;
  		else if (cmp > 0)
  			plink = &(*plink)->rb_right;
  		else
  			break;
  	}

	if (*plink!=NULL) {
		/* Both *curr and *ritem have the same virtual address. Leave item with higher entry.io_cnt */
		zklog_tag(ritem->io_cnt == curr->io_cnt ? Z_KERR : Z_KINFO/*Z_KDEB1*/, ZKLOG_TAG_JOURNAL, 
				  "zjournal %s: pool[%d]: duplicate vaddr: new item[%d]: "FMT_REPLAY_ITEM", existing item[%d]: "FMT_REPLAY_ITEM,
				  globals.jpath, pool->pool_id, ritem->item_idx, PRI_REPLAY_ITEM(ritem), curr->item_idx, PRI_REPLAY_ITEM(curr));
		if (unlikely(ritem->io_cnt == curr->io_cnt)) {
			zjournal_report_corruption(pool->pool_id, "duplicate virtual address");
			return ritem;
		}

		if (ritem->io_cnt < curr->io_cnt) {
			return ritem;
		}
		else {
			/* Replace curr by ritem */
			rb_replace_node(&curr->rbnode, &ritem->rbnode, vaddr_tree);
			return curr;
		}
	}

  	/* Add new node and rebalance tree. */
  	rb_link_node(&ritem->rbnode, parent_node, plink);
  	rb_insert_color(&ritem->rbnode, vaddr_tree);

	return NULL;
}

static void __zjournal_vaddr_tree_delete_item(struct rb_root *vaddr_tree, struct zjournal_replay_item *ritem)
{
	rb_erase(&ritem->rbnode, vaddr_tree);
}

static int __zjournal_vaddr_replay_item_cmp(struct zjournal_replay_item *ritem1, struct zjournal_replay_item *ritem2)
{
	if (ritem1->entry.subvol_treeid < ritem2->entry.subvol_treeid)
		return -1;
	if (ritem1->entry.subvol_treeid > ritem2->entry.subvol_treeid)
		return +1;

	if (ritem1->entry.inode_num < ritem2->entry.inode_num)
		return -1;
	if (ritem1->entry.inode_num > ritem2->entry.inode_num)
		return +1;

	if (ritem1->entry.inode_gen < ritem2->entry.inode_gen)
		return -1;
	if (ritem1->entry.inode_gen > ritem2->entry.inode_gen)
		return +1;

	if (ritem1->entry.file_offset < ritem2->entry.file_offset)
		return -1;
	if (ritem1->entry.file_offset > ritem2->entry.file_offset)
		return +1;

	return 0;
}

static void __zjournal_vaddr_tree_clean(struct zjournal_pool *pool)
{
	struct zjournal_replay_item *ritem = NULL;
	struct radix_tree_iter iter;
	void **slot;

	/* lockdep expects radix_tree_deref_slot() to be called under RCU */
	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &pool->replay_tree, &iter, 0/*start*/) {
		ritem = radix_tree_deref_slot(slot);
		if (unlikely(ritem == NULL))
			continue;
		if (radix_tree_exception(ritem)) {
			if (radix_tree_deref_retry(ritem)) {
				WARN(1, "__zjournal_vaddr_tree_clean: radix_tree_exception + retry");
				goto restart;
			}
			WARN(1, "__zjournal_vaddr_tree_clean: radix_tree_exception + no-retry");
			continue;
		}

		memzero(&ritem->rbnode, sizeof(ritem->rbnode));
	}
	rcu_read_unlock();
}
#endif /*CONFIG_BTRFS_ZADARA*/

