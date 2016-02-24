#ifdef CONFIG_BTRFS_ZADARA
#include "zjournal.h"
static int __zjournal_pool_sb_read_one(u16 pool_id, const struct zjournal_pool_superblock *sb);
static int __zjournal_pool_sb_update(struct zjournal_pool *pool, u64 generation, bool created);
static int __zjournal_pool_sb_update_version(struct zjournal_pool *pool, const struct zjournal_pool_superblock *sb, int old_version, bool *invalid);
static void __zjournal_pool_init(struct zjournal_pool *pool, u16 pool_id);

/****************************************************************/
/** CREATE/DELETE												*/
/****************************************************************/

int zjournal_create_pool(u16 pool_id)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];
	int rc;

	ZJOURNAL_CHECK_ARGS(pool_id, true);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: create", globals.jpath, pool_id);

	if (unlikely(pool->created)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: already created, max_transid=%llu", globals.jpath, pool_id, pool->max_transid);
		return -EEXIST;
	}

	/* Increment pool->generation and set 'created' */
	rc = __zjournal_pool_sb_update(pool, pool->generation+1, true/*created*/);
	if (unlikely(rc!=0))
		return rc;

	atomic64_set(&pool->io_cnt, 0);

	/* Just in case... */
	zjournal_map_item_reset_pool(pool_id);

	return 0;
}

int zjournal_delete_pool(u16 pool_id)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];
	int rc;

	ZJOURNAL_CHECK_ARGS(pool_id, true);
	ZJOURNAL_ASSERT(pool->pool_id == pool_id, "pool->pool_id=%d, pool_id=%d", pool->pool_id, pool_id);
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: delete", globals.jpath, pool_id);

	if (unlikely(!pool->created)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: not created, max_transid=%llu", globals.jpath, pool_id, pool->max_transid);
		return -ENOENT;
	}

	if (unlikely(pool->mounted)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: still mounted, max_transid=%llu", globals.jpath, pool_id, pool->max_transid);
		return -EBUSY;
	}

	/* Increment pool->generation, reset pool->created */
	rc = __zjournal_pool_sb_update(pool, pool->generation+1, false/*created*/);
	if (unlikely(rc!=0))
		return rc;

	zjournal_pool_reset(pool, false/*created*/);
	zjournal_map_item_reset_pool(pool_id);

	return 0;
}

/****************************************************************/
/** POOL SB														*/
/****************************************************************/

int zjournal_pool_sb_init_all(void)
{
	struct zjournal_pool *pool;
	u16 pool_id;
	int rc;

	for (pool_id = ZJOURNAL_MIN_POOL_ID; pool_id <= ZJOURNAL_MAX_POOL_ID; pool_id++) {

		pool = &globals.pools[pool_id];
		__zjournal_pool_init(pool, pool_id);

		rc = __zjournal_pool_sb_update(pool, 0/*generation*/, false/*created*/);
		if (unlikely(rc!=0))
			return rc;
	}

	return 0;
}

int zjournal_pool_sb_read_all(void)
{
	struct zjournal_pool_superblock *sb;
	struct bio *bio = NULL;
	sector_t bi_sector;
	int i, n_pools;
	int rc;
	u16 pool_id0;

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: read pool superblocks", globals.jpath);

	n_pools = ZJOURNAL_MAX_BUF_SIZE / ZJOURNAL_POOL_SUPERBLOCK_SIZE;
	sb = kmalloc(ZJOURNAL_POOL_SUPERBLOCK_SIZE*n_pools, GFP_NOFS);
	if (unlikely(sb==NULL))
		goto end;

	for (pool_id0=ZJOURNAL_MIN_POOL_ID; pool_id0 < ZJOURNAL_MAX_POOL_ID+1; pool_id0+=n_pools) {

		if (unlikely(pool_id0 + n_pools > ZJOURNAL_MAX_POOL_ID+1))
			n_pools = ZJOURNAL_MAX_POOL_ID+1 - pool_id0;

		bio = zjournal_bio_map_kern(sb, ZJOURNAL_POOL_SUPERBLOCK_SIZE*n_pools, GFP_NOFS, &rc);
		if (unlikely(rc!=0))
			goto end;

		bi_sector = ZJOURNAL_MAIN_SUPERBLOCK_SIZE_BLK + pool_id0;
		rc = submit_bio_sync(READ, bio, bi_sector);
		if (unlikely(rc!=0))
			goto end;

		for (i=0; i<n_pools; i++) {
			rc = __zjournal_pool_sb_read_one(pool_id0+i, &sb[i]);
			if (unlikely(rc!=0))
				goto end;
		}

		bio_put(bio);
		bio = NULL;
	}

end:

	if (bio!=NULL)
		bio_put(bio);
	kfree(sb);

	return rc;
}

static int __zjournal_pool_sb_read_one(u16 pool_id, const struct zjournal_pool_superblock *sb)
{
	struct zjournal_pool *pool = &globals.pools[pool_id];
	bool invalid = false;
	u32 crc = 0;
	int rc;
	
	zklog_tag(Z_KDEB2, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: read superblock", globals.jpath, pool_id);

	__zjournal_pool_init(pool, pool_id);

	if (likely(sb->magic == ZJOURNAL_POOL_SUPERBLOCK_MAGIC)) {
		if (unlikely(sb->version > ZJOURNAL_VERSION)) {
			invalid = true;
			goto cont;
		}

		if (likely(sb->version == ZJOURNAL_VERSION)) {
			crc = ZJOURNAL_CHECKSUM(sb);
			if (unlikely(sb->crc != crc)) {
				invalid = true;
				goto cont;
			}

			pool->created = sb->created;
			pool->generation = sb->generation;
		}
		else {
			rc = __zjournal_pool_sb_update_version(pool, sb, sb->version, &invalid);
			if (unlikely(rc!=0))
				return rc;
		}
	}
	else {
		/* Assume this is v1 */
		rc = __zjournal_pool_sb_update_version(pool, sb, 1/*version*/, &invalid);
		if (unlikely(rc!=0))
			return rc;
	}

cont:

	if (unlikely(invalid)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, 
				  "zjournal %s: pool[%d]: invalid pool superblock magic=%#x, version=%d, generation=%llu, flags=%#llx, crc=%d, expected crc=%d",
				  globals.jpath, pool_id, sb->magic, sb->version, sb->generation, sb->flags, sb->crc, crc);
		zjournal_report_corruption(pool_id, "invalid pool superblock");

		/* We do not know what is going on with this pool. To be on the safe side, let's mark it as "created". */
		rc = __zjournal_pool_sb_update(pool, 0/*generation*/, true/*created*/);
		if (unlikely(rc!=0))
			return rc;
	}

	zklog_tag(pool->created ? Z_KINFO : Z_KDEB2, ZKLOG_TAG_JOURNAL, 
			  "zjournal %s: pool[%d]: generation=%llu, %s", 
			  globals.jpath, pool_id, pool->generation, 
			  pool->created ? "created" : "not created");

	return 0;
}

static int __zjournal_pool_sb_update(struct zjournal_pool *pool, u64 generation, bool created)
{
	struct zjournal_pool_superblock sb;
	struct bio *bio = NULL;
	sector_t bi_sector;
	int rc;

	zklog_tag(generation==0 && !created ? Z_KDEB2 : Z_KINFO, ZKLOG_TAG_JOURNAL, 
			  "zjournal %s: pool[%d]: update generation=%llu, created=%d", 
			  globals.jpath, pool->pool_id, generation, created);

	memzero(&sb, ZJOURNAL_POOL_SUPERBLOCK_SIZE);

	sb.magic = ZJOURNAL_POOL_SUPERBLOCK_MAGIC;
	sb.version = ZJOURNAL_VERSION;
	sb.generation = generation;
	sb.created = created;
	sb.crc = ZJOURNAL_CHECKSUM(&sb);
	
	bio = zjournal_bio_map_kern(&sb, ZJOURNAL_POOL_SUPERBLOCK_SIZE, GFP_NOFS, &rc);
	if (unlikely(rc!=0))
		return rc;

	bi_sector = ZJOURNAL_MAIN_SUPERBLOCK_SIZE_BLK + pool->pool_id;
	rc = submit_bio_sync(WRITE, bio, bi_sector);
	bio_put(bio);
	if (unlikely(rc!=0))
		return rc;

	pool->generation = generation;
	pool->created = created;

	return 0;
}

static int __zjournal_pool_sb_update_version(struct zjournal_pool *pool, const struct zjournal_pool_superblock *sb, int old_version, bool *invalid)
{
	u64 generation;
	bool created;
	u32 crc;
	int rc;

	switch(old_version) {

	case 1:
		{
			const struct zjournal_pool_superblock_v1 *sb_v1 = (const struct zjournal_pool_superblock_v1 *)sb;
			crc = ZJOURNAL_CHECKSUM(sb_v1);
			if (unlikely(sb_v1->crc != crc)) {
				*invalid = true;
				return 0;
			}
			generation = sb_v1->generation;
			created = sb_v1->flags&0x1;
		}
		break;

	case 2:
		{
			crc = ZJOURNAL_CHECKSUM(sb);
			if (unlikely(sb->crc != crc)) {
				*invalid = true;
				return 0;
			}
			generation = sb->generation;
			created = sb->created;
		}
		break;

	default:
		ZBTRFS_WARN(false, "zjournal %s: pool[%d]: invalid version %d", globals.jpath, pool->pool_id, old_version);
		*invalid = true;
		return -EINVAL;
	}

	*invalid = false;

	zklog_tag(created ? Z_KINFO : Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: update version %d -> %d",
			  globals.jpath, pool->pool_id, old_version, ZJOURNAL_VERSION);
	rc = __zjournal_pool_sb_update(pool, generation, created);
	return rc;
}

static void __zjournal_pool_init(struct zjournal_pool *pool, u16 pool_id)
{
	memzero(pool, sizeof(*pool));
	pool->pool_id = pool_id;
	INIT_LIST_HEAD(&pool->replay_list);
	INIT_RADIX_TREE(&pool->replay_tree, GFP_NOFS);
}
#endif /*CONFIG_BTRFS_ZADARA*/

