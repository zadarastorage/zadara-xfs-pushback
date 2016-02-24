#ifdef CONFIG_BTRFS_ZADARA
#include "zjournal.h"

static int __zjournal_open(const u8 vpsaid[BTRFS_UUID_SIZE], bool wipe_out, bool sb_init);
static int __zjournal_sb_init(const u8 vpsaid[BTRFS_UUID_SIZE], struct zjournal_main_superblock *sb);
static int __zjournal_sb_read(const u8 vpsaid[BTRFS_UUID_SIZE], struct zjournal_main_superblock *sb);
static int __zjournal_sb_update_version(struct zjournal_main_superblock *sb);

static int __zjournal_read_map(void);
static void __zjournal_read_map_bulk(struct btrfs_work *work);

int zjournal_open(const char *zjournal_path, const u8 vpsaid[BTRFS_UUID_SIZE], bool wipe_out, bool sb_init)
{
	int rc;

	BUILD_BUG_ON(sizeof(struct zjournal_main_superblock) != ZJOURNAL_MAIN_SUPERBLOCK_SIZE);
	BUILD_BUG_ON(sizeof(struct zjournal_pool_superblock) != ZJOURNAL_POOL_SUPERBLOCK_SIZE);
	BUILD_BUG_ON(sizeof(struct zjournal_disk_item) != ZJOURNAL_DISK_ITEM_SIZE);
	BUILD_BUG_ON(ZJOURNAL_MAIN_SUPERBLOCK_SIZE + (ZJOURNAL_MAX_POOL_ID+1) * ZJOURNAL_POOL_SUPERBLOCK_SIZE > ZJOURNAL_SUPERBLOCK_SIZE);

	if (unlikely(globals.jdev!=NULL)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: already set as %s", zjournal_path, globals.jpath);
		if(strcmp(zjournal_path, globals.jpath) == 0)
			return -EEXIST;
		else
			return -ENOTUNIQ;
	}

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: open: wipe_out=%d, sb_init=%d", zjournal_path, wipe_out, sb_init);
	
	globals.jdev = blkdev_get_by_path(zjournal_path, FMODE_READ|FMODE_WRITE|FMODE_EXCL, &globals/*holder*/);
	if (unlikely(IS_ERR(globals.jdev))) {
		rc = PTR_ERR(globals.jdev);
		globals.jdev = NULL;
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: blkdev_get_by_path() failed, rc=%d", zjournal_path, rc);
		goto end;
	}
	snprintf(globals.jpath, sizeof(globals.jpath), "%s", zjournal_path);

	globals.jdev_size_blk = BYTES_TO_BLK(i_size_read(globals.jdev->bd_inode));
	globals.jmap_size = globals.jdev_size_blk - ZJOURNAL_SUPERBLOCK_SIZE_BLK;
	if (unlikely(globals.jmap_size<=0)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: too small: jdev_size_blk=%d, jmap_size=%d", zjournal_path, globals.jdev_size_blk, globals.jmap_size);
		rc = -EINVAL;
		goto end;
	}

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: allocate %d items", zjournal_path, globals.jmap_size);
	globals.jmap = vzalloc(globals.jmap_size * sizeof(struct zjournal_item));
	if (unlikely(globals.jmap==NULL)) {
		rc = -ENOMEM;
		goto end;
	}

	/* we ensure that NO_THRESHOLD will be set, so max_active will not change */
	globals.workers = btrfs_alloc_workqueue("zjrnl", WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_SYSFS, 16/*max_active*/, 1/*thresh*/);
	if (globals.workers == NULL) {
		rc = -ENOMEM;
		goto end;
	}

	rc = __zjournal_open(vpsaid, wipe_out, sb_init);
	if (unlikely(rc!=0))
		goto end;

	atomic_set(&globals.jmap_idx, 0);

end:

	if (unlikely(rc!=0)) {
		zjournal_close(true/*force*/);
	}

	return rc;
}

int zjournal_close(bool force)
{
	struct zjournal_pool *pool;
	u16 pool_id;
	int rc = 0;

	for (pool_id=ZJOURNAL_MIN_POOL_ID; pool_id<=ZJOURNAL_MAX_POOL_ID; pool_id++) {
		pool = &globals.pools[pool_id];
		if (unlikely(pool->mounted)) {
			zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: still mounted. %s", globals.jpath, pool_id, force ? "Force close." : "");
			if (!force) {
				rc = -EBUSY;
				continue;
			}
		}
		zjournal_pool_reset(pool, pool->created);
	}

	if (rc!=0)
		return rc;

	if(globals.workers) {
		btrfs_destroy_workqueue(globals.workers);
		globals.workers = NULL;
	}

	if (globals.jdev!=NULL) {
		zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: close", globals.jpath);
		memzero(globals.jpath, sizeof(globals.jpath));
		blkdev_put(globals.jdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
		globals.jdev = NULL;
		globals.jdev_size_blk = 0;
		globals.jmap_size = 0;
	}

	if (globals.jmap!=NULL) {
		vfree(globals.jmap);
		globals.jmap = NULL;
		atomic_set(&globals.jmap_idx, 0);
	}

	return rc;
}

static int __zjournal_open(const u8 vpsaid[BTRFS_UUID_SIZE], bool wipe_out, bool sb_init)
{
	struct zjournal_main_superblock *sb = NULL;
	struct timeval tv1, tv2;
	int rc;

	sb = kmalloc(ZJOURNAL_MAIN_SUPERBLOCK_SIZE, GFP_NOFS);
	if (unlikely(sb==NULL)) {
		rc = -ENOMEM;
		goto end;
	}

	if (unlikely(wipe_out)) {
		/* Zero the entire device */
		zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: wipe-out...", globals.jpath);
		rc = zjournal_issue_zeroout(0, globals.jdev_size_blk, GFP_NOFS);
		if (unlikely(rc!=0))
			goto end;
	}

	if (unlikely(sb_init))
		rc = __zjournal_sb_init(vpsaid, sb);
	else 
		rc = __zjournal_sb_read(vpsaid, sb);
	if (unlikely(rc!=0))
		goto end;

	TM_GET(&tv1);
	if (unlikely(sb_init))
		rc = zjournal_pool_sb_init_all();
	else
		rc = zjournal_pool_sb_read_all();
	TM_GET(&tv2);
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: %s() took %ld us, rc=%d", 
			  globals.jpath, sb_init ? "zjournal_pool_sb_init_all" : "zjournal_pool_sb_read_all", TM_DELTA(&tv2, &tv1), rc);
	if (unlikely(rc!=0))
		goto end;

	TM_GET(&tv1);
	rc = __zjournal_read_map();
	TM_GET(&tv2);
	zklog_tag(rc==0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: __zjournal_read_map() took %ld us, rc=%d", 
			  globals.jpath, TM_DELTA(&tv2, &tv1), rc);
	if (unlikely(rc!=0))
		goto end;

	rc = 0;

end:

	kfree(sb);

	return rc;
}

/****************************************************************/
/** MAIN SB														*/
/****************************************************************/

static int __zjournal_sb_init(const u8 vpsaid[BTRFS_UUID_SIZE], struct zjournal_main_superblock *sb)
{
	struct bio *bio = NULL;
	int rc;

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: vpsaid="PRIx128", ver=%d", globals.jpath, PRI_UUID(vpsaid), ZJOURNAL_VERSION);

	bio = zjournal_bio_map_kern(sb, ZJOURNAL_MAIN_SUPERBLOCK_SIZE, GFP_NOFS, &rc);
	if (unlikely(rc!=0))
		goto end;

	/* Init main superblock */
	memzero(sb, ZJOURNAL_MAIN_SUPERBLOCK_SIZE);
	sb->magic = ZJOURNAL_MAIN_SUPERBLOCK_MAGIC;
	sb->version = ZJOURNAL_VERSION;
	memcpy(sb->vpsaid, vpsaid, BTRFS_UUID_SIZE);

	/* Write main superblock */
	rc = submit_bio_sync(WRITE, bio, 0/*bi_sector*/);
	if (unlikely(rc!=0))
		goto end;

	memzero(globals.jmap, globals.jmap_size * sizeof(struct zjournal_item));
	rc = 0;

end:
	if (bio!=NULL)
		bio_put(bio);

	return rc;
}

static int __zjournal_sb_read(const u8 vpsaid[BTRFS_UUID_SIZE], struct zjournal_main_superblock *sb)
{
	struct bio *bio = NULL;
	int rc;

	bio = zjournal_bio_map_kern(sb, ZJOURNAL_MAIN_SUPERBLOCK_SIZE, GFP_NOFS, &rc);
	if (unlikely(rc!=0))
		goto end;

	rc = submit_bio_sync(READ, bio, 0/*bi_sector*/);
	if (unlikely(rc!=0))
		goto end;

	if (unlikely(sb->magic != ZJOURNAL_MAIN_SUPERBLOCK_MAGIC)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: invalid magic %#x, expected %#x", globals.jpath, sb->magic, ZJOURNAL_MAIN_SUPERBLOCK_MAGIC);
		rc = -ECANCELED;
		goto end;
	}

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: vpsaid="PRIx128", ver=%d", globals.jpath, PRI_UUID(vpsaid), sb->version);

	if (unlikely(sb->version > ZJOURNAL_VERSION)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: invalid version %d > %d", globals.jpath, sb->version, ZJOURNAL_VERSION);
		rc = -ECANCELED;
		goto end;
	}
	if (unlikely(sb->version < ZJOURNAL_VERSION)) {
		rc = __zjournal_sb_update_version(sb);
		if (unlikely(rc!=0))
			goto end;
	}

	if (unlikely(memcmp(sb->vpsaid, vpsaid, BTRFS_UUID_SIZE)!=0)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: invalid vpsaid ["PRIx128"], expected ["PRIx128"]", 
				  globals.jpath, PRI_UUID(sb->vpsaid), PRI_UUID(vpsaid));
		rc = -ECANCELED;
		goto end;
	}

	rc = 0;

end:

	if (bio!=NULL)
		bio_put(bio);

	return rc;
}

static int __zjournal_sb_update_version(struct zjournal_main_superblock *sb)
{
	struct bio *bio = NULL;
	int rc;

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: vpsaid="PRIx128", update version %d -> %d", globals.jpath, PRI_UUID(sb->vpsaid), sb->version, ZJOURNAL_VERSION);

	bio = zjournal_bio_map_kern(sb, ZJOURNAL_MAIN_SUPERBLOCK_SIZE, GFP_NOFS, &rc);
	if (unlikely(rc!=0))
		goto end;

	sb->version = ZJOURNAL_VERSION;

	rc = submit_bio_sync(WRITE, bio, 0/*bi_sector*/);
	if (unlikely(rc!=0))
		goto end;

	rc = 0;

end:
	if (bio!=NULL)
		bio_put(bio);

	return rc;
}

/****************************************************************/
/** MAP															*/
/****************************************************************/

static int __zjournal_read_map(void)
{
	int item_idx0, rc;
	struct zjournal_work *jwork;
	struct removelock rl;
	atomic_t arc;

	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: read map", globals.jpath);

	/* Start from 1 to ensure rl.cnt doesn't become 0 too early */
	removelock_init(&rl);
	removelock_acquire(&rl);
	atomic_set(&arc, 0);
	rc = 0;

	for (item_idx0=0; item_idx0<globals.jmap_size; item_idx0+=ZJOURNAL_MAX_BUF_SIZE/ZJOURNAL_DISK_ITEM_SIZE) {
		jwork = zjournal_work_alloc(__zjournal_read_map_bulk, &rl, &arc, (void*)(long)item_idx0);
		if (unlikely(jwork==NULL)) {
			rc = -ENOMEM;
			break;
		}
		zjournal_work_enqueue(jwork);
	}

	removelock_release(&rl);
	removelock_wait(&rl);

	if (likely(rc==0))
		rc = atomic_read(&arc);

	return rc;
}

static void __zjournal_read_map_bulk(struct btrfs_work *work)
{
	struct zjournal_work *jwork = container_of(work, struct zjournal_work, bwork);
	int item_idx0 = (int)(long)jwork->arg;
	struct zjournal_disk_item *disk_item = NULL;
	struct bio *bio = NULL;
	sector_t bi_sector;
	int item_idx, n_items, rc;

	n_items = ZJOURNAL_MAX_BUF_SIZE/ZJOURNAL_DISK_ITEM_SIZE;
	if (unlikely(item_idx0 + n_items > globals.jmap_size))
		n_items = globals.jmap_size - item_idx0;

	disk_item = kmalloc(ZJOURNAL_DISK_ITEM_SIZE * n_items, GFP_NOFS);
	if (unlikely(disk_item==NULL)) {
		rc = -ENOMEM;
		goto end;
	}

	bio = zjournal_bio_map_kern(disk_item, ZJOURNAL_DISK_ITEM_SIZE * n_items, GFP_NOFS, &rc);
	if (unlikely(rc!=0))
		goto end;

	bi_sector = ZJOURNAL_SUPERBLOCK_SIZE_BLK + item_idx0;
	rc = submit_bio_sync(READ, bio, bi_sector);
	if (unlikely(rc!=0))
		goto end;

	for (item_idx=item_idx0; item_idx<item_idx0+n_items; item_idx++) {
		rc = zjournal_disk_item_version_convert(item_idx, &disk_item[item_idx-item_idx0]);
		if (likely(rc == 0)) {
			if (zjournal_disk_item_in_use(item_idx, &disk_item[item_idx-item_idx0]))
				zjournal_map_item_set(item_idx, &disk_item[item_idx-item_idx0]);
			else
				zjournal_map_item_reset(item_idx);
		}
	}

end:

	if(bio!=NULL)
		bio_put(bio);
	kfree(disk_item);

	zjournal_work_set_rc(jwork, rc);
	zjournal_work_done(jwork);
	zjournal_work_free(jwork);
}
#endif /*CONFIG_BTRFS_ZADARA*/

