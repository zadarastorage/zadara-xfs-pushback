#ifdef CONFIG_BTRFS_ZADARA
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "zjournal.h"
#include "zbtrfs.h"
#include "zbtrfs-block-virt.h"

struct zjournal_globals globals;

zklog_tag_t ZKLOG_TAG_JOURNAL = 0;

/****************************************************************/
/** INIT / EXIT													*/
/****************************************************************/

int zjournal_init(void)
{
	int rc;
	u16 pool_id;

	zklog(Z_KINFO, "Init zjournal");

	rc = zklog_add_tag("jrn", "Journal", Z_KINFO, &ZKLOG_TAG_JOURNAL);
	if (rc != 0) {
		zklog(Z_KERR, "zklog_add_tag('zj') failed, ret=%d", rc);
		return rc;
	}

	memzero(&globals, sizeof(globals));
	for (pool_id=ZJOURNAL_MIN_POOL_ID; pool_id<=ZJOURNAL_MAX_POOL_ID; pool_id++) {
		struct zjournal_pool *pool = &globals.pools[pool_id];
		INIT_LIST_HEAD(&pool->replay_list);
	}
	
	globals.enable = true;

	return 0;
}

void zjournal_exit(void)
{
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "Exit zjournal");

	zjournal_close(true/*force*/);
}

/****************************************************************/
/** SHOW														*/
/****************************************************************/
static int zjournal_show_pools(char *buf, size_t len);

int zjournal_show_globals(char *buf, size_t len)
{
	ssize_t size = 0;
	u32 jmap_idx = atomic_read(&globals.jmap_idx);
	
	size += scnprintf(buf+size, len-size, "ZJOURNAL_VERSION: %d\n", ZJOURNAL_VERSION);	
	size += scnprintf(buf+size, len-size, "zjournal_enable: %d\n", globals.enable);
	size += scnprintf(buf+size, len-size, "zjournal_path: %s\n", globals.jpath);
	size += scnprintf(buf+size, len-size, "zjournal_idx: %d(%d)\n", jmap_idx, globals.jmap_size!=0 ? jmap_idx%globals.jmap_size : -1);
	size += scnprintf(buf+size, len-size, "zjournal_map_size: %d\n", globals.jmap_size);
	size += scnprintf(buf+size, len-size, "zjournal_dev_size_blk: %d\n", globals.jdev_size_blk);
	size += zjournal_show_pools(buf+size, len-size);

	return size;
}

static int zjournal_show_pools(char *buf, size_t len)
{
	const struct zjournal_pool *pool;
	ssize_t size = 0;
	u16 pool_id;

	for (pool_id=ZJOURNAL_MIN_POOL_ID; pool_id<=ZJOURNAL_MAX_POOL_ID && size<len; pool_id++) {
		pool = &globals.pools[pool_id];
		if (!pool->created)
			continue;
		size += scnprintf(buf+size, len-size, 
						  "pool[%d]: generation=%llu, max_transid=%llu, io_cnt=%lu, created=%u, mounted=%u, replayed=%u, replay_tree_valid=%u, replay_tree_cnt=%d\n", 
						  pool->pool_id, pool->generation, pool->max_transid, atomic64_read(&pool->io_cnt), 
						  pool->created?1:0, pool->mounted?1:0, pool->replayed?1:0, pool->replay_tree_valid?1:0, 
						  pool->replay_tree_cnt);
	}

	return size;
}

/****************************************************************/
/** DUMP														*/
/****************************************************************/

int zjournal_dump_map(struct file *fd)
{
	char line[256] = "";
	struct zjournal_item *item;
	mm_segment_t old_fs;
	loff_t off;
	int rc, i, len;

	rc = 0;
	off = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	for (i=0; i<globals.jmap_size; i++) {
		item = &globals.jmap[i];
		len = scnprintf(line, sizeof(line), "%d,%d,%llu\n", i, item->pool_id, item->transid);
		rc = vfs_write(fd, line, len, &off);
		if (unlikely(rc!=len)) {
			zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "vfs_write(%s,'%s') failed, rc=%d", fd->f_dentry->d_name.name, line, rc);
			if(rc>=0)
				rc = -EIO;
			break;
		}
		else {
			rc = 0;
		}
	}

	set_fs(old_fs);

	return rc;
}

/****************************************************************/
/** 															*/
/****************************************************************/

void zjournal_enable(bool enable)
{
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: %s", globals.jpath, enable ? "ENABLE" : "DISABLE");
	globals.enable = enable;
}

/****************************************************************/
/** 															*/
/****************************************************************/

bool zjournal_map_item_try_lock(int item_idx)
{
	struct zjournal_item *item = &globals.jmap[item_idx];
	if(atomic_cmpxchg(&item->lock, 0, 1) == 0)
		return true;
	else
		return false;
}

void zjournal_map_item_unlock(int item_idx)
{
	struct zjournal_item *item = &globals.jmap[item_idx];
	atomic_set(&item->lock, 0);
}

void zjournal_map_item_set(int item_idx, const struct zjournal_disk_item *disk_item)
{
	struct zjournal_item *item = &globals.jmap[item_idx];
	BUG_ON(disk_item->pool_id==0);
	item->pool_id = disk_item->pool_id;
	item->transid = disk_item->transid;
}

void zjournal_map_item_reset(int item_idx)
{
	struct zjournal_item *item = &globals.jmap[item_idx];
	item->pool_id = 0;
}

void zjournal_map_item_reset_pool(u16 pool_id)
{
	int item_idx;
	for (item_idx=0; item_idx<globals.jmap_size; item_idx++) {
		struct zjournal_item *item = &globals.jmap[item_idx];
		if(item->pool_id!=pool_id)
			continue;
		item->pool_id = 0;
	}
}

/****************************************************************/
/** BIO WRAPPERS												*/
/****************************************************************/

static void submit_bio_sync_cb(struct bio *bio, int error);

int zjournal_issue_zeroout(sector_t start_sector, sector_t size, gfp_t gfp_mask)
{
	/* We can't just call here
	    	blkdev_issue_zeroout(globals.jdev, 0, globals.jdev_size_blk, gfp_mask);
	   - MD kills the WRITE_SAME flag. There are also several layers down that also need to support WRITE_SAME (open-iscsi, scst(stgt?), sn)
    */

	struct blk_plug plug;
	sector_t nr_sects;
	int rc;

	if (unlikely(globals.jdev==NULL)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: journal was not opened", globals.jpath);
		return -EBADF;
	}

	blk_start_plug(&plug);

	rc = 0;
	while (size>0) {
		nr_sects = min(size, (sector_t)ZJOURNAL_MAX_BUF_BLK);
		rc = zblkdev_issue_zeroout(globals.jdev, start_sector, nr_sects, gfp_mask);
		if (unlikely(rc!=0))
			break;
		start_sector += nr_sects;
		size -= nr_sects;
	}

	blk_finish_plug(&plug);

	return rc;
}

struct bio_sync_ctx {
	struct completion	wait;
	int					error;
};

int __submit_bio_sync(int rw, struct bio *bio, sector_t bi_sector, const char *file, const char *func, int line)
{
	struct bio_sync_ctx ctx;
	struct blk_plug plug;

	BUG_ON(bio->bi_end_io!=NULL);
	BUG_ON(bio->bi_private!=NULL);

	bio->bi_iter.bi_sector = bi_sector;
	bio->bi_end_io = submit_bio_sync_cb;
	bio->bi_private = &ctx;

	bio->bi_rw |= rw;
	if (rw == READ)
		BUG_ON(bio->bi_rw & WRITE);

	__zklog_print_tag(ZKLOG_THIS_MODULE_CTX, Z_KDEB2, ZKLOG_TAG_JOURNAL, file, func, line, 
					  "zjournal %s: submit_bio_sync(%s,bi_sector=%ld,bi_size=%d)", rw==READ ? "READ" : "WRITE", globals.jpath, bio->bi_iter.bi_sector, bio->bi_iter.bi_size);

	init_completion(&ctx.wait); 

	if (rw == WRITE)
		blk_start_plug(&plug);
	submit_bio(rw, bio);
	if (rw == WRITE)
		blk_finish_plug(&plug);

	wait_for_completion(&ctx.wait);

	bio->bi_end_io = NULL;
	bio->bi_private = NULL;

	if (unlikely(ctx.error!=0))
		__zklog_print_tag(ZKLOG_THIS_MODULE_CTX, Z_KWARN, ZKLOG_TAG_JOURNAL, file, func, line, 
						  "zjournal %s: submit_bio_sync(%s,bi_sector=%ld,bi_size=%d) failed: rc=%d", rw==READ ? "READ" : "WRITE", globals.jpath, bio->bi_iter.bi_sector, bio->bi_iter.bi_size, ctx.error);

	return ctx.error;
}

static void submit_bio_sync_cb(struct bio *bio, int error)
{
	struct bio_sync_ctx *ctx = bio->bi_private;
	ctx->error = error;
	complete(&ctx->wait);
}

struct bio* __zjournal_bio_map_kern(void *data, unsigned int len, gfp_t gfp_mask, int *rc, const char *file, const char *func, int line)
{
	struct bio *bio;

	if (unlikely(globals.jdev==NULL)) {
		__zklog_print_default_tag(ZKLOG_THIS_MODULE_CTX, Z_KWARN, file, func, line, 
								  "zjournal %s: journal was not opened", globals.jpath);
		*rc = -EBADF;
		return NULL;
	}

	/* TODO: Reimplement bio_map_kern/bio_kmalloc as zbtrfs_zstats_* to allow using overriden submit_bio and not zbtrfs_globals.orig_submit_bio */
	bio = bio_map_kern(bdev_get_queue(globals.jdev), data, len, gfp_mask);
	if (unlikely(IS_ERR(bio))) {
		*rc = PTR_ERR(bio);
		bio = NULL;
		__zklog_print_default_tag(ZKLOG_THIS_MODULE_CTX, Z_KWARN, file, func, line, 
								  "zjournal %s: bio_map_kern(size=%u) failed, rc=%d", globals.jpath, len, *rc);
	}
	else {
		bio->bi_bdev = globals.jdev;
		bio->bi_end_io = NULL;
		bio->bi_private = NULL;
		*rc = 0;
	}

	return bio;
}

/****************************************************************/
/** 															*/
/****************************************************************/

void zjournal_pool_reset(struct zjournal_pool *pool, bool created)
{
	if (!pool->replayed) {
		zjournal_pool_free_replay_tree(pool);
		zjournal_pool_free_replay_list(pool);
	}
	else {
		ZJOURNAL_ASSERT(pool->replay_tree_cnt==0, "replay_tree_cnt=%d", pool->replay_tree_cnt);
	}

	pool->max_transid = 0;
	pool->flags = 0;
	pool->created = created;
	pool->fs_info = NULL;
}

/****************************************************************/
/** REPLAY TREE													*/
/****************************************************************/

void zjournal_pool_free_replay_tree(struct zjournal_pool *pool)
{
	struct zjournal_replay_item *gang[16];

	while (1) {
		unsigned int item_idx = 0;
		unsigned int nr_items = radix_tree_gang_lookup(&pool->replay_tree, (void**)gang, 0/*first_index*/, ARRAY_SIZE(gang)/*max_items*/);

		if (nr_items == 0)
			break;

		for (item_idx = 0; item_idx < nr_items; ++item_idx) {
			if (unlikely(gang[item_idx] == NULL))
				continue;
			zjournal_pool_replay_tree_delete_item(pool, gang[item_idx]);
			kfree(gang[item_idx]);
		}
	}

	ZJOURNAL_ASSERT(pool->replay_tree_cnt==0, "replay_tree_cnt=%d", pool->replay_tree_cnt);

	INIT_RADIX_TREE(&pool->replay_tree, GFP_NOFS);
	pool->replay_tree_valid = false;
}

struct zjournal_replay_item *zjournal_pool_replay_tree_get_first(struct zjournal_pool *pool)
{
	struct zjournal_replay_item *gang[1];
	unsigned int nr_items = 0;

	nr_items = radix_tree_gang_lookup(&pool->replay_tree, (void**)gang, 0/*first_index*/, 1/*max_items*/);
	if (nr_items == 0)
		return NULL;

	return gang[0];
}

int zjournal_pool_replay_tree_insert_item(struct zjournal_pool *pool, struct zjournal_replay_item *ritem)
{
	int rc;
	rc = radix_tree_insert(&pool->replay_tree, ritem->entry.address, ritem);
	if (likely(rc == 0)) {
		pool->replay_tree_cnt++;
	}
	else {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: radix_tree_insert("FMT_REPLAY_ITEM") failed, rc=%d", 
				  globals.jpath, pool->pool_id, ritem->item_idx, PRI_REPLAY_ITEM(ritem), rc);
	}
	return rc;
}

void zjournal_pool_replay_tree_delete_item(struct zjournal_pool *pool, struct zjournal_replay_item *ritem)
{
	struct zjournal_replay_item *r;
	r = radix_tree_delete(&pool->replay_tree, ritem->entry.address);
	BUG_ON(r!=ritem);
	pool->replay_tree_cnt--;
}

/****************************************************************/
/** REPLAY LIST													*/
/****************************************************************/

void zjournal_pool_free_replay_list(struct zjournal_pool *pool)
{
	struct zjournal_replay_item *ritem;

	while(!list_empty(&pool->replay_list)) {
		ritem = list_entry(pool->replay_list.next, struct zjournal_replay_item, lnode);
		list_del(&ritem->lnode);
		kfree(ritem);
	}
}
	
/****************************************************************/
/** 															*/
/****************************************************************/

static const char* zjournal_disk_item_version_convert_from_01(int item_idx, struct zjournal_disk_item *disk_item);
static const char* zjournal_disk_item_version_convert_from_02(int item_idx, struct zjournal_disk_item *disk_item);

int zjournal_disk_item_version_convert(int item_idx, struct zjournal_disk_item *disk_item)
{
	const char *err_msg = NULL;
	
	if (unlikely(disk_item->magic != ZJOURNAL_DISK_ITEM_MAGIC)) {
		/* Assume this is v1 */
		err_msg = zjournal_disk_item_version_convert_from_01(item_idx, disk_item);
		goto end;
	}

	if (likely(disk_item->version == ZJOURNAL_VERSION)) {
		u32 crc = ZJOURNAL_CHECKSUM(disk_item);
		if (unlikely(disk_item->crc != crc)) {
			zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: invalid crc %u, expected %u: "FMT_DISK_ITEM, 
					  globals.jpath, disk_item->pool_id, item_idx, disk_item->crc, crc, PRI_DISK_ITEM(disk_item));
			err_msg = "invalid disk item crc";
		}
		goto end;
	}

	if (likely(disk_item->version == 2)) {
		err_msg = zjournal_disk_item_version_convert_from_02(item_idx, disk_item);
		goto end;
	}

	zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: invalid version: "FMT_DISK_ITEM, 
			  globals.jpath, disk_item->pool_id, item_idx, PRI_DISK_ITEM(disk_item));
	err_msg = "invalid disk item version";

end:
	if (likely(err_msg == NULL)) {
		return 0;
	}
	else {
		zjournal_report_corruption(disk_item->pool_id, err_msg);
		memzero(disk_item, sizeof(struct zjournal_disk_item));
		return -EINVAL;
	}
}

static const char* zjournal_disk_item_version_convert_from_01(int item_idx, struct zjournal_disk_item *disk_item)
{
	const struct zjournal_disk_item_v1 *disk_item_v1;
	u32 crc;

	disk_item_v1 = (const struct zjournal_disk_item_v1*)disk_item;

	if (disk_item_v1->pool_id == 0) {
		memzero(disk_item, sizeof(struct zjournal_disk_item));
		return NULL;
	}

	crc = ZJOURNAL_CHECKSUM(disk_item_v1);
	if (unlikely(disk_item_v1->crc != crc)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: invalid v1 crc %u, expected %u: "FMT_DISK_ITEM, 
				  globals.jpath, disk_item->pool_id, item_idx, disk_item_v1->crc, crc, PRI_DISK_ITEM(disk_item));
		return "invalid v1 disk item crc";
	}

	zjournal_disk_item_init(disk_item, 
							disk_item_v1->pool_id, disk_item_v1->generation, disk_item_v1->transid, 0/*io_cnt*/, ZBTRFS_ZTENANT_SYSTEM_ID, 
							disk_item_v1->subvol_treeid, disk_item_v1->inode_num, disk_item_v1->inode_gen, disk_item_v1->file_offset, 
							disk_item_v1->address);

	zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, 
			  "zjournal %s: pool[%d]: item[%d]: convert version %d -> %d: "FMT_DISK_ITEM,
			  globals.jpath, disk_item->pool_id, item_idx, 1, ZJOURNAL_VERSION, PRI_DISK_ITEM(disk_item));

	return NULL;
}

static const char* zjournal_disk_item_version_convert_from_02(int item_idx, struct zjournal_disk_item *disk_item)
{
	const struct zjournal_disk_item_v2 *disk_item_v2;
	u32 crc;

	disk_item_v2 = (const struct zjournal_disk_item_v2*)disk_item;

	if (disk_item_v2->pool_id == 0) {
		memzero(disk_item, sizeof(struct zjournal_disk_item));
		return NULL;
	}

	crc = ZJOURNAL_CHECKSUM(disk_item_v2);
	if (unlikely(disk_item_v2->crc != crc)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: invalid v2 crc %u, expected %u: "FMT_DISK_ITEM, 
				  globals.jpath, disk_item->pool_id, item_idx, disk_item_v2->crc, crc, PRI_DISK_ITEM(disk_item));
		return "invalid v2 disk item crc";
	}

	zjournal_disk_item_init(disk_item, 
							disk_item_v2->pool_id, disk_item_v2->generation, disk_item_v2->transid, disk_item_v2->io_cnt, ZBTRFS_ZTENANT_SYSTEM_ID, 
							disk_item_v2->subvol_treeid, disk_item_v2->inode_num, disk_item_v2->inode_gen, disk_item_v2->file_offset, 
							disk_item_v2->address);

	zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, 
			  "zjournal %s: pool[%d]: item[%d]: convert version %d -> %d: "FMT_DISK_ITEM,
			  globals.jpath, disk_item->pool_id, item_idx, 2, ZJOURNAL_VERSION, PRI_DISK_ITEM(disk_item));

	return NULL;
}


void zjournal_disk_item_init(struct zjournal_disk_item *disk_item, u16 pool_id, u64 generation, u64 transid, u64 io_cnt, u16 tenant_id, u64 subvol_treeid, u64 inode_num, u64 inode_gen, u64 file_offset, u64 address)
{
	memzero(disk_item, sizeof(struct zjournal_disk_item));

	disk_item->magic = ZJOURNAL_DISK_ITEM_MAGIC;
	disk_item->version = ZJOURNAL_VERSION;

	disk_item->pool_id = pool_id;
	disk_item->generation = generation;
	disk_item->transid = transid;
	disk_item->io_cnt = io_cnt;
	disk_item->tenant_id = tenant_id;

	disk_item->entry.subvol_treeid = subvol_treeid;
	disk_item->entry.inode_num = inode_num;
	disk_item->entry.inode_gen = inode_gen;
	disk_item->entry.file_offset = file_offset;
	disk_item->entry.address = address;

	disk_item->crc = ZJOURNAL_CHECKSUM(disk_item);
}

bool zjournal_disk_item_in_use(int item_idx, const struct zjournal_disk_item *disk_item)
{
	struct zjournal_pool *pool = NULL;

	if (disk_item->pool_id == 0) {
		zklog_tag(Z_KDEB2, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: pool_id==0", globals.jpath, disk_item->pool_id, item_idx);
		return false;
	}

	if (unlikely(disk_item->pool_id < ZJOURNAL_MIN_POOL_ID || disk_item->pool_id > ZJOURNAL_MAX_POOL_ID)) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: "FMT_DISK_ITEM": pool_id too big", 
				  globals.jpath, disk_item->pool_id, item_idx, PRI_DISK_ITEM(disk_item));
		zjournal_report_corruption(disk_item->pool_id, "invalid pool_id");
		return false;
	}

	pool = &globals.pools[disk_item->pool_id];
	ZJOURNAL_ASSERT(pool->pool_id == disk_item->pool_id, "pool->pool_id=%d, disk_item->pool_id=%d", pool->pool_id, disk_item->pool_id);

	if (!pool->created) {
		zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: pool not created", 
				  globals.jpath, disk_item->pool_id, item_idx);
		return false;
	}

	if (disk_item->generation < pool->generation) {
		zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: "FMT_DISK_ITEM", generation < %llu, reuse item", 
				  globals.jpath, disk_item->pool_id, item_idx, PRI_DISK_ITEM(disk_item), pool->generation);
		return false;
	}

	/* This item might need be replayed */
	zklog_tag(Z_KDEB1, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: item[%d]: " FMT_DISK_ITEM " - need replay", 
			  globals.jpath, disk_item->pool_id, item_idx, PRI_DISK_ITEM(disk_item));

	return true;
}

/****************************************************************/
/** 															*/
/****************************************************************/

void zjournal_report_corruption(u16 pool_id, const char *msg)
{
	struct btrfs_fs_info *fs_info;

	if (unlikely(pool_id<ZJOURNAL_MIN_POOL_ID || pool_id>ZJOURNAL_MAX_POOL_ID)) {
		fs_info = NULL;
	}
	else {
		struct zjournal_pool *pool = &globals.pools[pool_id];
		if (unlikely(pool->fs_info==NULL))
			fs_info = NULL;
		else
			fs_info = pool->fs_info;
	}
		

//	WARN(true, "zjournal %s: pool[%d]: %s", globals.jpath, pool_id, msg);
	zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: %s", globals.jpath, pool_id, msg);

	if(likely(fs_info!=NULL)) {
		fs_info->zfs_info.report_zjournal_corruption = true;
		zbtrfs_control_poll_wake_up(fs_info, POLLERR);
	}
}
#endif /*CONFIG_BTRFS_ZADARA*/

