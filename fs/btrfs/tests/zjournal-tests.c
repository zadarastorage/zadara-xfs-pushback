#ifdef CONFIG_BTRFS_ZADARA
#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
#include <linux/delay.h>
#include <linux/random.h>
#include "btrfs-tests.h"
#include "../ctree.h"
#include "../zjournal.h"

#define ZJOURNAL_TEST_ASSERT_MSG(cond, fmt, ...)														\
do {																									\
	if (unlikely(!(cond))) {																			\
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "ASSERT(%s): "fmt, #cond, ##__VA_ARGS__);					\
		return -ECANCELED;																				\
	}																									\
} while(0)

#define ZJOURNAL_TEST_ASSERT(cond)	ZJOURNAL_TEST_ASSERT_MSG(cond, "")


#define ZJOURNAL_TEST_CALLV(call, exp_rc)																\
({																										\
	rc = call;																							\
	if (unlikely(rc!=(exp_rc)))																			\
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "%s returned %d, expected %d", (#call), rc, (exp_rc));	\
	(rc == (exp_rc));																					\
})

#define ZJOURNAL_TEST_CALL(call, exp_rc)																\
do {																									\
	if (unlikely(!ZJOURNAL_TEST_CALLV(call, exp_rc)))													\
		return (exp_rc)==0 ? rc : -ECANCELED;															\
} while(0)

#define ZJOURNAL_RUN_TEST(n)																			\
do {																									\
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "======================================================");	\
	zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "Running test_zjournal %s...", (#n));							\
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);														\
	ZJOURNAL_TEST_CALL(zbtrfs_zjournal_test_##n(), 0);													\
} while(0)

#define zjournal_test_close()																			\
({																										\
	/* We don't have a btrfs patch "eliminate races in worker stopping code".			*/				\
	/* WORKAROUND: sleep before zjournal_close() to ensure worker_loop() is sleepin.	*/				\
	msleep(100);																						\
	zjournal_close(false);																				\
})

static int zbtrfs_zjournal_test_open(const char *zjournal_path)
{
	int rc;

	globals.jdev = blkdev_get_by_path(zjournal_path, FMODE_READ|FMODE_WRITE|FMODE_EXCL, &globals/*holder*/);
	if (unlikely(IS_ERR(globals.jdev))) {
		rc = PTR_ERR(globals.jdev);
		globals.jdev = NULL;
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "blkdev_get_by_path(%s) failed, rc=%d", zjournal_path, rc);
		return rc;
	}

	return 0;
}

static void zbtrfs_zjournal_test_close(void)
{
	blkdev_put(globals.jdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	globals.jdev = NULL;
}

static int zbtrfs_zjournal_test_01(void)
{
	const u8 vpsaid1[BTRFS_UUID_SIZE] = {1};
	const u8 vpsaid2[BTRFS_UUID_SIZE] = {2};
	int rc;

	ZJOURNAL_TEST_CALL(	zjournal_open("/non-existing-device",	vpsaid1, true, true),	-ENOENT		);
	ZJOURNAL_TEST_CALL(	zjournal_open("/dev/ram0", 				vpsaid1, true, true),	0			);
	ZJOURNAL_TEST_CALL(	zjournal_open("/dev/ram0", 				vpsaid1, true, true),	-EEXIST		);
	ZJOURNAL_TEST_CALL(	zjournal_open("/dev/ram1", 				vpsaid1, true, true),	-ENOTUNIQ	);
	ZJOURNAL_TEST_CALL(	zjournal_test_close(),											0			);
	ZJOURNAL_TEST_CALL(	zjournal_open("/dev/ram0", 				vpsaid2, false, false),	-ECANCELED	);
	ZJOURNAL_TEST_CALL(	zjournal_open("/dev/ram0", 				vpsaid2, false, true),	0			);
	ZJOURNAL_TEST_CALL(	zjournal_test_close(),											0			);
	ZJOURNAL_TEST_CALL(	zjournal_open("/dev/ram0", 				vpsaid2, false, false),	0			);
	ZJOURNAL_TEST_CALL(	zjournal_test_close(),											0			);

	return 0;
}

static int zbtrfs_zjournal_test_02(void)
{
	const u8 vpsaid[BTRFS_UUID_SIZE] = {2};
	int rc, i, j;

	ZJOURNAL_TEST_CALL(zjournal_open("/dev/ram2", vpsaid, true, true), 0);

	for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i+=4) {
		ZJOURNAL_TEST_CALL(zjournal_create_pool(i), 0);
	}

	for(j=0; j<2; j++) {
		for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
			struct zjournal_pool *pool = &globals.pools[i];
			ZJOURNAL_TEST_ASSERT(pool->pool_id==i);
			if(i%4==1) {
				ZJOURNAL_TEST_ASSERT(pool->generation==1);
				ZJOURNAL_TEST_ASSERT(pool->created);
			}
			else {
				ZJOURNAL_TEST_ASSERT(pool->generation==0);
				ZJOURNAL_TEST_ASSERT(!pool->created);
			}
		}
		if (j==0) {
			ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);
			ZJOURNAL_TEST_CALL(zjournal_open("/dev/ram2", vpsaid, false, false), 0);
		}
	}

	for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i+=2) {
		ZJOURNAL_TEST_CALL(zjournal_create_pool(i), i%4==1 ? -EEXIST : 0);
	}

	for(j=0; j<2; j++) {
		for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
			struct zjournal_pool *pool = &globals.pools[i];
			ZJOURNAL_TEST_ASSERT(pool->pool_id==i);
			if(i%2==1) {
				ZJOURNAL_TEST_ASSERT(pool->generation==1);
				ZJOURNAL_TEST_ASSERT(pool->created);
			}
			else {
				ZJOURNAL_TEST_ASSERT(pool->generation==0);
				ZJOURNAL_TEST_ASSERT(!pool->created);
			}
		}
		if (j==0) {
			ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);
			ZJOURNAL_TEST_CALL(zjournal_open("/dev/ram2", vpsaid, false, false), 0);
		}
	}

	for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i+=2) {
		ZJOURNAL_TEST_CALL(zjournal_delete_pool(i), 0);
	}

	for(j=0; j<2; j++) {
		for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
			struct zjournal_pool *pool = &globals.pools[i];
			ZJOURNAL_TEST_ASSERT(pool->pool_id==i);
			if(i%2==1)
				ZJOURNAL_TEST_ASSERT(pool->generation==2);
			else
				ZJOURNAL_TEST_ASSERT(pool->generation==0);
			ZJOURNAL_TEST_ASSERT(!pool->created);
		}
		if (j==0) {
			ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);
			ZJOURNAL_TEST_CALL(zjournal_open("/dev/ram2", vpsaid, false, false), 0);
		}
	}

	for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
		ZJOURNAL_TEST_CALL(zjournal_create_pool(i), 0);
	}

	for(j=0; j<2; j++) {
		for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
			struct zjournal_pool *pool = &globals.pools[i];
			ZJOURNAL_TEST_ASSERT(pool->pool_id==i);
			if(i%2==1)
				ZJOURNAL_TEST_ASSERT(pool->generation==3);
			else
				ZJOURNAL_TEST_ASSERT(pool->generation==1);
			ZJOURNAL_TEST_ASSERT(pool->created);
		}
		if (j==0) {
			ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);
			ZJOURNAL_TEST_CALL(zjournal_open("/dev/ram2", vpsaid, false, false), 0);
		}
	}

	for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
		ZJOURNAL_TEST_CALL(zjournal_delete_pool(i), 0);
	}

	for(j=0; j<2; j++) {
		for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
			struct zjournal_pool *pool = &globals.pools[i];
			ZJOURNAL_TEST_ASSERT(pool->pool_id==i);
			if(i%2==1)
				ZJOURNAL_TEST_ASSERT(pool->generation==4);
			else
				ZJOURNAL_TEST_ASSERT(pool->generation==2);
			ZJOURNAL_TEST_ASSERT(!pool->created);
		}
		if (j==0) {
			ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);
			ZJOURNAL_TEST_CALL(zjournal_open("/dev/ram2", vpsaid, false, false), 0);
		}
	}

	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	return 0;
}

static int zbtrfs_zjournal_test_03(void)
{
	const char zjournal_path[] = "/dev/ram3";
	const u8 vpsaid[BTRFS_UUID_SIZE] = {3};
	char buf[512] = "";
	struct bio *bio = NULL;
	int rc, i, j, main_sb_ver;
	bool ok;

	for (main_sb_ver=1; main_sb_ver<=ZJOURNAL_VERSION; main_sb_ver++) {

		ZJOURNAL_TEST_CALL(zbtrfs_zjournal_test_open(zjournal_path), 0);

		// Create main superblock, main_sb_ver
		{
			memzero(buf, sizeof(buf));
			*(u32*)(&buf[0]) = ZJOURNAL_MAIN_SUPERBLOCK_MAGIC;
			*(u32*)(&buf[4]) = main_sb_ver;	// version
			memcpy(&buf[8], vpsaid, BTRFS_UUID_SIZE);

			bio = zjournal_bio_map_kern(buf, sizeof(buf), GFP_KERNEL, &rc);
			if (unlikely(rc!=0)) {
				zbtrfs_zjournal_test_close();
				return rc;
			}

			ok = ZJOURNAL_TEST_CALLV(submit_bio_sync(WRITE, bio, 0), 0);
			bio_put(bio);
			if (unlikely(!ok)) {
				zbtrfs_zjournal_test_close();
				return rc;
			}
		}

		// Create pool superblocks
		{
			// 1: ver=-1
			// 2: ver=ZJOURNAL_VERSION
			// 3: ver=ZJOURNAL_VERSION, bad crc
			// 4: ver=1
			// 5: ver=1, bad crc
			// 6: ver=2
			// 7: ver=2, bad crc			
			for (i=1; i<=7; i++) {
				memzero(buf, sizeof(buf));
				if (i <= 3) {
					struct zjournal_pool_superblock *pool_sb = (struct zjournal_pool_superblock*)buf;
					pool_sb->magic = ZJOURNAL_POOL_SUPERBLOCK_MAGIC;
					pool_sb->version = ZJOURNAL_VERSION;
					pool_sb->generation = i;
					pool_sb->flags = 0x1;
					pool_sb->crc = ZJOURNAL_CHECKSUM(pool_sb);
					if (i==1)
						pool_sb->version = -1;
					else if (i==3)
						pool_sb->crc = 12345;
				}
				else if (i <= 5) {
					struct zjournal_pool_superblock_v1 *pool_sb = (struct zjournal_pool_superblock_v1*)buf;
					pool_sb->generation = i;
					pool_sb->flags = 0x1;
					pool_sb->crc = ZJOURNAL_CHECKSUM(pool_sb);
					if (i==5)
						pool_sb->crc = 12345;
				}
				else {
					struct zjournal_pool_superblock *pool_sb = (struct zjournal_pool_superblock*)buf;
					pool_sb->magic = ZJOURNAL_POOL_SUPERBLOCK_MAGIC;
					pool_sb->version = 2;
					pool_sb->generation = i;
					pool_sb->flags = 0x1;
					pool_sb->crc = ZJOURNAL_CHECKSUM(pool_sb);
					if (i==7)
						pool_sb->crc = 12345;
				}

				bio = zjournal_bio_map_kern(buf, sizeof(buf), GFP_KERNEL, &rc);
				if (unlikely(rc!=0)) {
					zbtrfs_zjournal_test_close();
					return rc;
				}

				ok = ZJOURNAL_TEST_CALLV(submit_bio_sync(WRITE, bio, ZJOURNAL_MAIN_SUPERBLOCK_SIZE_BLK + i), 0);
				bio_put(bio);
				if (unlikely(!ok)) {
					zbtrfs_zjournal_test_close();
					return rc;
				}
			}
		}

		zbtrfs_zjournal_test_close();

		for(j=0; j<2; j++) {
			ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, false, false), 0);

			for(i=ZJOURNAL_MIN_POOL_ID; i<=ZJOURNAL_MAX_POOL_ID; i++) {
				struct zjournal_pool *pool = &globals.pools[i];
				ZJOURNAL_TEST_ASSERT(pool->pool_id==i);
				if (i<=7) {
					if(i==2 || i==4 || i==6)
						ZJOURNAL_TEST_ASSERT(pool->generation==i);
					else
						ZJOURNAL_TEST_ASSERT(pool->generation==0);
					ZJOURNAL_TEST_ASSERT(pool->created);
				}
				else {
					ZJOURNAL_TEST_ASSERT(pool->generation==0);
					ZJOURNAL_TEST_ASSERT(!pool->created);
				}
			}

			ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);
		}

	} /* for (main_sb_ver=1; main_sb_ver<=ZJOURNAL_VERSION; main_sb_ver++) */

	return 0;
}

static int zbtrfs_zjournal_test_04(void)
{
	const u16 pool_id = 4;
	const char zjournal_path[] = "/dev/ram4";
	const u8 vpsaid[BTRFS_UUID_SIZE] = {4};
	struct zjournal_pool *pool;
	char buf[512] = "";
	struct bio *bio = NULL;
	int rc, i;
	bool ok;

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, true, true), 0);
	ZJOURNAL_TEST_CALL(zjournal_create_pool(pool_id), 0);
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	ZJOURNAL_TEST_CALL(zbtrfs_zjournal_test_open(zjournal_path), 0);

	// Create disk items
	// 1: ver=-1
	// 2: ver=ZJOURNAL_VERSION
	// 3: ver=ZJOURNAL_VERSION, bad crc
	// 4: ver=ZJOURNAL_VERSION, bad pool_id
	// 5: ver=1
	// 6: ver=1, bad crc
	// 7: ver=2
	// 8: ver=2, bad crc
	for (i=1; i<=8; i++) {
		memzero(buf, sizeof(buf));
		if (i <= 4) {
			struct zjournal_disk_item *disk_item = (struct zjournal_disk_item*)buf;
			zjournal_disk_item_init(disk_item, 
									i!=4 ? pool_id : 44444, 
									i/*generation*/,
									10*i/*transid*/,
									1/*io_cnt*/,
									10*i/*tenant_id*/,
									100*i/*entry.subvol_treeid*/,
									1000*i/*entry.inode_num*/,
									10000*i/*entry.inode_gen*/,
									100000*i/*entry.file_offset*/,
									1000000*i/*entry.address*/);
			if (i == 1)
				disk_item->version = -1;
			else if (i == 3)
				disk_item->crc = 12345;
		}
		else if (i <= 6) {
			struct zjournal_disk_item_v1 *disk_item = (struct zjournal_disk_item_v1*)buf;
			disk_item->pool_id = pool_id;
			disk_item->generation = i;
			disk_item->transid = 10*i;
			disk_item->subvol_treeid = 100*i;
			disk_item->inode_num = 1000*i;
			disk_item->inode_gen = 10000*i;
			disk_item->file_offset = 100000*i;
			disk_item->address = 1000000*i;
			disk_item->crc = ZJOURNAL_CHECKSUM(disk_item);
			if (i==6)
				disk_item->crc = 12345;
		}
		else {
			struct zjournal_disk_item_v2 *disk_item = (struct zjournal_disk_item_v2*)buf;
			disk_item->magic = ZJOURNAL_DISK_ITEM_MAGIC;
			disk_item->version = 2;
			disk_item->pool_id = pool_id;
			disk_item->generation = i;
			disk_item->transid = 10*i;
			disk_item->subvol_treeid = 100*i;
			disk_item->inode_num = 1000*i;
			disk_item->inode_gen = 10000*i;
			disk_item->file_offset = 100000*i;
			disk_item->address = 1000000*i;
			disk_item->crc = ZJOURNAL_CHECKSUM(disk_item);
			if (i==8)
				disk_item->crc = 12345;
		}

		bio = zjournal_bio_map_kern(buf, sizeof(buf), GFP_KERNEL, &rc);
		if (unlikely(rc!=0)) {
			zbtrfs_zjournal_test_close();
			return rc;
		}

		ok = ZJOURNAL_TEST_CALLV(submit_bio_sync(WRITE, bio, ZJOURNAL_SUPERBLOCK_SIZE_BLK + i), 0);
		bio_put(bio);
		if (unlikely(!ok)) {
			zbtrfs_zjournal_test_close();
			return rc;
		}
	}

	zbtrfs_zjournal_test_close();

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, false, false), 0);
	for (i=0; i<globals.jmap_size; i++) {
		if (i==2 || i==5 || i==7) {
			ZJOURNAL_TEST_ASSERT_MSG(globals.jmap[i].pool_id == pool_id, "jmap[%d].pool_id=%d!=%d", i, globals.jmap[i].pool_id, pool_id);
			ZJOURNAL_TEST_ASSERT(globals.jmap[i].transid == 10*i);
		}
		else {
			ZJOURNAL_TEST_ASSERT(globals.jmap[i].pool_id == 0);
			ZJOURNAL_TEST_ASSERT(globals.jmap[i].transid == 0);
		}
	}
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, false, false), 0);

	for (i=0; i<globals.jmap_size; i++) {
		if (i==2 || i==5 || i==7) {
			ZJOURNAL_TEST_ASSERT(globals.jmap[i].pool_id == pool_id);
			ZJOURNAL_TEST_ASSERT(globals.jmap[i].transid == 10*i);
		}
		else {
			ZJOURNAL_TEST_ASSERT(globals.jmap[i].pool_id == 0);
			ZJOURNAL_TEST_ASSERT(globals.jmap[i].transid == 0);
		}
	}

	pool = &globals.pools[pool_id];

	ZJOURNAL_TEST_CALL(zjournal_mount(pool_id, 1/*last_commited_transid*/, NULL/*fs_info*/), 0);
	ZJOURNAL_TEST_ASSERT(pool->replay_tree_cnt == 3);
	ZJOURNAL_TEST_ASSERT(pool->replay_tree_valid);

	ZJOURNAL_TEST_CALL(zjournal_replay(pool_id), 0);
	ZJOURNAL_TEST_ASSERT(pool->replay_tree_cnt == 0);
	ZJOURNAL_TEST_ASSERT(!pool->replay_tree_valid);
	ZJOURNAL_TEST_ASSERT(list_empty(&pool->replay_list));
	ZJOURNAL_TEST_ASSERT(pool->replayed);

	ZJOURNAL_TEST_CALL(zjournal_umount(pool_id), 0);
	ZJOURNAL_TEST_CALL(zjournal_delete_pool(pool_id), 0);
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, false, false), 0);
	for (i=0; i<globals.jmap_size; i++) {
		ZJOURNAL_TEST_ASSERT_MSG(globals.jmap[i].pool_id == 0, "jmap[%d].pool_id=%d!=%d", i, globals.jmap[i].pool_id, 0);
		ZJOURNAL_TEST_ASSERT(globals.jmap[i].transid == 0);
	}
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	return 0;
}

static int zbtrfs_zjournal_test_05(void)
{
	const u16 pool_id = 5;
	const char zjournal_path[] = "/dev/ram5";
	const u8 vpsaid[BTRFS_UUID_SIZE] = {5};
	struct zjournal_pool *pool;
	char buf[512] = "";
	struct bio *bio = NULL;
	int rc, i, j;
	bool ok;

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, true, true), 0);
	ZJOURNAL_TEST_CALL(zjournal_create_pool(pool_id), 0);
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	ZJOURNAL_TEST_CALL(zbtrfs_zjournal_test_open(zjournal_path), 0);

	// Create disk items
	for (i=1; i<=12; i++) {
		memzero(buf, sizeof(buf));
		if (i<=3) {
			struct zjournal_disk_item_v1 *disk_item = (struct zjournal_disk_item_v1*)buf;
			disk_item->pool_id = pool_id;
			disk_item->generation = i;
			disk_item->transid = 10*i;
			disk_item->subvol_treeid = i%2;
			disk_item->inode_num = 1000*i;
			disk_item->inode_gen = 10000*i;
			disk_item->file_offset = 100000*i;
			disk_item->address = 1000000*i;
			if (i==3) {
				// Conflicting address with 2
				j = 2;
				disk_item->subvol_treeid = j%2;
				disk_item->address = 1000000*j;
			}
			disk_item->crc = ZJOURNAL_CHECKSUM(disk_item);
		}
		else {
			struct zjournal_disk_item *disk_item = (struct zjournal_disk_item*)buf;
			u64 generation = i;
			u64 transid = 10*i;
			u64 io_cnt = 10;
			u64 subvol_treeid = i%2;
			u64 inode_num = 1000*i;
			u64 inode_gen = 10000*i;
			u64 file_offset = 100000*i;
			u64 address = 1000000*i;

			if (i==6) {
				// Conflicting physical address with 5
				j = 5;
				subvol_treeid = j%2;
				address = 1000000*j;
			}
			else if (i==8) {
				// Conflicting virtual address with 7, io_cnt[8]<io_cnt[7]
				j = 7;
				io_cnt = 5;
				subvol_treeid = j%2;
				inode_num = 1000*j;
				inode_gen = 10000 * j;
				file_offset = 100000*j;
			}
			else if (i==10) {
				// Conflicting virtual address with 9, io_cnt[10]>io_cnt[9]
				j = 9;
				io_cnt = 20;
				subvol_treeid = j%2;
				inode_num = 1000*j;
				inode_gen = 10000 * j;
				file_offset = 100000*j;
			}
			else if (i==12) {
				// Conflicting virtual address with 11, io_cnt[12]==io_cnt[11]
				j = 11;
				subvol_treeid = j%2;
				inode_num = 1000*j;
				inode_gen = 10000 * j;
				file_offset = 100000*j;
			}

			zjournal_disk_item_init(disk_item, pool_id, generation, transid, io_cnt, ZBTRFS_ZTENANT_SYSTEM_ID,
									subvol_treeid, inode_num, inode_gen, file_offset, address);
		}

		bio = zjournal_bio_map_kern(buf, sizeof(buf), GFP_KERNEL, &rc);
		if (unlikely(rc!=0)) {
			zbtrfs_zjournal_test_close();
			return rc;
		}

		ok = ZJOURNAL_TEST_CALLV(submit_bio_sync(WRITE, bio, ZJOURNAL_SUPERBLOCK_SIZE_BLK + i), 0);
		bio_put(bio);
		if (unlikely(!ok)) {
			zbtrfs_zjournal_test_close();
			return rc;
		}
	}

	zbtrfs_zjournal_test_close();

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, false, false), 0);

	pool = &globals.pools[pool_id];

	ZJOURNAL_TEST_CALL(zjournal_mount(pool_id, 1/*last_commited_transid*/, NULL/*fs_info*/), 0);
	ZJOURNAL_TEST_ASSERT_MSG(pool->replay_tree_cnt == 7, "replay_tree_cnt=%d", pool->replay_tree_cnt);
	ZJOURNAL_TEST_ASSERT(pool->replay_tree_valid);

	ZJOURNAL_TEST_CALL(zjournal_replay(pool_id), 0);
	ZJOURNAL_TEST_ASSERT(pool->replay_tree_cnt == 0);
	ZJOURNAL_TEST_ASSERT(!pool->replay_tree_valid);
	ZJOURNAL_TEST_ASSERT(list_empty(&pool->replay_list));
	ZJOURNAL_TEST_ASSERT(pool->replayed);

	ZJOURNAL_TEST_CALL(zjournal_umount(pool_id), 0);
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	return 0;
}

static int zbtrfs_zjournal_test_06(void)
{
	const u16 pool_id = 6;
	const char zjournal_path[] = "/dev/ram6";
	const u8 vpsaid[BTRFS_UUID_SIZE] = {6};
	char buf[512] = "";
	struct bio *bio = NULL;
	int jmap_size, rc, i;
	bool ok;

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, true, true), 0);
	ZJOURNAL_TEST_CALL(zjournal_create_pool(pool_id), 0);
	jmap_size = globals.jmap_size;
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	ZJOURNAL_TEST_CALL(zbtrfs_zjournal_test_open(zjournal_path), 0);

	// Create disk items
	for (i=0; i<jmap_size; i++) {
		struct zjournal_disk_item *disk_item = (struct zjournal_disk_item*)buf;
		
		u64 generation, transid, io_cnt, vaddr, paddr;

		memzero(buf, sizeof(buf));
		get_random_bytes(&generation, sizeof(generation));
		get_random_bytes(&transid, sizeof(transid));
		get_random_bytes(&io_cnt, sizeof(io_cnt));
		get_random_bytes(&vaddr, sizeof(vaddr));
		get_random_bytes(&paddr, sizeof(paddr));

		vaddr = vaddr % (jmap_size*10000);
		paddr = paddr % (jmap_size*10000);

		zjournal_disk_item_init(disk_item, pool_id, generation, transid, io_cnt, ZBTRFS_ZTENANT_SYSTEM_ID,
								vaddr/*subvol_treeid*/, vaddr/*inode_num*/, vaddr/*inode_gen*/, vaddr/*file_offset*/, 
								paddr/*address*/);

		bio = zjournal_bio_map_kern(buf, sizeof(buf), GFP_KERNEL, &rc);
		if (unlikely(rc!=0)) {
			zbtrfs_zjournal_test_close();
			return rc;
		}

		ok = ZJOURNAL_TEST_CALLV(submit_bio_sync(WRITE, bio, ZJOURNAL_SUPERBLOCK_SIZE_BLK + i), 0);
		bio_put(bio);
		if (unlikely(!ok)) {
			zbtrfs_zjournal_test_close();
			return rc;
		}
	}

	zbtrfs_zjournal_test_close();

	ZJOURNAL_TEST_CALL(zjournal_open(zjournal_path, vpsaid, false, false), 0);
	ZJOURNAL_TEST_CALL(zjournal_mount(pool_id, 1/*last_commited_transid*/, NULL/*fs_info*/), 0);
	ZJOURNAL_TEST_CALL(zjournal_replay(pool_id), 0);
	ZJOURNAL_TEST_CALL(zjournal_umount(pool_id), 0);
	ZJOURNAL_TEST_CALL(zjournal_test_close(), 0);

	return 0;
}

int zbtrfs_test_zjournal(void)
{
	int rc;

	ZJOURNAL_RUN_TEST(01);	/* open_journal,close_journal */
	ZJOURNAL_RUN_TEST(02);	/* create_pool,delete_pool */
	ZJOURNAL_RUN_TEST(03);	/* pool version convert */
	ZJOURNAL_RUN_TEST(04);	/* disk_item version convert */
	ZJOURNAL_RUN_TEST(05);	/* disk_item conflicts */
	ZJOURNAL_RUN_TEST(06);	/* replay */

	return 0;
}

#endif /*CONFIG_BTRFS_FS_RUN_SANITY_TESTS*/
#endif /*CONFIG_BTRFS_ZADARA*/

