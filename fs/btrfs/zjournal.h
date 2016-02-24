#ifndef __ZJOURNAL__
#define __ZJOURNAL__

#include <linux/blkdev.h>
#include <linux/crc32c.h>
#include <linux/types.h>
#include <zbio.h>
#include "ctree.h"
#include "zbtrfs-exported.h"

struct zbtrfs_fs_info;

extern zklog_tag_t ZKLOG_TAG_JOURNAL;

int zjournal_init(void);
void zjournal_exit(void);
int zjournal_sysfs_init(void);

int zjournal_show_globals(char *buf, size_t len);
int zjournal_dump_map(struct file *fd);
void zjournal_enable(bool enable);

/** 
 * Called from user-space (vac) on SOD
 * @return 0 on success 
 *  -EEXIST		journal was already opened with this path
 *  -ENOTUNIQ	journal was already opened with another path
 *  -EINVAL		journal device is zero sized
 *  -errno		other error
 */
int zjournal_open(const char *zjournal_path, const u8 vpsaid[BTRFS_UUID_SIZE], bool wipe_out, bool sb_init);

/** 
 * Called from user-space (vac) on EOD 
 * @param force	if true and any pool is mounted, do not reset this pool and return -EBUSY
 */
int zjournal_close(bool force);

/** 
 * Called from user-space (vac) on pool creation (not establish!)
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -EEXIST		poll was already created
   -errno		other error
 */
int zjournal_create_pool(u16 pool_id);

/** 
 * Called from user-space (vac) on pool deletion (not passivation!)
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -ENOENT		poll was not created
 *  -EBUSY		poll is still mounted
 *  -errno		other error
 */
int zjournal_delete_pool(u16 pool_id);

/** 
 * Called from btrfs during mount  
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -ENOENT		poll was not created
 *  -EBUSY		pool is already mounted
 *  -EINVAL		invalid transid (0)
 *  -errno		other error
 */
int zjournal_mount(u16 pool_id, u64 last_commited_transid, struct btrfs_fs_info *fs_info);

/** 
 * Called from btrfs during pool umount
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -errno		other error
 */
int zjournal_umount(u16 pool_id);

/** 
 * Called at the very end of btrfs mount sequence
 * @return 0 on success 
 *  -EINVAL		invalid pool_id 
 *  -EBADF		journal was not opened
 *  -EINVAL		pool was not mounted
 *  -EEXIST		pool was already replayed
 *  -errno		other error
 */
int zjournal_replay(u16 pool_id);

/** 
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -errno		other error
 */
int zjournal_is_replayed(u16 pool_id, bool *replayed);

/** 
 * Return min and max unreplayed address in range [start_addr..start_addr+num_addr). If there is no unreplayed address in the range, 
 * *min_addr=(u64)-1, and *max_addr=0. 
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -EINVAL		pool was not mounted
 *  -EEXIST		pool was already replayed
 *  -errno		other error
 */
int zjournal_get_unreplayed_addresses(u16 pool_id, u64 start_addr, u64 num_addr, u64 *min_addr, u64 *max_addr);

/** 
 * Called from btrfs after commit
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -EINVAL		pool was not replayed
 *  -EINVAL		invalid transid
 *  -errno		other error
 */
int zjournal_commit(u16 pool_id, u64 transid);





/** 
 * @internal: DEFINES
 */

#define ZJOURNAL_VERSION					3

#define ZJOURNAL_MIN_POOL_ID				ZBTRFS_MIN_POOL_ID
#define ZJOURNAL_MAX_POOL_ID				ZBTRFS_MAX_POOL_ID

#define ZJOURNAL_MAIN_SUPERBLOCK_SIZE		((size_t)PAGE_SIZE)
#define ZJOURNAL_POOL_SUPERBLOCK_SIZE		((size_t)ONE_BLK)
#define ZJOURNAL_SUPERBLOCK_SIZE			((size_t)ONE_MB)
#define ZJOURNAL_DISK_ITEM_SIZE				((size_t)ONE_BLK)
#define ZJOURNAL_MAX_BUF_SIZE				((size_t)BLK_DEF_MAX_SECTORS*ONE_BLK)

#define ZJOURNAL_MAIN_SUPERBLOCK_SIZE_BLK	BYTES_TO_BLK(ZJOURNAL_MAIN_SUPERBLOCK_SIZE)
#define ZJOURNAL_POOL_SUPERBLOCK_SIZE_BLK	BYTES_TO_BLK(ZJOURNAL_POOL_SUPERBLOCK_SIZE)
#define ZJOURNAL_SUPERBLOCK_SIZE_BLK		BYTES_TO_BLK(ZJOURNAL_SUPERBLOCK_SIZE)
#define ZJOURNAL_DISK_ITEM_SIZE_BLK			BYTES_TO_BLK(ZJOURNAL_DISK_ITEM_SIZE)
#define ZJOURNAL_MAX_BUF_BLK				BYTES_TO_BLK(ZJOURNAL_MAX_BUF_SIZE)

#define ZJOURNAL_MAIN_SUPERBLOCK_MAGIC		0x25604A1A
#define ZJOURNAL_POOL_SUPERBLOCK_MAGIC		0x25604A19
#define ZJOURNAL_DISK_ITEM_MAGIC			0x25604AD1

/** 
 * @internal: MACROS
 */

#define memzero(s, n)		memset((s), 0, (n))

#define TM_GET(tv)			do_gettimeofday((tv))
#define TM_DELTA(tv2, tv1)	((tv2)->tv_sec*1000000 + (tv2)->tv_usec) - ((tv1)->tv_sec*1000000 + (tv1)->tv_usec)

#define ZJOURNAL_ASSERT(cond, fmt, ...)														\
do {																						\
	if(unlikely(!(cond))) {																	\
		zklog_tag(Z_KERR, ZKLOG_TAG_JOURNAL, "ASSERT(%s): " fmt, #cond, ##__VA_ARGS__);		\
		BUG_ON(!(cond));																	\
	}																						\
} while(0)																					\

#define ZJOURNAL_CHECK_ARGS(pool_id, check_jdev) do {																			\
	if (unlikely(!globals.enable)) {																							\
		zklog_tag(Z_KINFO, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: disabled", globals.jpath, (pool_id));						\
		return 0;																												\
	}																															\
	if (unlikely((pool_id)<ZJOURNAL_MIN_POOL_ID || (pool_id)>ZJOURNAL_MAX_POOL_ID)) {											\
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: invalid pool_id", globals.jpath, (pool_id));				\
		return -EINVAL;																											\
	}																															\
	if (unlikely(globals.jdev==NULL)) {																							\
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "zjournal %s: pool[%d]: journal was not opened", globals.jpath, (pool_id));		\
		return check_jdev ? -EBADF : 0;																							\
	}																															\
} while(0)

#define ZJOURNAL_CHECKSUM(buf)		crc32c(0, (buf), offsetof(typeof(*buf), crc))

#define FMT_ENTRY					"subvol=%llu, inode_num=%llu, inode_gen=%llu, file_offset=%llu, address=%llu"
#define PRI_ENTRY(entry)			(entry)->subvol_treeid, (entry)->inode_num, (entry)->inode_gen, (entry)->file_offset, (entry)->address

#define FMT_DISK_ITEM				"ver=%d, generation=%llu, transid=%llu, io_cnt=%llu, tenant_id=%u, " FMT_ENTRY
#define PRI_DISK_ITEM(disk_item)	(disk_item)->version, (disk_item)->generation, (disk_item)->transid, (disk_item)->io_cnt, (disk_item)->tenant_id, PRI_ENTRY(&(disk_item)->entry)

#define FMT_REPLAY_ITEM				"generation=%llu, transid=%llu, io_cnt=%llu, tenant_id=%u, " FMT_ENTRY
#define PRI_REPLAY_ITEM(ritem)		(ritem)->generation, (ritem)->transid, (ritem)->io_cnt, (ritem)->tenant_id, PRI_ENTRY(&(ritem)->entry)

/** 
 * @internal: REMOVE LOCK
 */

struct removelock {
	atomic_t			cnt;
	struct completion	wait;
};

#define removelock_init(rl) do {			\
	atomic_set(&(rl)->cnt, 0);				\
	init_completion(&(rl)->wait);			\
} while(0)
#define removelock_acquire(rl) do {			\
	atomic_inc(&(rl)->cnt);					\
} while(0)
#define removelock_release(rl) do {			\
	if (atomic_dec_return(&(rl)->cnt) == 0)	\
		complete(&(rl)->wait);				\
} while(0)
#define removelock_wait(rl) do {			\
	wait_for_completion(&(rl)->wait);		\
} while(0)

/** 
 * @internal: ZJOURNAL WORK
 */

struct zjournal_work {
	struct btrfs_work	bwork;
	struct removelock	*rl;
	atomic_t			*rc;
	void				*arg;
};

#define zjournal_work_init(jwork, _func, _rl, _rc, _arg) ({				          \
	btrfs_init_work(&(jwork)->bwork, btrfs_zjournal_helper, (_func), NULL, NULL); \
	(jwork)->rl = (_rl);												          \
	(jwork)->rc = (_rc);												          \
	(jwork)->arg = (_arg);												          \
})
#define zjournal_work_alloc(_func, _rl, _rc, _arg) ({					\
	struct zjournal_work *jwork = kmalloc(sizeof(*jwork), GFP_NOFS);	\
	if (likely(jwork!=NULL))											\
		zjournal_work_init(jwork, _func, _rl, _rc, _arg);				\
	jwork;																\
})
#define zjournal_work_free(jwork) do {									\
	kfree((jwork));														\
} while(0)
#define zjournal_work_set_rc(jwork, _rc) do {							\
	atomic_cmpxchg((jwork)->rc, 0, (_rc));								\
} while(0)
#define zjournal_work_enqueue(jwork) do {								\
	removelock_acquire((jwork)->rl);									\
	btrfs_queue_work(globals.workers, &(jwork)->bwork);					\
} while(0)
#define zjournal_work_done(jwork) do {									\
	removelock_release((jwork)->rl);									\
} while(0)

/** 
 * @internal: ON-DISK STRUCTS
 */

struct zjournal_main_superblock {
	u32 magic;										/* ZJOURNAL_MAIN_SUPERBLOCK_MAGIC */
	u32 version;									/* ZJOURNAL_VERSION */
	u8 vpsaid[BTRFS_UUID_SIZE];
	u8 reserved[ZJOURNAL_MAIN_SUPERBLOCK_SIZE-24];
} __attribute__ ((packed));

struct zjournal_pool_superblock_v1 {
	u64 generation;
	u64 flags;
	u32 crc;
} __attribute__ ((packed));

struct zjournal_pool_superblock {
	u32 magic;										/* ZJOURNAL_POOL_SUPERBLOCK_MAGIC */
	u32 version;									/* ZJOURNAL_VERSION */
	u64 generation;									/* never reset, even if the pool is deleted! */
	union {
		u64 flags;
		struct {
			u64 created:1;
		};
	};
	u32 crc;										/* must be the last pool sb field. crc is computed up to here (not including) */
	u8 reserved[ZJOURNAL_POOL_SUPERBLOCK_SIZE-28];
} __attribute__ ((packed));

struct zjournal_disk_item {
	u32						magic;					/* ZJOURNAL_DISK_ITEM_MAGIC */
	u32						version;				/* ZJOURNAL_VERSION */
 	u16						pool_id;
	u64						generation;
	u64						transid;
	u64 					io_cnt;
	u16						tenant_id;
	struct zjournal_entry	entry;
	u32						crc;					/* must be the last journal disk item field. crc is computed up to here (not including) */

	u8 reserved1[48];
	u8 reserved2[128];

	union {
		u8 reserved3[256];
		/* This is not part of journal on-disk item, but we have to store these fields anywhere in the memory.
		   Here we have a lot of unused memory, so store them here. */
		struct {
			zjournal_end_io_func cb_func;
			void *cb_arg;
			u32 item_idx;
		};
	};

} __attribute__ ((packed));

struct zjournal_disk_item_v1 {
	u16	pool_id;
	u64	generation;
	u64	transid;
	/*struct zjournal_entry*/
	u64 subvol_treeid;
	u64 inode_num;
	u64 inode_gen;
	u64 file_offset;
	u64 address;
	u32	crc;
} __attribute__ ((packed));

struct zjournal_disk_item_v2 {
	u32 magic;					/* ZJOURNAL_DISK_ITEM_MAGIC */
	u32	version;				/* 2 */
	u16	pool_id;
	u64	generation;
	u64	transid;
	u64 io_cnt;
	/*struct zjournal_entry*/
	u64 subvol_treeid;
	u64 inode_num;
	u64 inode_gen;
	u64 file_offset;
	u64 address;
	u32 crc;
} __attribute__ ((packed));

/** 
 * @internal: IN-MEMORY STRUCTS
 */

struct zjournal_item {
	u64 transid;
	u16 pool_id;
	atomic_t lock;
};

struct zjournal_replay_item {
	int						item_idx;		/* item index in the map and on disk */
	u64						generation;		/* equal to zjournal_disk_item::generation */
	u64						transid;		/* equal to zjournal_disk_item::transid */
	u64						io_cnt;			/* equal to zjournal_disk_item::io_cnt */
	u16						tenant_id;		/* equal to zjournal_disk_item::tenant_id */
	struct zjournal_entry	entry;			/* equal to zjournal_disk_item::entry */
	struct zjournal_pool	*pool;			/* back pointer to the pool */

	u64 					new_address;	/* get from zbtrfs_blk_virt_get_chunk_for_replay */
	void					*replay_ctx;	/* get from zbtrfs_blk_virt_get_chunk_for_replay */
	
	struct list_head		lnode;			/* pool->replay_list */
	struct rb_node			rbnode;			/* __zjournal_build_replay_tree()::vaddr_tree */

	struct zjournal_work	jwork;

	u64						replay_time_ms;	/* time spent in zbtrfs_blk_virt_journal_replay_entry */
	u64						update_time_ms;	/* time spent in submit_bio_sync, if disk_item had to be updated */
};

struct zjournal_pool {
	u64 generation;			/* equal to zjournal_pool_superblock::generation, never reset, even if the pool is deleted! */
	u64 max_transid;		/* can be accessed for read only if replayed==true */
	u16 pool_id;
	atomic64_t io_cnt;

	union {
		int flags;
		struct {
			int created:1;	/* equal to zjournal_pool_superblock::created */
			int mounted:1;
			int replayed:1;
			int replay_tree_valid:1;
		};
	};

	struct btrfs_fs_info *fs_info;

	/* TODO: allocate struct zjournal_pool_replay only when replay is really needed */
	struct list_head		replay_list;		/* zjournal_replay_item */
	struct radix_tree_root	replay_tree;		/* zjournal_replay_item */
	int						replay_tree_cnt;	/* number of items in replay tree */
};

struct zjournal_globals {

	bool enable;

	char jpath[256];
	struct block_device *jdev;
	int jdev_size_blk;					/* size of the jdev, [blocks] */

	struct zjournal_item *jmap;
	int jmap_size;						/* number of items in the jmap */
	atomic_t jmap_idx;

	struct zjournal_pool pools[ZJOURNAL_MAX_POOL_ID+1];

	struct btrfs_workqueue *workers;
};
extern struct zjournal_globals globals;

/** 
 * @internal
 */

bool zjournal_map_item_try_lock(int item_idx);
void zjournal_map_item_unlock(int item_idx);
void zjournal_map_item_set(int item_idx, const struct zjournal_disk_item *disk_item);
void zjournal_map_item_reset(int item_idx);
void zjournal_map_item_reset_pool(u16 pool_id);

int zjournal_issue_zeroout(sector_t start_sector, sector_t size, gfp_t gfp_mask);
#define submit_bio_sync(rw, bio, bi_sector)	__submit_bio_sync((rw), (bio), (bi_sector), __FILE__, __FUNCTION__, __LINE__)
int __submit_bio_sync(int rw, struct bio *bio, sector_t bi_sector, const char *file, const char *func, int line);
#define zjournal_bio_map_kern(data, len, gfp_mask, rc)	__zjournal_bio_map_kern((data), (len), (gfp_mask), (rc), __FILE__, __FUNCTION__, __LINE__)
struct bio* __zjournal_bio_map_kern(void *data, unsigned int len, gfp_t gfp_mask, int *rc, const char *file, const char *func, int line);

void zjournal_pool_reset(struct zjournal_pool *pool, bool created);
void zjournal_pool_free_replay_tree(struct zjournal_pool *pool);
struct zjournal_replay_item *zjournal_pool_replay_tree_get_first(struct zjournal_pool *pool);
int zjournal_pool_replay_tree_insert_item(struct zjournal_pool *pool, struct zjournal_replay_item *ritem);
void zjournal_pool_replay_tree_delete_item(struct zjournal_pool *pool, struct zjournal_replay_item *ritem);
void zjournal_pool_free_replay_list(struct zjournal_pool *pool);

int zjournal_pool_sb_init_all(void);
int zjournal_pool_sb_read_all(void);

int zjournal_disk_item_version_convert(int item_idx, struct zjournal_disk_item *disk_item);
void zjournal_disk_item_init(struct zjournal_disk_item *disk_item, u16 pool_id, u64 generation, u64 transid, u64 io_cnt, u16 tenant_id, u64 subvol_treeid, u64 inode_num, u64 inode_gen, u64 file_offset, u64 address);
bool zjournal_disk_item_in_use(int item_idx, const struct zjournal_disk_item *disk_item);


void zjournal_report_corruption(u16 pool_id, const char *msg);

#endif /* __ZJOURNAL__ */

