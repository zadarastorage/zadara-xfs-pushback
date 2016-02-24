#ifdef CONFIG_BTRFS_ZADARA
#ifndef __ZBTRFS_HDR__
#define __ZBTRFS_HDR__

#include <linux/cdev.h>
#include <zklog.h>

/*******************************************************/
/************** defines ********************************/
/*******************************************************/

/******** WARN_ON/BUG_ON *****************************/
/* 
 * Redefine some macros for several purposes:
 * - to identify that this BUG_ON/WARN_IN was added by Zadara, to avoid #ifdef ZADARA
 * - default WARN_ON doesn't print its condition (BUG_ON is already redefined by zklog)
 * - strigifying some conditions is not printf-friendly
 */
#define ZBTRFS_BUG(condition, format, ...) ({      \
	if (WARN(condition, format, ##__VA_ARGS__)) {  \
		BUG();                                     \
	}                                              \
})

#define ZBTRFS_BUG_ON(cond) ZBTRFS_BUG(cond, #cond)
#define ZBTRFS_WARN(condition, format, ...) WARN(condition, format, ##__VA_ARGS__)
#define ZBTRFS_WARN_ONCE(condition, format, ...) WARN_ONCE(condition, format, ##__VA_ARGS__)
#define ZBTRFS_WARN_ON(cond) ZBTRFS_WARN(cond, "ZBTRFS WARNING: " #cond)

#define ZBTRFS_WARN_ON_ONCE(cond)	({				               \
	static bool __section(.data.unlikely) __warned;		           \
	int __ret_warn_once = !!(cond);			                       \
	if (unlikely(__ret_warn_once)) {                               \
		if (!__warned) {                                           \
			ZBTRFS_WARN(cond, "ZBTRFS ONE-TIME WARNING: " #cond);  \
			__warned = true;			                           \
		}                                                          \
	}                                                              \
	unlikely(__ret_warn_once);				                       \
})

#ifdef WARN_ON
#undef WARN_ON
#endif
#define WARN_ON(cond) ZBTRFS_WARN_ON(cond)

#ifdef WARN_ON_ONCE
#undef WARN_ON_ONCE
#endif
#define WARN_ON_ONCE(cond) ZBTRFS_WARN_ON_ONCE(cond)

/*********** zklog stuff **************************/

extern zklog_tag_t ZKLOG_TAG_TR_COMP;
extern zklog_tag_t ZKLOG_TAG_SR;
extern zklog_tag_t ZKLOG_TAG_CHCKP;
extern zklog_tag_t ZKLOG_TAG_BLKVIRT;
extern zklog_tag_t ZKLOG_TAG_SUBVOL_CRE;
extern zklog_tag_t ZKLOG_TAG_SUBVOL_DEL;
extern zklog_tag_t ZKLOG_TAG_SPACE_USAGE;
extern zklog_tag_t ZKLOG_TAG_TXN;
extern zklog_tag_t ZKLOG_TAG_CHUNK_ALLOC;
extern zklog_tag_t ZKLOG_TAG_SPACE_CACHING;
extern zklog_tag_t ZKLOG_TAG_EXTENT_ALLOC;
extern zklog_tag_t ZKLOG_TAG_FREE_SP_CACHE;
extern zklog_tag_t ZKLOG_TAG_RESIZE;
extern zklog_tag_t ZKLOG_TAG_DINODE;
extern zklog_tag_t ZKLOG_TAG_ZTENANT;
extern zklog_tag_t ZKLOG_TAG_DREF;
extern zklog_tag_t ZKLOG_TAG_CH_CHUNKS;

#define ZBTRFSLOG(fs_info, level, fmt, ...)			        zklog(level, "FS[%s]: "fmt, (fs_info)->sb->s_id, ##__VA_ARGS__)
#define ZBTRFSLOG_TAG(fs_info, level, tag, fmt, ...)		zklog_tag(level, tag, "FS[%s]: "fmt, (fs_info)->sb->s_id, ##__VA_ARGS__)
#define ZBTRFSLOG_RL(fs_info, level, fmt, ...)				zklog_ratelimited(level, "FS[%s]: "fmt, (fs_info)->sb->s_id, ##__VA_ARGS__)
#define ZBTRFSLOG_TAG_RL(fs_info, level, tag, fmt, ...)	    zklog_tag_ratelimited(level, tag, "FS[%s]: "fmt, (fs_info)->sb->s_id, ##__VA_ARGS__)

/****** FS-state related **************************/

#define ZBTRFS_FS_ERROR(fs_info) test_bit(BTRFS_FS_STATE_ERROR, &(fs_info)->fs_state)

#define ZBTRFS_IS_BLKVIRT_MOUNT(fs_info)                             \
	((fs_info)->zfs_info.pool_data_devpath[0] != '\0' &&             \
	 (fs_info)->zfs_info.pool_gran_bytes > 0)

#define ZBTRFS_IS_FULL_BLKVIRT_MOUNT(fs_info)                        \
	((fs_info)->zfs_info.pool_data_devpath[0] != '\0' &&             \
	 (fs_info)->zfs_info.pool_gran_bytes > 0 &&                      \
	 (fs_info)->zfs_info.pool_id >= ZBTRFS_MIN_POOL_ID &&            \
	 (fs_info)->zfs_info.pool_id <= ZBTRFS_MAX_POOL_ID)

#define ZBTRFS_IN_UNIT_TEST() (zbtrfs_globals.is_unit_test)
#define ZBTRFS_SET_IN_UNIT_TEST(val) do { zbtrfs_globals.is_unit_test = (val); } while (0)

/*******************************************************/
/************** structures *****************************/
/*******************************************************/
struct zbtrfs_ctl_dev {
	struct cdev			cdev;
	dev_t				devno;
	struct list_head    ctl_devs_link;          /* link in zbtrfs_globals.ctl_devs list */
	bool				is_alive;
	atomic_t			open_cnt;
	atomic_t 			poll_mask;				/* mask to return in poll() */
	wait_queue_head_t	poll_wait;      		/* used for poll() */
	wait_queue_head_t	wait_cleanup;			/* used to wait until everybody is done with the device */
};

struct zbtrfs_mdata_rsv_ctx {
	/* how much we have now allocated of each kind */
	u64 metadata_and_system_bytes_allocated;
	u64 data_bytes_allocated;

	/* how much we want to reserve in total (including already-allocated) */
	u64 total_reserved_meta_system_bytes;
	/* how much we still need to reserve */
	u64 to_reserve_meta_system_bytes;
};

/*
 * After a subvol is deleted, we keep tracking
 * this information about it, until VAC fetches it.
 */
struct zbtrfs_deleted_subvol_info {
	struct list_head deleted_subvols_link;

	u64 root_objectid;    
	u64 otransid;
	u64 deletion_transid; /* deletion will commit in this transid */
};

enum zstats_txn_commit_phase {
	RUN_DELAYED_REFS_1      = 0,
	CRE_BLOCK_GROUPS,
	RUN_DELAYED_REFS_2,
	WAIT_FOR_COMMIT,
	WAIT_FOR_PREV_COMMIT,
	START_DELAL_RUN_DEL_ITEMS,
	WAIT_EXT_WRITERS,
	RUN_DEL_ITEMS_WAIT_DELAL_PO,
	WAIT_WRITERS,
	CRE_SNAPSHOTS,
	RUN_DELAYED_ITEMS,
	RUN_DELAYED_REFS_3,
	COMMIT_FS_ROOTS,
	COMMIT_COWONLY_ROOTS,
	COMMIT_COWONLY_ROOTS_ZTENANTS_SYNC, /* this phase is inside COMMIT_COWONLY_ROOTS */
	PREP_EXTENT_COMMIT,
	WRITE_AND_WAIT,
	WRITE_SUPER,

	ZSTATS_TXN_COMMIT_NUM_PHASES,
};

/* Zadara-specific part of btrfs_fs_info */
struct zbtrfs_fs_info {
	
	struct zbtrfs_ctl_dev ctl_dev;

	/*
	 * pool data device ('\0' if not specified)
	 * not needed during regular mount; needed during block-virt mount.
	 * for unit tests - needed, if you want to do real journal replay
	 * or if you are testing ReadDiff+block-virt
	 */
	char pool_data_devpath[32];           
	struct block_device *pool_data_bdev;

	/*
	 * pool granularity in bytes (0 - if not specified)
	 * must be at least PAGE_CACHE_SIZE and power of 2
	 * not needed during regular mount; needed during block-virt mount.
	 * for unit tests - needed, if you want to do real journal replay
	 */
	u32 pool_gran_bytes;

    /*
     * zcache pool_id (0 if not specified)
     * not needed during regular mount; needed during block-virt mount.
     * for unit tests - needed, if you want an operational journal, but it might
     * not do real journal replay, depending on previous parameters
     */
#define ZBTRFS_MIN_POOL_ID		1
#define ZBTRFS_MAX_POOL_ID		1023
	u16	pool_id;

	/*
	 * when we detect a tree corruption, we save here
	 * transid of the currently-running transaction.
	 */
	atomic64_t corrupted_tree_transid;
	/*
	 * until replay is completed (whether successfully or not,
	 * we are not allowed to start any activities on the FS.
	 * these fields are used to wait untul replay is completed
	 */
	wait_queue_head_t replay_completed_wait;
	bool replay_completed;

	/*	
	 * a flag that is set, when we want to report
	 * journal corruption to user-space
	 */ 
	bool report_zjournal_corruption;

	/* block-group cache-warmup tracking stuff - just for printing */
	atomic_t data_block_groups_to_warmup;
	atomic_t metadata_block_groups_to_warmup;
	atomic_t system_block_groups_to_warmup;

	/***** subvolume deletion tracking stuff *****/
	u64 curr_deleting_subvol_objectid;
	u64 curr_deleting_subvol_otransid;
	/* list is ordered in ascending transid from head to tail */
	struct list_head deleted_subvols; /* of zbtrfs_deleted_subvol_info */
	spinlock_t deleted_subvols_lock;

	/* stats */
	struct zstats {
		/* There can be at most 2 open transactions */
		struct zstats_txn_stats {
			u64 transid;
			ktime_t start_time;

			atomic_t blocked;
			ktime_t blocked_time;
			ktime_t unblocked_time;

			atomic_t committers_count;
			ktime_t commit_start_time;
			pid_t first_committer_pid;
			pid_t real_committer_pid;
			bool in_commit_flush;

			/* how many pages were flushed during "WRITE_AND_WAIT/WRITE_SUPER" phase of this transaction */
			atomic64_t npages_flushed_txn_commit;
			/* how many pages were written by this transaction in total */
			atomic64_t npages_flushed_total;

			/* how many pages were read from disk */
			u64 npages_read;

			/* how many delayed refs in transaction and total time to process them */
			atomic64_t total_delayed_ref_runtime_nsec;
			atomic64_t total_num_delayed_refs;
			/* amount of delayed refs processed during transaction commit */
			atomic64_t commit_num_delayed_refs;

			/* how much time each phase took in ms */
			atomic64_t phases[ZSTATS_TXN_COMMIT_NUM_PHASES];
		} txns[2];

		/* how many pages were read from disk; periodically zeroed */
		atomic64_t npages_read;

		/* the following stats are fetched by metering code */
		atomic64_t n_commits;
		atomic64_t total_commit_run_delayed_refs_time_ms;
		atomic64_t total_commit_writeout_time_ms;
		atomic64_t total_commit_elapsed_time_ms;
		atomic64_t max_commit_elapsed_time_ms;
		atomic64_t total_commit_bytes_flushed;
		atomic64_t re_read_marker; /* to avoid locking when fetching stats values */

		atomic64_t n_txn_joins;
		atomic64_t total_txn_join_elapsed_time_us;
		atomic64_t max_txn_join_elapsed_time_us;

		/* COW statistics */
		atomic64_t n_cow_unmapped;   /* COW done because chunk was unmapped */
		atomic64_t n_cow_mapped;     /* COW done because of snapshot */
		atomic64_t n_cow_allocator;  /* COW done because allocator requested so - obsolete */
		atomic64_t n_nocow;          /* COW was avoided */
		atomic64_t n_unmap;          /* chunk was un-mapped (un-COW'ed) */
	} zstats;
};

struct zbtrfs_globals_t {
	struct dm_kcopyd_client *kcopyd_client;
	struct kmem_cache *replay_ctx_cachep;
	struct kmem_cache *deleted_subvol_cachep;
	struct kmem_cache *send_ctx_cachep;
	struct kmem_cache *send_arg_cachep;
	struct kmem_cache *changed_chunks_ctx_cachep;
	struct kmem_cache *async_delayed_refs_cachep;

	struct class			*ctl_dev_class;
	struct file_operations	ctl_dev_fops;
	dev_t					ctl_devno;

	/* 
	 * all control devices are linked here, and this
	 * list is sorted by their minor number, in 
	 * ascending order from head to tail.
	 */
	struct list_head        ctl_devs;
	spinlock_t              ctl_devs_lock;

	/* set if right now we are in unit test */
	bool is_unit_test;
};
extern struct zbtrfs_globals_t zbtrfs_globals;

/*********************************************************/
/********** function delcarations ************************/
/*********************************************************/

/********** forward-declarations of btrfs structures ***********/
struct btrfs_transaction;
struct btrfs_trans_handle;
struct btrfs_space_info;
struct btrfs_device;
struct btrfs_key;

/****** misc stuff ****************************************/
#define ZBTRFS_TREE_CORRUPTION(fs_info)  __zbtrfs_tree_corruption(fs_info, __FILE__, __FUNCTION__, __LINE__)
void __zbtrfs_tree_corruption(struct btrfs_fs_info *fs_info, const char *file, const char *func, unsigned int line);

#define ZBTRFS_LOG_IO_ERROR(fs_info, bdev, bio, error) __zbtrfs_log_io_error(fs_info, bdev, bio, error, __FILE__, __FUNCTION__, __LINE__)
void __zbtrfs_log_io_error(struct btrfs_fs_info *fs_info, struct block_device *bdev, struct bio *bio, int error,
	                       const char *file, const char *func, unsigned int line);

void zbtrfs_notify_fs_error(struct btrfs_fs_info *fs_info);

/********* transaction-related stuff ***********/
/*
 * This aborts the transaction, even if no changes were made on behalf of it.
 * Also trans can be NULL, in which case we will still mark FS as ERROR.
 */
#define zbtrfs_force_abort_transaction(trans, root, errno)                            \
do {                                                                                  \
	__zbtrfs_force_abort_transaction((trans), (root), __func__,	__LINE__, (errno));   \
} while (0)

void __zbtrfs_force_abort_transaction(struct btrfs_trans_handle *trans,
		struct btrfs_root *root, const char *function,
		unsigned int line, int errno);

void zbtrfs_new_txn_started(struct btrfs_fs_info *fs_info, struct btrfs_transaction *new_trans);
void zbtrfs_trans_committed(struct btrfs_fs_info *fs_info, struct btrfs_transaction *cur_trans);

void ZBTRFS_TXN_START_WAIT_STARTED(struct btrfs_fs_info *fs_info, ktime_t *start);
void ZBTRFS_TXN_START_WAIT_DONE(struct btrfs_fs_info *fs_info, ktime_t *start);
void ZBTRFS_TXN_JOIN_WAIT_STARTED(struct btrfs_fs_info *fs_info, ktime_t *start);
void ZBTRFS_TXN_JOIN_WAIT_DONE(struct btrfs_fs_info *fs_info, ktime_t *start);

#define ZBTRFS_TXN_BLOCKED(fs_info, curr_trans)     __zbtrfs_txn_blocked(fs_info, curr_trans, false, __FUNCTION__, __LINE__)
#define ZBTRFS_TXN_IN_COMMIT(fs_info, curr_trans)   __zbtrfs_txn_blocked(fs_info, curr_trans, true,  __FUNCTION__, __LINE__)
void __zbtrfs_txn_blocked(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans, bool in_commit, const char* func, unsigned int line);

void ZBTRFS_TXN_COMMIT_PHASE_STARTED(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans, ktime_t *start, enum zstats_txn_commit_phase phase);
void ZBTRFS_TXN_COMMIT_PHASE_DONE(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans, ktime_t *start, enum zstats_txn_commit_phase phase);

void zbtrfs_async_run_delayed_refs(struct btrfs_root *root, unsigned long count, u64 transid);
void zbtrfs_account_delayed_ref_runtime(struct btrfs_fs_info *fs_info, u64 transid, u64 runtime_nsec, u64 count);
int zbtrfs_assert_no_delayed_refs(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans);

/****** snapshot deletion tracking stuff *******************/
void zbtrfs_set_deleting_subvol(struct btrfs_fs_info *fs_info, struct btrfs_root *root);
int zbtrfs_subvol_deletion_will_commit(struct btrfs_fs_info *fs_info, struct btrfs_trans_handle* trans);
void zbtrfs_reset_deleting_subvol(struct btrfs_fs_info *fs_info);
void zbtrfs_subvol_deletion_committed(struct btrfs_fs_info *fs_info, struct btrfs_transaction *cur_trans);
void zbtrfs_subvol_deletion_list_free(struct btrfs_fs_info *fs_info, struct list_head *deleted_subvols);
void zbtrfs_fetch_committed_deleted_subvols(struct btrfs_fs_info *fs_info, u32 max_subvols_to_fetch,
	                 struct list_head *out_list, bool *have_more);
bool zbtrfs_have_deleted_subvol(struct btrfs_fs_info *fs_info, u64 root_objectid, u64 otransid);

/****** allocation-related stuff ***************/

#define ZBTRFS_GLOBAL_RSV_SLACK_BYTES (64*ONE_MB)
#define ZBTRFS_METADATA_SLACK_BYTES   (64*ONE_MB)

u64 zbtrfs_adjust_bytes_may_use_space_info_spinlocked(struct btrfs_fs_info *fs_info, struct btrfs_space_info *space_info,
                                                      u64 *global_rsv_size, u64 *global_rsv_reserved);

struct btrfs_space_info* zbtrfs_find_space_info(struct btrfs_fs_info *fs_info, u64 type);
struct btrfs_block_group_cache *zbtrfs_lookup_first_block_group(struct btrfs_fs_info *info, u64 bytenr);
void zbtrfs_block_group_warmup_init(struct btrfs_block_group_cache *block_group);
void zbtrfs_block_group_warmup_finished(struct btrfs_block_group_cache *block_group);

/* print zbtrfs_mdata_rsv_ctx */
#define ZBTRFS_MDATA_RSV_CTX_FMT "[r=%llu(%lluMB)/%llu(%lluGB) msa=%llu(%lluMB) da=%llu(%lluGB) ua=%llu(%lluGB) tr=%llu(%lluMB)]"
#define ZBTRFS_MDATA_RSV_CTX_PRINT(ctx, device)                                                                                      \
	(ctx)->total_reserved_meta_system_bytes, BYTES_TO_MB((ctx)->total_reserved_meta_system_bytes),                                   \
	btrfs_device_get_total_bytes(device), BYTES_TO_GB(btrfs_device_get_total_bytes(device)),                                         \
	(ctx)->metadata_and_system_bytes_allocated, BYTES_TO_MB((ctx)->metadata_and_system_bytes_allocated),                             \
	(ctx)->data_bytes_allocated, BYTES_TO_GB((ctx)->data_bytes_allocated),                                                           \
	btrfs_device_get_total_bytes(device) - (ctx)->metadata_and_system_bytes_allocated - (ctx)->data_bytes_allocated,                 \
	BYTES_TO_GB(btrfs_device_get_total_bytes(device) - (ctx)->metadata_and_system_bytes_allocated - (ctx)->data_bytes_allocated),    \
	(ctx)->to_reserve_meta_system_bytes, BYTES_TO_MB((ctx)->to_reserve_meta_system_bytes)

/* device-extent allocation */
int zbtrfs_find_free_dev_extent(struct btrfs_trans_handle *trans,
			 struct btrfs_device *device, u64 num_bytes, u64 alloc_type,
			 u64 *start, u64 *len);
void zbtrfs_mdata_rsv_ctx_init(struct zbtrfs_mdata_rsv_ctx *ctx, struct btrfs_device *device, bool for_shrink);
void zbtrfs_adjust_free_dev_extent(struct zbtrfs_mdata_rsv_ctx *ctx,
		struct btrfs_device *device,
		u64 extent_start, u64 extent_size, u64 requested_alloc_size, u64 alloc_type,
		u64 *adjusted_extent_start, u64 *adjusted_extent_size);
void zbtrfs_adjust_free_dev_extent_final(struct zbtrfs_mdata_rsv_ctx *ctx,
		struct btrfs_device *device,
		u64 extent_start, u64 extent_size, u64 alloc_type,
		u64 *adjusted_extent_start, u64 *adjusted_extent_size);

/* shrink */
int zbtrfs_shrink_device(struct btrfs_device *device, u64 new_size);
int zbtrfs_set_block_group_ro(struct btrfs_block_group_cache *cache, int *was_rw);

/*********** send/receive-related stuff ********************************/
void zbtrfs_root_dec_send_in_progress(struct btrfs_root *root);
struct btrfs_path *zbtrfs_alloc_path_for_send(void);

/********* block-virt flow *************************/
#define ZBTRFS_ZSTATS_COW_UNMAPPED(fs_info)    atomic64_inc(&(fs_info)->zfs_info.zstats.n_cow_unmapped)
#define ZBTRFS_ZSTATS_COW_MAPPED(fs_info)      atomic64_inc(&(fs_info)->zfs_info.zstats.n_cow_mapped)
#define ZBTRFS_ZSTATS_COW_ALLOCATOR(fs_info)   atomic64_inc(&(fs_info)->zfs_info.zstats.n_cow_allocator)
#define ZBTRFS_ZSTATS_NOCOW(fs_info, count)    atomic64_add((count), &(fs_info)->zfs_info.zstats.n_nocow)
#define ZBTRFS_ZSTATS_UNMAP(fs_info)           atomic64_inc(&(fs_info)->zfs_info.zstats.n_unmap)

int zbtrfs_alloc_reserved_file_extent(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     u64 root_objectid, u64 owner,
				     u64 offset, struct btrfs_key *ins,
				     u16 tenant_id);
void zbtrfs_update_root_on_cow(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root, int mod_chunk_alloc);
u64 zbtrfs_sync_bv_num_mapped_chunks(struct btrfs_root *root, struct btrfs_inode *binode, u64 curr_transid);
void zbtrfs_update_blk_virt_inode_on_cow(struct btrfs_trans_handle *trans,
				struct btrfs_root *root, struct inode *inode,
				int mod_chunk_alloc);

/********* per-FS sysfs stuff **********************/
void zbtrfs_sysfs_init(struct btrfs_fs_info *fs_info);
void zbtrfs_sysfs_start(struct btrfs_fs_info *fs_info, const char *name);
void zbtrfs_sysfs_stop(struct btrfs_fs_info *fs_info);
void zbtrfs_sysfs_fini(struct btrfs_fs_info *fs_info);
ssize_t zbtrfs_show_space_info_spinlocked(struct btrfs_fs_info *fs_info, struct btrfs_space_info *si, 
	                                      char *buf, size_t buf_size,
	                                      const char *msg, 
	                                      enum zklog_level_t level, zklog_tag_t tag);

/********* per-FS info init/exit stuff **********************/
void zbtrfs_fs_info_init(struct btrfs_fs_info *fs_info, const char *mount_dev_name);
int zbtrfs_fs_info_start1(struct btrfs_fs_info *fs_info, u64 latest_trans_before_mount);
int zbtrfs_fs_info_start2(struct btrfs_fs_info *fs_info);
void zbtrfs_fs_info_stop(struct btrfs_fs_info *fs_info);
void zbtrfs_fs_info_fini(struct btrfs_fs_info *fs_info);
void zbtrfs_wait_for_journal_replay(struct btrfs_fs_info *fs_info);

/********* per-FS control device stuff **********************/
void zbtrfs_control_init(struct btrfs_fs_info *fs_info);
int zbtrfs_control_start(struct btrfs_fs_info *fs_info);
void zbtrfs_control_stop(struct btrfs_fs_info *fs_info);
void zbtrfs_control_fini(struct btrfs_fs_info *fs_info);
void zbtrfs_control_poll_wake_up(struct btrfs_fs_info *fs_info, int poll_mask);
void zbtrfs_control_poll_reset(struct btrfs_fs_info *fs_info);

/********* our IOCTL entry points **************************/
long btrfs_fs_inode_zioctl(struct file *file, unsigned int cmd, void __user *argp);
long btrfs_global_control_zioctl(struct file *file, unsigned int cmd, void __user *argp);

/*********** stats **************************************/
void zbtrfs_zstats_init(struct btrfs_fs_info *fs_info);
int zbtrfs_ioctl_get_stats(struct btrfs_fs_info *fs_info, struct btrfs_ioctl_stats_args *args);
ssize_t zbtrfs_zstats_show(struct btrfs_fs_info *fs_info, char *buf, size_t buf_size);
void zbtrfs_metadata_page_flushed(struct btrfs_fs_info *fs_info, u64 transid);
void zbtrfs_metadata_page_read(struct btrfs_fs_info *fs_info, unsigned int npages);

/********** global stuff init/exit ****************/
int zbtrfs_globals_control_init(void);
void zbtrfs_globals_control_exit(void);

/* sizes for kmem_cache initializations */
size_t zbtrfs_replay_ctx_size(void);
size_t zbtrfs_send_ctx_size(void);
size_t zbtrfs_send_arg_size(void);
size_t zbtrfs_changed_chunks_ctx_size(void);
size_t zbtrfs_async_delayed_refs_size(void);

int zinit_btrfs_fs(void);
void zexit_btrfs_fs(void);

#endif /*__ZBTRFS_HDR__*/
#endif /*CONFIG_BTRFS_ZADARA*/

