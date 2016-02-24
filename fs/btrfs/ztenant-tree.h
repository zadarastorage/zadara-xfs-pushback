#ifdef CONFIG_BTRFS_ZADARA
#ifndef __ZBTRFS_ZTENANT__
#define __ZBTRFS_ZTENANT__

/*
 * This is Zadara poor-man's quota-groups implementation.
 * Instead of the complex qgroup logic, we simply stamp
 * each EXTENT_ITEM with a "tenant-id". This way, for each
 * tenant-id, we know how much capacity all its subvolumes use.
 * This is less granular than the quota groups, but it works.
 * See more info in:
 * https://github.com/zadarastorage/Zadara-VC/issues/3282
 */

/*
 * this tenant always exists; it accounts
 * for "old" volumes, which did not have
 * explicit tenant-id.
 */
#define ZBTRFS_ZTENANT_SYSTEM_ID ((u16)0)
#define ZBTRFS_ZTENANT_MAX_ID    USHRT_MAX

struct zbtrfs_ztenant_config {
	/*
	 * holds zbtrfs_ztenant_info's; protected by
	 * the below spinlock for write access, and
	 * by RCU for read access.
	 */
	struct radix_tree_root ztenants_radix;
	/* 
	 * those zbtrfs_ztenant_info's that need to be synced
	 * on next transaction commit; protected by the below
	 * lock
	 */
	struct list_head dirty_ztenants;
	spinlock_t ztenants_lock;

	/* 
	 * when transaction commit begins, and we sync
	 * the tenant info to disk, there should not be
	 * any attempts to update it (all delayed refs has
	 * been processed). and vice-versa - when there are
	 * delayed refs being procesed, nobody should try
	 * to sync the tenant info.
	 * the two fields below are used to quickly detect that.
	 */
	atomic_t updaters;
	atomic_t syncing;
};

void zbtrfs_ztenant_init_config(struct btrfs_fs_info *fs_info);
int zbtrfs_ztenant_load_config(struct btrfs_fs_info *fs_info);
void zbtrfs_ztenant_free_config(struct btrfs_fs_info *fs_info);

int zbtrfs_ztenant_create_tree_if_needed(struct btrfs_fs_info *fs_info);
int zbtrfs_ztenant_account_usage(struct btrfs_fs_info *fs_info, struct btrfs_trans_handle *trans, u16 tenant_id, s64 bytes_delta);

int zbtrfs_run_ztenants(struct btrfs_trans_handle *trans, struct btrfs_fs_info *fs_info);
void zbtrfs_ztenants_assert_uptodate(struct btrfs_fs_info *fs_info);

void zbtrfs_ztenant_get_used(struct btrfs_fs_info *fs_info, u16 tenant_id, u64 *bytes_used, u64 *bytes_used_synced);

/* sysfs */
ssize_t zbtrfs_ztenant_inmem_show(struct btrfs_fs_info *fs_info, char *buf, size_t buf_size, enum zklog_level_t level);

int zbtrfs_ztenant_init(void);
void zbtrfs_ztenant_exit(void);

#endif /*__ZBTRFS_ZTENANT__*/
#endif /*CONFIG_BTRFS_ZADARA*/

