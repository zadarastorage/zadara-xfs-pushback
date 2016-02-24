/*
 * IOCTLs added by Zadara.
 * This file is meant to be included directly from fs/btrfs/ioctl.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 * If Zadara changes are ever accepted by the community, the contents of this file
 * will move into ioctl.c and this file will disappear.
 */

#include <linux/poll.h>
#include "zchanged-chunks.h"
#include "zjournal.h"

/* 
 * Note1: otransid value never changes, so no lock needed
 * Note2: each snapshot/subvol is identified with a UUID for mirroring purposes.
 *        If it was received, it is identified by its received_uuid, otherwise,
 *        this snapshot was created not by receiving, so use its uuid.
 */
#define __fill_subvol_info(root, info)                                                  \
do {                                                                                    \
	struct btrfs_root_item *root_item = &(root)->root_item;                             \
                                                                                        \
	(info)->subvol_treeid = (root)->objectid;                                           \
                                                                                        \
	(info)->otransid    = btrfs_root_otransid(root_item);                               \
	(info)->otime.sec   = btrfs_stack_timespec_sec(&root_item->otime);                  \
	(info)->otime.nsec  = btrfs_stack_timespec_nsec(&root_item->otime);                 \
                                                                                        \
	(info)->flags = 0;                                                                  \
	down_read(&(root)->fs_info->subvol_sem);                                            \
	if (btrfs_root_readonly(root))                                                      \
		(info)->flags |= BTRFS_SUBVOL_RDONLY;                                           \
	up_read(&(root)->fs_info->subvol_sem);                                              \
                                                                                        \
	if (btrfs_is_empty_uuid(root_item->received_uuid))                                  \
		memcpy((info)->received_uuid, root_item->uuid, BTRFS_UUID_SIZE);                \
	else                                                                                \
		memcpy((info)->received_uuid, root_item->received_uuid, BTRFS_UUID_SIZE);       \
                                                                                        \
	spin_lock(&(root)->root_item_lock);                                                 \
	(info)->ctransid = btrfs_root_ctransid(root_item);                                  \
	(info)->num_mapped_chunks_subvol = btrfs_root_limit(root_item);                     \
	spin_unlock(&(root)->root_item_lock);                                               \
} while (0)

/* sent to a subvolume */
static long btrfs_ioctl_get_subvol_info(struct file *file, void __user *argp)
{
	struct inode *inode = file_inode(file);
	u64 my_ino = btrfs_ino(inode);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_subvol_info_args args;
	int ret = 0;

	/* This IOCTL succeeds only if the inode is a top subvolume inode */
	if (my_ino != BTRFS_FIRST_FREE_OBJECTID) {
		ZBTRFSLOG(root->fs_info, Z_KWARN, "subvol[%llu] my_ino=%llu, not subvolume", root->objectid, my_ino);
		ret = -EINVAL;
		goto out;
	}

	memset(&args, 0, sizeof(struct btrfs_ioctl_subvol_info_args));
	__fill_subvol_info(root, &args);

	if (copy_to_user(argp, &args, sizeof(struct btrfs_ioctl_subvol_info_args)) != 0)
		ret = -EFAULT;
out:
	return ret;
}

/* sent to a block-virt file */
static long btrfs_ioctl_get_blk_virt_vol_info(struct file *file, void __user *argp)
{
	struct inode *inode = file_inode(file);
	u64 my_ino = btrfs_ino(inode);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_ioctl_blk_virt_vol_info_args args;
	u64 curr_transid = 0;
	int ret = 0;

	/*
	 * This IOCTL should only succeed if sent to a block-virt volume.
	 * Let's do some checks to attempt ensuring that.
	 */
	if (my_ino == BTRFS_FIRST_FREE_OBJECTID || btrfs_is_free_space_inode(inode) || !S_ISREG(inode->i_mode)) {
		ZBTRFSLOG(fs_info, Z_KWARN, "subvol[%llu] my_ino=%llu doesn't look like a blk-virt inode (mode=0%o)!",
			      root->objectid, my_ino, inode->i_mode);
		ret = -EINVAL;
		goto out;
	}

	if (copy_from_user(&args, argp, sizeof(args)) != 0) {
		ret = -EFAULT;
		goto out;
	}

	/* subvol info */
	__fill_subvol_info(root, &args);

	/* vol info */
	args.num_mapped_chunks_blk_virt_vol = atomic64_read(&BTRFS_I(inode)->num_mapped_bv_chunks);

	/*
	 * find out the latest transaction that has not committed yet.
	 * if we have no running transaction right now, just take the next FS generation;
	 * this will be the future transaction.
	 */
	if (fs_info->running_transaction != NULL) {
		curr_transid = fs_info->generation;
	} else {
		spin_lock(&fs_info->trans_lock);
		if (fs_info->running_transaction != NULL)
			curr_transid = fs_info->running_transaction->transid;
		else
			curr_transid = fs_info->generation + 1;
		spin_unlock(&fs_info->trans_lock);
	}
	args.num_mapped_chunks_synced_blk_virt_vol = zbtrfs_sync_bv_num_mapped_chunks(root, BTRFS_I(inode), curr_transid);

	if (args.tenant_id != ZBTRFS_ZTENANT_SYSTEM_ID) {
		zbtrfs_ztenant_get_used(fs_info, args.tenant_id, &args.bytes_used_tenant, &args.bytes_used_synced_tenant);
	} else {
		args.bytes_used_tenant = 0;
		args.bytes_used_synced_tenant = 0;
	}

	if (copy_to_user(argp, &args, sizeof(struct btrfs_ioctl_blk_virt_vol_info_args)) != 0)
		ret = -EFAULT;
out:
	return ret;
}

/* can be sent to any btrfs inode; usually sent to the mount point */
static long btrfs_ioctl_monitor_fs(struct file *file, void __user *user_arg)
{
	struct btrfs_ioctl_monitor_fs_args arg;
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	LIST_HEAD(deleted_subvols_lst);
	int rc = 0;

	if (copy_from_user(&arg, user_arg, sizeof(arg))) {
		rc = -EFAULT;
		goto out;
	}

	/* Clear the awake condition first of all */
	if (arg.is_periodic)
		zbtrfs_control_poll_reset(fs_info);

	arg.last_trans_committed = fs_info->last_trans_committed;

	/* set args.fs_state flags */
	arg.fs_state = 0;

	/* --- BTRFS_ZIOC_FS_STATE_SUPER_ERROR--- */
	if (ZBTRFS_FS_ERROR(fs_info)) {
		arg.fs_state |= BTRFS_ZIOC_FS_STATE_SUPER_ERROR;
		ZBTRFSLOG(fs_info, Z_KWARN, "Pool[%u] FSID["PRIX128"]: SUPER_ERROR", zfs_info->pool_id, PRI_UUID(fs_info->fsid));
	}

	/* --- BTRFS_ZIOC_FS_STATE_JOURNAL_CORRUPTION--- */
	if (zfs_info->report_zjournal_corruption) {
		/* Report journal corruption only once */
		zfs_info->report_zjournal_corruption = false;
		arg.fs_state |= BTRFS_ZIOC_FS_STATE_JOURNAL_CORRUPTION;
		ZBTRFSLOG(fs_info, Z_KWARN, "Pool[%u] FSSID["PRIX128"]: JOURNAL_CORRUPTION", zfs_info->pool_id, PRI_UUID(fs_info->fsid));
	}

	/* --- BTRFS_ZIOC_FS_STATE_TREE_CORRUPTION--- */
	/*
	 * once we have this bit set, we always report it.
	 */
	{
		u64 corrupted_tree_transid = atomic64_read(&zfs_info->corrupted_tree_transid);
		if (corrupted_tree_transid != 0) {
			arg.fs_state |= BTRFS_ZIOC_FS_STATE_TREE_CORRUPTION;
			ZBTRFSLOG(fs_info, Z_KWARN, "Pool[%u] fsid["PRIX128"] TREE CORRUPTION", zfs_info->pool_id, PRI_UUID(fs_info->fsid));
		}
	}

	/*** fetching deleted snapshots ***/
	{
		bool have_more = false;
		struct btrfs_ioctl_subvol_id_args __user *deleted_subvols_ubuff = NULL;
		u32 deleted_subvols_ubuff_cnt = 0;
		struct zbtrfs_deleted_subvol_info *subv_info = NULL;

		/* check if we have a buffer to fetch to */
		if (arg.deleted_subvols != NULL && arg.deleted_subvol_cnt > 0) {
			deleted_subvols_ubuff = arg.deleted_subvols;
			deleted_subvols_ubuff_cnt = arg.deleted_subvol_cnt;
		}
		/* check if we can write to the buffer */
		if (deleted_subvols_ubuff != NULL &&
			!access_ok(VERIFY_WRITE, deleted_subvols_ubuff, 
			           deleted_subvols_ubuff_cnt * sizeof(struct btrfs_ioctl_subvol_id_args))) {
			rc = -EFAULT;
			goto out;
		}

		zbtrfs_fetch_committed_deleted_subvols(fs_info,
				deleted_subvols_ubuff_cnt, &deleted_subvols_lst,
				&have_more);

		/* copy the deleted subvols one-by-one */
		arg.deleted_subvol_cnt = 0;
		list_for_each_entry(subv_info, &deleted_subvols_lst, deleted_subvols_link) {
			struct btrfs_ioctl_subvol_id_args __user *curr_ubuff = NULL;

			ZBTRFS_BUG_ON(arg.deleted_subvol_cnt >= deleted_subvols_ubuff_cnt);
			curr_ubuff = &deleted_subvols_ubuff[arg.deleted_subvol_cnt];

			if (copy_to_user(&curr_ubuff->subvol_treeid, &subv_info->root_objectid, sizeof(u64)) ||
				copy_to_user(&curr_ubuff->otransid, &subv_info->otransid, sizeof(u64))) {
				rc = -EFAULT;
				goto out;
			}

			++arg.deleted_subvol_cnt;
		}

		if (have_more)
			zbtrfs_control_poll_wake_up(fs_info, POLLIN);
	}

	rc = copy_to_user(user_arg, &arg, sizeof(arg));
	if (rc)
		rc = -EFAULT;

out:
	zbtrfs_subvol_deletion_list_free(fs_info, &deleted_subvols_lst);

	return rc;
}

/* can be sent to any btrfs inode; usually sent to the mount point */
static long btrfs_ioctl_abort_transaction(struct file *file, void __user *user_arg)
{
	int ret = 0;
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_trans_handle* trans = NULL;

	ZBTRFSLOG(fs_info, Z_KWARN, "going to abort!");

	/* if transaction has been already aborted, we will not be able to attach */
	trans = btrfs_attach_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		if (ret == -ENOENT) {
			ZBTRFSLOG(fs_info, Z_KINFO, "no ongoing transaction");
			ret = 0;
		} else {
			ZBTRFSLOG(fs_info, Z_KWARN, "btrfs_attach_transaction() ret=%d", ret);
			/* ret will indicate an error here */
		}
		trans = NULL;
	} else {
		ZBTRFSLOG(fs_info, Z_KWARN, "force-aborting transid=%llu", trans->transid);
	}

	zbtrfs_force_abort_transaction(trans, root, -EIO);

	if (trans)
		btrfs_end_transaction(trans, root);
	return ret;
}

/*
 * Should only be sent for a subvolume, which is not seen
 * from user-space anymore in the file tree.
 * Returns:
 *     0             : subvolume has already been deleted
 *     -EINPROGRESS  : subvolume is still being deleted
 *    any other error
 * @note: can be sent to any btrfs inode.
 */
static long btrfs_ioctl_is_subvolume_deleted(struct file *file, void __user *user_arg)
{
	int ret = 0;
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_ioctl_subvol_id_args arg;
	struct btrfs_root *dead_root = NULL;

	if (copy_from_user(&arg, user_arg, sizeof(arg))) {
		ret = -EFAULT;
		goto out;
	}

	spin_lock(&fs_info->trans_lock);
	list_for_each_entry(dead_root, &fs_info->dead_roots, root_list) {
		if (dead_root->objectid == arg.subvol_treeid &&
			btrfs_root_otransid(&dead_root->root_item) == arg.otransid) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "BTRFS_ZIOC_IS_SUBVOL_DELETED root=(%llu,%llu) is in dead_roots EINPROGRESS",
				          arg.subvol_treeid, arg.otransid);
			ret = -EINPROGRESS;
			break;
		}
	}
	spin_unlock(&fs_info->trans_lock);

	if (ret == 0 &&
		fs_info->zfs_info.curr_deleting_subvol_objectid == arg.subvol_treeid &&
		fs_info->zfs_info.curr_deleting_subvol_otransid == arg.otransid) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "BTRFS_ZIOC_IS_SUBVOL_DELETED root=(%llu,%llu) currently DELETING EINPROGRESS",
				      arg.subvol_treeid, arg.otransid);
		ret = -EINPROGRESS;
	}

	if (ret == 0 &&
		zbtrfs_have_deleted_subvol(fs_info, arg.subvol_treeid, arg.otransid)) {
		/*
		 * subvolume deletion was done, and may be even committed, but let VAC
		 * learn about it in the usual way.
		 */
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "BTRFS_ZIOC_IS_SUBVOL_DELETED root=(%llu,%llu) deleted, but not fetched EINPROGRESS",
		              arg.subvol_treeid, arg.otransid);
		ret = -EINPROGRESS;
	}

out:
	if (ret == 0)
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "BTRFS_ZIOC_IS_SUBVOL_DELETED root=(%llu,%llu) not found - DELETED",
		              arg.subvol_treeid, arg.otransid);

	return ret;
}

/* can be sent to any btrfs inode; usually sent to the mount point */
static long btrfs_ioctl_get_stats(struct file *file, void __user *user_arg)
{
	int ret = 0;
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_ioctl_stats_args args;

	ret = zbtrfs_ioctl_get_stats(fs_info, &args);
	if (ret == 0) {
		if (copy_to_user(user_arg, &args, sizeof(args)))
			ret = -EFAULT;
	}

	return ret;
}

struct btrfs_pending_snapshot_ex {
	/*
	 * directory, in which the snap will be created.
	 * if snap_dir_fd.file != NULL, we need to do fdput()
	 */
	struct fd snap_dir_fd;

	/* we need to mnt_drop_write_file() on snap_dir_fd.file */
	bool mnt_drop_snap_dir_fd;

	/*
	 * fd to the source subvolume, off of
	 * which we are going to create a snap.
	 * if snap_src_fd.file != NULL, we need to do fdput()
	 */
	struct fd snap_src_fd;

	/* we need to unlock snap_dir_fd.file->f_path.dentry->d_inode->i_mutex */
	bool mutex_unlock_snap_dir_fd_i_mutex;

	/* we need to btrfs_subvolume_release_metadata() and also decrement root->will_be_snapshoted */
	bool need_release_metadata;

	/* those that we have really submitted to be created */
	bool creation_attempted;

	/* will be handed to transaction */
	struct btrfs_pending_snapshot pending;

	/* pending->cre_snap_ctx will point here */
	struct zbtrfs_blk_virt_cre_snap_ctx cre_snap_ctx;
};

/* can be sent to any btrfs inode; usually sent to the mount point */
static long btrfs_ioctl_snap_create_batched(struct file *file, void __user *user_arg)
{
	int ret = 0;
	struct btrfs_fs_info *fs_info = BTRFS_I(file_inode(file))->root->fs_info;
	struct btrfs_ioctl_snap_create_batched_args args;
	struct btrfs_pending_snapshot_ex *snaps = NULL;
	unsigned int snap_idx = 0;
	char *snap_name_buff = NULL;
	struct btrfs_trans_handle *trans = NULL;
	bool need_additional_commit = false;

	/* if we are mounted read-only, let's bail out early */
	if (fs_info->sb->s_flags & MS_RDONLY) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "read-only mount!");
		ret = -EROFS;
		goto out;
	}

	/* this IOCTL is only suitable for block-virt mount */
	if (!ZBTRFS_IS_BLKVIRT_MOUNT(fs_info)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "batched snap creation is suitable only for block-virt mounts!");
		ret = -ENOTSUPP;
		goto out;
	}

	if (copy_from_user(&args, user_arg, sizeof(args)) != 0) {
		ret = -EFAULT;
		goto out;
	}

	/* nothing to do? */
	if (args.n_snaps == 0)
		goto out;

	/* we need to read and write the whole array of structures */
	if (!access_ok(VERIFY_WRITE, args.snaps, args.n_snaps * sizeof(struct btrfs_ioctl_snap_create_batched_entry))) {
		ret = -EFAULT;
		goto out;
	}

	snaps = vzalloc(args.n_snaps * sizeof(struct btrfs_pending_snapshot_ex));
	if (snaps == NULL) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "vzalloc(%u * btrfs_pending_snapshot_ex(%lu)) failed",
			          args.n_snaps, sizeof(struct btrfs_pending_snapshot_ex));
		ret = -ENOMEM;
		goto out;
	}
	/* be explicit - initialize */
	for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];

		snap->mnt_drop_snap_dir_fd = false;
		snap->mutex_unlock_snap_dir_fd_i_mutex = false;
		snap->need_release_metadata = false;
		snap->creation_attempted = false;

		snaps[snap_idx].pending.cre_snap_ctx = &snaps[snap_idx].cre_snap_ctx;
		btrfs_init_block_rsv(&snap->pending.block_rsv, BTRFS_BLOCK_RSV_TEMP);

		zbtrfs_blk_virt_cre_snap_ctx_init(&snap->cre_snap_ctx, NULL/*dm_btrfs_devpath*/, args.flush_writes_ioctl_cmd);
	}

	snap_name_buff = kmalloc((BTRFS_SUBVOL_NAME_MAX + 1) * sizeof(char), GFP_NOFS);
	if (snap_name_buff == NULL) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "kmalloc(BTRFS_SUBVOL_NAME_MAX+1) failed");
		ret = -ENOMEM;
		goto out;
	}

	/* 
	 * starting from here, we will return success
	 * to userspace, and individual error for each
	 * snapshot.
	 */
	for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];
		struct btrfs_ioctl_snap_create_batched_entry snap_arg;
		struct inode *src_inode = NULL;

		if (copy_from_user(&snap_arg, &args.snaps[snap_idx], sizeof(snap_arg)) != 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: failed copying btrfs_ioctl_snap_create_batched_entry", snap_idx);
			snap->pending.error = -EFAULT;
			continue;
		}

		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: zbtrfs_blk_virt_cre_snap_ctx_init(dm_btrfs_devpath=%s,flush_writes_ioctl_cmd=%u",
			          snap_idx, snap_arg.dm_btrfs_devpath, args.flush_writes_ioctl_cmd);
		ret = zbtrfs_blk_virt_cre_snap_ctx_init(&snap->cre_snap_ctx, snap_arg.dm_btrfs_devpath, args.flush_writes_ioctl_cmd);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: zbtrfs_blk_virt_cre_snap_ctx_init() failed ret=%d", snap_idx, ret);
			snap->pending.error = ret;
			continue;
		}

		snap->pending.readonly = (snap_arg.flags & BTRFS_SUBVOL_RDONLY) ? true : false;

		/* mnt_want_write_file on the destination directory of the snapshot */
		snap->snap_dir_fd = fdget(snap_arg.dst_dir_fd);
		if (snap->snap_dir_fd.file == NULL) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: fdget(dst_dir_fd=%lld) failed", snap_idx, snap_arg.dst_dir_fd);
			snap->pending.error = -EINVAL;
			continue;
		}
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: fdget(dst_dir_fd=%lld)=>file=%p", snap_idx, snap_arg.dst_dir_fd, snap->snap_dir_fd.file);
		if (file_inode(snap->snap_dir_fd.file)->i_sb != file_inode(file)->i_sb) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: dst_dir_fd=%lld is from another FS!", snap_idx, snap_arg.dst_dir_fd);
			snap->pending.error = -EXDEV;
			continue;
		}
		ret = mnt_want_write_file(snap->snap_dir_fd.file);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: mnt_want_write_file(dst_dir_fd=%lld) ret=%d", snap_idx, snap_arg.dst_dir_fd, ret);
			snap->pending.error = ret;
			continue;
		}
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: mnt_want_write_file(%p)", snap_idx, snap->snap_dir_fd.file);
		snap->mnt_drop_snap_dir_fd = true; /* remember to drop it */
		snap->pending.dir = snap->snap_dir_fd.file->f_path.dentry->d_inode;

		/* copy the snapshot name and verify it */
		if (snap_arg.namelen > BTRFS_SUBVOL_NAME_MAX) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: namelen(%u)>BTRFS_SUBVOL_NAME_MAX(%u)", 
				          snap_idx, snap_arg.namelen, BTRFS_SUBVOL_NAME_MAX);
			snap->pending.error = -ENAMETOOLONG;
			continue;
		}
		if (copy_from_user(snap_name_buff, snap_arg.name, snap_arg.namelen) != 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: failed copying snap_arg.name", snap_idx);
			snap->pending.error = -EFAULT;
			continue;
		}
		snap_name_buff[snap_arg.namelen] = '\0';

		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: verify snap name [%s]", snap_idx, snap_name_buff);

		if (strchr(snap_name_buff, '/')) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: invalid name[%s]", snap_idx, snap_name_buff);
			snap->pending.error = -EINVAL;
			continue;
		}
		if (snap_name_buff[0] == '.' &&
		   (snap_arg.namelen == 1 || (snap_name_buff[1] == '.' && snap_arg.namelen == 2))) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: invalid name[%s]", snap_idx, snap_name_buff);
			snap->pending.error = -EEXIST;
			continue;
		}

		/* find out the source of the snapshot and do some checks on it */
		snap->snap_src_fd = fdget(snap_arg.src_subvol_fd);
		if (snap->snap_src_fd.file == NULL) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: fdget(src_subvol_fd=%lld) failed", snap_idx, snap_arg.src_subvol_fd);
			snap->pending.error = -EINVAL;
			continue;
		}
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: fdget(src_subvol_fd=%lld)=>file=%p", snap_idx, snap_arg.src_subvol_fd, snap->snap_src_fd.file);

		src_inode = file_inode(snap->snap_src_fd.file);
		if (src_inode->i_sb != file_inode(file)->i_sb) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: src_subvol_fd=%lld is from another FS!", snap_idx, snap_arg.src_subvol_fd);
			snap->pending.error = -EXDEV;
			continue;
		}
		if (!inode_owner_or_capable(src_inode)) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: src_subvol_fd=%lld inode_owner_or_capable() failed", snap_idx, snap_arg.src_subvol_fd);
			snap->pending.error = -EPERM;
			continue;
		}
		snap->pending.root = BTRFS_I(src_inode)->root;

		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_SUBVOL_CRE, "create %s snap[%s] in [%.*s] of root[%llu]",
			          snap->pending.readonly ? "RO" : "RW", snap_name_buff,
			          snap->snap_dir_fd.file->f_path.dentry->d_name.len, snap->snap_dir_fd.file->f_path.dentry->d_name.name,
			          snap->pending.root->objectid);

		/* 
		 * before locking the destination directory mutex
		 * check that we are not locking it twice.
		 */
		{
			unsigned int tmp_idx = 0;
			for (tmp_idx = 0; tmp_idx < snap_idx; ++tmp_idx) {
				if (snaps[tmp_idx].mutex_unlock_snap_dir_fd_i_mutex &&
					snaps[tmp_idx].pending.dir == snap->pending.dir) {
					ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: not locking dir->i_mutex cause snap#%u is in the same dir", snap_idx, tmp_idx);
					break;
				}
			}
			if (tmp_idx >= snap_idx) {
				ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: mutex_lock_killable_nested(ino=%p mtx=%p)",
					          snap_idx, snap->pending.dir, &snap->pending.dir->i_mutex);
				ret = mutex_lock_killable_nested(&snap->pending.dir->i_mutex, I_MUTEX_PARENT);
				if (ret) {
					ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: mutex_lock_killable_nested(snap_dir) failed ret=%d", snap_idx, ret);
					snap->pending.error = ret;
					continue;
				}
				snap->mutex_unlock_snap_dir_fd_i_mutex = true; /* remember to unlock it */
			}
		}

		/* lookup the dentry for the new snap */
		snap->pending.dentry = lookup_one_len(snap_name_buff, snap->snap_dir_fd.file->f_path.dentry, snap_arg.namelen);
		if (IS_ERR(snap->pending.dentry)) {
			ret = PTR_ERR(snap->pending.dentry);
			snap->pending.dentry = NULL;
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: lookup_one_len(%s) failed ret=%d", snap_idx, snap_name_buff, ret);
			snap->pending.error = ret;
			continue;
		}
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: snap->pending.dentry=%p", snap_idx, snap->pending.dentry);
		if (snap->pending.dentry->d_inode) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: inode for dentry(%s) already exists", snap_idx, snap_name_buff);
			snap->pending.error = -EEXIST;
			continue;
		}
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_may_create(dir=%p,dentry=%p)", snap_idx, snap->pending.dir, snap->pending.dentry);
		ret = btrfs_may_create(snap->pending.dir, snap->pending.dentry);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_may_create() failed ret=%d", snap_idx, ret);
			snap->pending.error = ret;
			continue;
		}

		/*
		 * even if this name doesn't exist, we may get hash collisions.
		 * check for them now when we can safely fail
		 */
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_check_dir_item_collision(root=%llu,dir_ino=%lu)",
		              snap_idx, BTRFS_I(snap->pending.dir)->root->objectid, snap->pending.dir->i_ino);
		ret = btrfs_check_dir_item_collision(BTRFS_I(snap->pending.dir)->root,
						   snap->pending.dir->i_ino,
						   snap_name_buff, snap_arg.namelen);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_check_dir_item_collision(%s) failed ret=%d", snap_idx, snap_name_buff, ret);
			snap->pending.error = ret;
			continue;
		}
	}

	down_read(&fs_info->subvol_sem);

	for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];

		/* skip snapshots that errored out */
		if (snap->pending.error)
			continue;

		if (btrfs_root_refs(&BTRFS_I(snap->pending.dir)->root->root_item) == 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_root_refs(snap_dir)==0", snap_idx);
			snap->pending.error = -ECANCELED;
			continue;
		}

		if (!test_bit(BTRFS_ROOT_REF_COWS, &snap->pending.root->state)) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: src_root=%llu BTRFS_ROOT_REF_COWS not set", snap_idx, snap->pending.root->objectid);
			snap->pending.error = -EINVAL;
			continue;
		}

		atomic_inc(&snap->pending.root->will_be_snapshoted);
		smp_mb__after_atomic();

		/*
		 * normal snap creation does:
		 *
		 * btrfs_wait_nocow_write(root);
		 * ret = btrfs_start_delalloc_inodes(root, 0);
		 * btrfs_wait_ordered_extents(root, -1);
		 *
		 * but for block-virt we don't have nocow/delalloc etc, so we are good.
		 */

		/*
		 * 1 - parent dir inode
		 * 2 - dir entries
		 * 1 - root item
		 * 2 - root ref/backref
		 * 1 - root of snapshot
		 * 1 - UUID item - we don't have this
		 */
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_subvolume_reserve_metadata", snap_idx);
		ret = btrfs_subvolume_reserve_metadata(BTRFS_I(snap->pending.dir)->root,
						&snap->pending.block_rsv, 7,
						&snap->pending.qgroup_reserved,
						false);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_subvolume_reserve_metadata() ret=%d", snap_idx, ret);
			atomic_dec(&snap->pending.root->will_be_snapshoted);
			snap->pending.error = ret;
			continue;
		}
		snap->need_release_metadata = true;
	}

	ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "btrfs_start_transaction");
	trans = btrfs_start_transaction(fs_info->extent_root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "btrfs_start_transaction() failed ret=%d", ret);
		for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
			struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];

			if (snap->pending.error == 0)
				snap->pending.error = ret;
		}
	} else {
		for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
			struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];

			/* skip snapshots that errored out */
			if (snap->pending.error)
				continue;

			snap->creation_attempted = true;

			spin_lock(&fs_info->trans_lock);
			list_add_tail(&snap->pending.list, &trans->transaction->pending_snapshots);
			spin_unlock(&fs_info->trans_lock);
		}

		ret = btrfs_commit_transaction(trans, fs_info->extent_root);
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "btrfs_commit_transaction() failed ret=%d", ret);
			/* 
			 * if transaction was aborted, we should have received error statuses in all the pending snapshots.
			 * just to be safe, make sure it is so.
			 */
			for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
				struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];
				if (snap->pending.error == 0)
					snap->pending.error = ret;
			}
		}
	}

	for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];

		/* skip those that we didn't attempt to create */
		if (!snap->creation_attempted) {
			ZBTRFS_WARN_ON(snap->pending.error == 0);
			continue;
		}

		/* some of the submitted snapshots may have errored out */
		if (snap->pending.error) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "create %s snap[%.*s] of root[%llu] error=%d",
				          snap->pending.readonly ? "RO" : "RW",
				          snap->pending.dentry->d_name.len, snap->pending.dentry->d_name.name, 
				          snap->pending.root->objectid, snap->pending.error);
			continue;
		}

		/*
		 * we should not have any orphans for block-virt inodes.
		 * so if orphan cleanup fails, just proceed.
		 */
		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_orphan_cleanup(snap_root=%llu)", snap_idx, snap->pending.snap->objectid);
		ret = btrfs_orphan_cleanup(snap->pending.snap);
		if (ret)
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_orphan_cleanup() ret=%d", snap_idx, ret);

		/*
		 * If orphan cleanup did remove any orphans, it means the tree was
		 * modified and therefore the commit root is not the same as the
		 * current root anymore. This is a problem, because send uses the
		 * commit root and therefore can see inode items that don't exist
		 * in the current root anymore, and for example make calls to
		 * btrfs_iget, which will do tree lookups based on the current root
		 * and not on the commit root. Those lookups will fail, returning a
		 * -ESTALE error, and making send fail with that error. So make sure
		 * a send does not see any orphans we have just removed, and that it
		 * will see the same inodes regardless of whether a transaction
		 * commit happened before it started (meaning that the commit root
		 * will be the same as the current root) or not.
		 *
		 * AlexL-Zadara: we should not have any orphans, therefore this should not happen to us
		 */
		if (snap->pending.readonly && snap->pending.snap->node != snap->pending.snap->commit_root) {
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_orphan_cleanup() snap->node!=snap->commit_root", snap_idx);
			need_additional_commit = true;
		}
	}

	/* 
	 * if we fail somewhere during this additional commit,
	 * it should not be critical (for the snapshot creation,
	 * at least it shouldn't)
	 */
	if (ZBTRFS_WARN(need_additional_commit, "FS[%s]: doing additional commit due to orphan cleanup!", fs_info->sb->s_id)) {
		trans = btrfs_join_transaction(fs_info->extent_root);
		if (!IS_ERR(trans))
			ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	}

	for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];
		struct inode *inode = NULL;

		/* skip those that we didn't attempt to create or those that were not created */
		if (!snap->creation_attempted || snap->pending.error)
			continue;

		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_lookup_dentry()", snap_idx);
		inode = btrfs_lookup_dentry(snap->pending.dentry->d_parent->d_inode, snap->pending.dentry);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			ZBTRFS_WARN(1, "FS[%s]: snap#%u: btrfs_lookup_dentry() ret=%d", fs_info->sb->s_id, snap_idx, ret);
			/* 
			 * not sure what to do here, because snapshot really was created in btrfs,
			 * but we cannot call d_instantiate. I think it's better not to fail the snap
			 * creation here, although most probably user-space will not be able to
			 * reach the snap properly.
			 */
		} else {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: d_instantiate(dentry=%p,inode=%p)", snap_idx, snap->pending.dentry, inode);
			d_instantiate(snap->pending.dentry, inode);
		}
	}

	for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];

		if (snap->need_release_metadata) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: btrfs_subvolume_release_metadata", snap_idx);
			btrfs_subvolume_release_metadata(BTRFS_I(snap->pending.dir)->root,
				             &snap->pending.block_rsv,
				             snap->pending.qgroup_reserved);
			atomic_dec(&snap->pending.root->will_be_snapshoted);
		}

		if (snap->pending.error == 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: fsnotify_mkdir(dir=%p,dentry=%p)", snap_idx, snap->pending.dir, snap->pending.dentry);
			fsnotify_mkdir(snap->pending.dir, snap->pending.dentry);
		}
	}

	up_read(&fs_info->subvol_sem);

	/*
	 * release all the resources; move backwards in the array of snapshots, 
	 * mostly because of mutex_unlock() 
	 */
	snap_idx = args.n_snaps - 1;
	while (true) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];

		if (snap->pending.dentry) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: dput(snap->pending.dentry=%p)", snap_idx, snap->pending.dentry);
			dput(snap->pending.dentry);
		}

		if (snap->mutex_unlock_snap_dir_fd_i_mutex) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: mutex_unlock(ino=%p mtx=%p)",
				          snap_idx, snap->pending.dir, &snap->pending.dir->i_mutex);
			mutex_unlock(&snap->pending.dir->i_mutex);
		}

		if (snap->snap_src_fd.file) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: fdput(src_file=%p)", snap_idx, snap->snap_src_fd.file);
			fdput(snap->snap_src_fd);
		}

		if (snap->mnt_drop_snap_dir_fd) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: mnt_drop_write_file(%p)", snap_idx, snap->snap_dir_fd.file);
			mnt_drop_write_file(snap->snap_dir_fd.file);
		}

		if (snap->snap_dir_fd.file) {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: fdput(snap_dir_file=%p)", snap_idx, snap->snap_dir_fd.file);
			fdput(snap->snap_dir_fd);
		}

		ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_SUBVOL_CRE, "snap#%u: zbtrfs_blk_virt_cre_snap_ctx_fini", snap_idx);
		zbtrfs_blk_virt_cre_snap_ctx_fini(&snap->cre_snap_ctx);

		if (snap_idx == 0)
			break;

		--snap_idx;
	}

	/* copy individual statuses */
	for (snap_idx = 0; snap_idx < args.n_snaps; ++snap_idx) {
		struct btrfs_pending_snapshot_ex *snap = &snaps[snap_idx];
		struct btrfs_ioctl_snap_create_batched_entry __user *entry = &args.snaps[snap_idx];
		int snap_error = 0;

		if (snap->pending.error > 0)
			snap_error = ECANCELED;
		else
			snap_error = -(snap->pending.error); /* convert to user-space */

		/* this really shouldn't happen, cause we checked access_ok */
		if (copy_to_user(&entry->error, &snap_error, sizeof(snap_error)) != 0) {
			ZBTRFS_WARN(1, "FS[%s]: failed copying snap_error=%d to entry #%u", fs_info->sb->s_id, snap_error, snap_idx);
		}
	}

	ret = 0;

out:
	kfree(snap_name_buff);  /* ok to call on NULL */
	vfree(snaps);           /* ok to call on NULL */
	return ret;
}

/*
 * sent to the block-virt inode, which is the "left" inode of the read-diff operation.
 * this is the inode, which we want to ship the data for.
 */
static long btrfs_ioctl_changed_chunks(struct file *file, void __user *user_arg)
{
	int ret = 0;
	struct btrfs_ioctl_changed_chunks_args args;
	struct inode *left_inode = file_inode(file);
	struct btrfs_root *left_root = BTRFS_I(left_inode)->root;
	struct file *right_file = NULL;
	struct inode *right_inode = NULL;
	struct zbtrfs_changed_chunks_addtnl_params addtnl_params = {
		.n_chunks_in_superchunk = 1,
		.changed_chunks_lbas = NULL,
		.parent_chunks_lbas = NULL
	};

	ret = copy_from_user(&args, user_arg, sizeof(args));
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	addtnl_params.changed_chunks_lbas = args.changed_chunks_lbas;
	addtnl_params.parent_chunks_lbas = args.parent_chunks_lbas;

	/* open the "right" inode, if given */
	if (args.parent_file_path[0] != '\0') {
		right_file = filp_open(args.parent_file_path, O_RDONLY, 0/*needed only for O_CREAT*/);
		if (IS_ERR(right_file)) {
			ret = PTR_ERR(right_file);
			ZBTRFSLOG_TAG(left_root->fs_info, Z_KERR, ZKLOG_TAG_CH_CHUNKS, "open(%s) failed, ret=%d", args.parent_file_path, ret);
			right_file = NULL;
			goto out;
		}

		right_inode = file_inode(right_file);

		/* check that right_inode is from same FS */
		if (ZBTRFS_WARN(left_inode->i_sb != right_inode->i_sb,
						"FS[%s]: left_ino(%llu:%llu) but right_ino is from FS[%s]",
						left_root->fs_info->sb->s_id,
						btrfs_ino(left_inode), BTRFS_I(left_inode)->generation,
						right_inode->i_sb->s_id)) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* the prefix of btrfs_ioctl_changed_chunks_args matches zbtrfs_changed_chunks_common_params */
	SAME_OFFSET_AND_SIZE(struct btrfs_ioctl_changed_chunks_args, in_cp,					struct zbtrfs_changed_chunks_common_params, in_cp);
	SAME_OFFSET_AND_SIZE(struct btrfs_ioctl_changed_chunks_args, in_cp_size_bytes,		struct zbtrfs_changed_chunks_common_params, in_cp_size_bytes);
	SAME_OFFSET_AND_SIZE(struct btrfs_ioctl_changed_chunks_args, changed_chunks, 	    struct zbtrfs_changed_chunks_common_params, changed_superchunks);
	SAME_OFFSET_AND_SIZE(struct btrfs_ioctl_changed_chunks_args, n_changed_chunks,	    struct zbtrfs_changed_chunks_common_params, n_changed_superchunks);
	SAME_OFFSET_AND_SIZE(struct btrfs_ioctl_changed_chunks_args, out_cp,				struct zbtrfs_changed_chunks_common_params, out_cp);
	SAME_OFFSET_AND_SIZE(struct btrfs_ioctl_changed_chunks_args, out_cp_size_bytes,		struct zbtrfs_changed_chunks_common_params, out_cp_size_bytes);
	SAME_OFFSET_AND_SIZE(struct btrfs_ioctl_changed_chunks_args, end_of_data, 			struct zbtrfs_changed_chunks_common_params, end_of_data);

	ret = zbtrfs_changed_chunks(left_inode, right_inode,
		                        (struct zbtrfs_changed_chunks_common_params*)&args,
		                        &addtnl_params);
out:
	if (ret == 0) {
		/* do not bother to copy last fields, they don't change */
		ret = copy_to_user(user_arg, &args, sizeof(struct zbtrfs_changed_chunks_common_params));
		if (ret)
			ret = -EFAULT;
	}

	if (right_file)
		filp_close(right_file, NULL);

	return ret;
}

/* sent to the global control device */
static long btrfs_ioctl_zjournal_open(struct file *file, void __user *user_arg)
{
	struct btrfs_ioctl_zjournal_open_args *arg = NULL;
	int rc;

	arg = memdup_user(user_arg, sizeof(struct btrfs_ioctl_zjournal_open_args));
	if (IS_ERR(arg)) {
		rc = PTR_ERR(arg);
		arg = NULL;
		goto out;
	}

	rc = zjournal_open(arg->journal_dev_path, arg->vpsaid, arg->new_journal/*wipe_out*/, arg->new_journal/*sb_init*/);
	
out:
	kfree(arg);
	return rc;
}

/* sent to the global control device */
static long btrfs_ioctl_zjournal_close(struct file *file, void __user *user_arg)
{
	return zjournal_close(false/*force*/);
}

/* sent to the global control device */
static long btrfs_ioctl_zjournal_create_pool(struct file *file, void __user *user_arg)
{
	u16 *pool_id = NULL;
	int rc;

	pool_id = memdup_user(user_arg, sizeof(u16));
	if (IS_ERR(pool_id)) {
		rc = PTR_ERR(pool_id);
		pool_id = NULL;
		goto out;
	}

	rc = zjournal_create_pool(*pool_id);

out:
	kfree(pool_id);
	return rc;
}

/* sent to the global control device */
static long btrfs_ioctl_zjournal_delete_pool(struct file *file, void __user *user_arg)
{
	u16 *pool_id = NULL;
	int rc;

	pool_id = memdup_user(user_arg, sizeof(u16));
	if (IS_ERR(pool_id)) {
		rc = PTR_ERR(pool_id);
		pool_id = NULL;
		goto out;
	}

	rc = zjournal_delete_pool(*pool_id);

out:
	kfree(pool_id);
	return rc;
}

struct btrfs_ioctl_zjournal_write_sync {
	struct completion wait;
	int rc;
};

static void btrfs_ioctl_zjournal_write_cb(void *arg, int error)
{
	struct btrfs_ioctl_zjournal_write_sync *sync = (struct btrfs_ioctl_zjournal_write_sync*)arg;
	sync->rc = error;
	complete(&sync->wait); 
}

/* can be sent to any btrfs inode; usually sent to the mount point */
static long btrfs_ioctl_zjournal_write(struct file *file, void __user *user_arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_zjournal_write_args *arg = NULL;
	struct btrfs_ioctl_zjournal_write_sync sync;

	arg = memdup_user(user_arg, sizeof(struct btrfs_ioctl_zjournal_write_args));
	if (IS_ERR(arg)) {
		sync.rc = PTR_ERR(arg);
		arg = NULL;
		goto out;
	}

	init_completion(&sync.wait);

	zjournal_write(root->fs_info->zfs_info.pool_id, arg->subvol_treeid, arg->inode_num, arg->inode_gen, arg->file_offset, arg->address, arg->transid, arg->tenant_id, btrfs_ioctl_zjournal_write_cb, &sync);

	wait_for_completion(&sync.wait);

out:
	kfree(arg);
	return sync.rc;
}

/* can be sent to any btrfs inode; usually sent to the mount point */
static long btrfs_ioctl_zjournal_commit(struct file *file, void __user *user_arg)
{
    struct inode *inode = file_inode(file);
    struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 *transid;
	int rc;

    transid = memdup_user(user_arg, sizeof(u64));
    if (IS_ERR(transid)) {
        rc = PTR_ERR(transid);
        transid = NULL;
        goto out;
    }

    rc = zjournal_commit(root->fs_info->zfs_info.pool_id, *transid);

out:
    kfree(transid);
    return rc;
}

/*
 * ATTENTION!!!
 * This function is used both from btrfs_ioctl and btrfs_control_ioctl.
 * Some of the IOCTLs here assume that "file" is located on the BTRFS file system,
 * but this is not true, if get here through btrfs_control_ioctl.
 * We need to rework this some day, to be safer.
 */
long btrfs_fs_inode_zioctl(struct file *file, unsigned int cmd, void __user *argp)
{
	switch (cmd) {
		case BTRFS_ZIOC_GET_SUBVOL_INFO:
			return btrfs_ioctl_get_subvol_info(file, argp);
		case BTRFS_ZIOC_SEND_WITH_CHECKPOINT:
			return btrfs_ioctl_send_with_checkpoint(file, argp);
		case BTRFS_ZIOC_MONITOR_FS:
			return btrfs_ioctl_monitor_fs(file, argp);
		case BTRFS_ZIOC_ABORT_TRANS:
			return btrfs_ioctl_abort_transaction(file, argp);
		case BTRFS_ZIOC_IS_SUBVOL_DELETED:
			return btrfs_ioctl_is_subvolume_deleted(file, argp);
		case BTRFS_ZIOC_GET_STATS:
			return btrfs_ioctl_get_stats(file, argp);
		case BTRFS_ZIOC_SET_RG_MAP:
			return -ENOTSUPP;
		case BTRFS_ZIOC_SNAP_CREATE_BATCHED:
			return btrfs_ioctl_snap_create_batched(file, argp);
		case BTRFS_ZIOC_GET_BLK_VIRT_VOL_INFO:
			return btrfs_ioctl_get_blk_virt_vol_info(file, argp);
		case BTRFS_ZIOC_CHANGED_CHUNKS:
			return btrfs_ioctl_changed_chunks(file, argp);

		case BTRFS_ZJIOC_WRITE:
			return btrfs_ioctl_zjournal_write(file, argp);
		case BTRFS_ZJIOC_COMMIT:
			return btrfs_ioctl_zjournal_commit(file, argp);
	}

	return -ENOTTY;
}

long btrfs_global_control_zioctl(struct file *file, unsigned int cmd, void __user *argp)
{
	switch (cmd) {
		case BTRFS_ZJIOC_OPEN:
			return btrfs_ioctl_zjournal_open(file, argp);
		case BTRFS_ZJIOC_CLOSE:
			return btrfs_ioctl_zjournal_close(file, argp);
		case BTRFS_ZJIOC_CREATE_POOL:
			return btrfs_ioctl_zjournal_create_pool(file, argp);
		case BTRFS_ZJIOC_DELETE_POOL:
			return btrfs_ioctl_zjournal_delete_pool(file, argp);
	}

	return -ENOTTY;
}


