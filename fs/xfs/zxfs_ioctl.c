/*
 * IOCTLs added by Zadara.
 * This file is meant to be included directly from fs/xfs/xfs_ioctl.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

STATIC long xfs_ioctl_monitor_fs(struct file *filp, void __user *uarg)
{
	int error = 0;
	struct xfs_ioctl_monitor_fs_args arg;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct xfs_mount *mp = XFS_I(inode)->i_mount;
	struct zxfs_mount *zmp = &mp->m_zxfs;

	if (copy_from_user(&arg, uarg, sizeof(arg))) {
		error = -XFS_ERROR(EFAULT);
		goto out;
	}

	/* Clear the awake condition first of all */
	if (arg.is_periodic)
		zxfs_control_poll_reset(zmp);

	/* set args.fs_state flags */
	arg.fs_state = 0;

	/* --- XFS_ZIOC_FS_STATE_SHUTDOWN--- */
	{
		u64 shutdown_flags = atomic64_read(&zmp->shutdown_flags);
		if (shutdown_flags) {
			arg.fs_state |= XFS_ZIOC_FS_STATE_SHUTDOWN;
			zklog(Z_KWARN, "XFS(%s): POLL - SHUTDOWN", mp->m_fsname);
		}
	}

	if (copy_to_user(uarg, &arg, sizeof(arg)))
		error = -XFS_ERROR(EFAULT);

out:
	return error;
}

long xfs_zioctl(struct file	*filp, unsigned int	cmd, void __user *arg)
{
	switch (cmd) {
		case XFS_ZIOC_MONITOR_FS:
			return xfs_ioctl_monitor_fs(filp, arg);
	}

	return -ENOTTY;
}

