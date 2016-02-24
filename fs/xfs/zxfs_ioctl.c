/*
 * IOCTLs added by Zadara.
 * This file is meant to be included directly from fs/xfs/xfs_ioctl.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

STATIC long xfs_ioctl_refresh_discard_gran(struct file *filp, void __user *uarg)
{
	int error = 0;
	struct xfs_ioctl_refresh_discard_gran_args arg;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct xfs_mount *mp = XFS_I(inode)->i_mount;
	struct zxfs_mount *zmp = &mp->m_zxfs;
	int frozen = SB_UNFROZEN;
	int total_discard_ranges = atomic_read(&zmp->total_discard_ranges);

	ZXFSLOG(mp, Z_KINFO, "REFRESH DISCARD GRAN");

	/* FS needs to be frozen */
	frozen = mp->m_super->s_writers.frozen;
	if (frozen != SB_FREEZE_COMPLETE ||
		!zmp->is_fs_frozen ||
		total_discard_ranges > 0) {
		ZXFSLOG(mp, Z_KWARN, "frozen=%d(SB_FREEZE_COMPLETE=%d) is_fs_frozen=%u total_discard_ranges=%d",
			    frozen, SB_FREEZE_COMPLETE, zmp->is_fs_frozen, total_discard_ranges);
		error = -EBUSY;
	} else {
		zxfs_set_discard_gran(mp);
		arg.discard_gran_sectors = zmp->discard_gran_bbs;
	}

	if (error == 0) {
		if (copy_to_user(uarg, &arg, sizeof(arg)))
			error = -EFAULT;
	}

	return error;
}

STATIC long xfs_ioctl_allow_resize(struct file *filp, void __user *uarg)
{
	int error = 0;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct xfs_mount *mp = XFS_I(inode)->i_mount;
	struct zxfs_mount *zmp = &mp->m_zxfs;
	u8 new_allowed = 0;
	int prev_allowed = 0;

	if (copy_from_user(&new_allowed, uarg, sizeof(new_allowed))) {
		error = -EFAULT;
		goto out;
	}

	new_allowed = (new_allowed != 0) ? 1 : 0;
	prev_allowed = atomic_xchg(&zmp->allow_resize, (int)new_allowed);
	ZXFSLOG(mp, Z_KINFO, "resize allowed: %d => %u", prev_allowed, new_allowed);

out:
	return error;
}

STATIC long xfs_ioctl_fake_corruption(struct file *filp)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct xfs_mount *mp = XFS_I(inode)->i_mount;

	ZXFSLOG(mp, Z_KERR, "FAKE CORRUPTION!");
	XFS_CORRUPTION_ERROR("!!!FAKE CORRUPTION!!!", XFS_ERRLEVEL_HIGH, mp, mp);

	return 0;
}

long xfs_zioctl(struct file	*filp, unsigned int	cmd, void __user *arg)
{
	switch (cmd) {
		case XFS_ZIOC_REFRESH_DISCARD_GRAN:
			return xfs_ioctl_refresh_discard_gran(filp, arg);
		case XFS_ZIOC_ALLOW_RESIZE:
			return xfs_ioctl_allow_resize(filp, arg);
		case XFS_ZIOC_FAKE_CORRUPTION:
			return xfs_ioctl_fake_corruption(filp);
	}

	return -ENOTTY;
}

