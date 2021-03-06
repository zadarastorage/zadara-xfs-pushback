#ifdef CONFIG_XFS_ZADARA
#include "xfs.h"
#include "xfs_sb.h"
#include "xfs_ag.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_error.h"
#include <linux/poll.h>

#define ZXFS_CONTROL_DEVICE_NAME "zxfs"
#define MAX_MINORS (1U << MINORBITS)
#define MAX_MINOR   MINORMASK

STATIC int alloc_ctl_minor(struct zxfs_ctl_dev *ctl_dev) 
{
	int error = 0;
	int major = MAJOR(zxfs_globals.ctl_base_devno);
	struct zxfs_ctl_dev *prev_ctl_dev = NULL, *curr_ctl_dev = NULL;
	int prev_ctl_dev_minor = 0;

	if (ZXFS_WARN_ON(major == 0)) {
		error = -ECANCELED;
		goto out;
	}

	spin_lock(&zxfs_globals.ctl_devs_lock);

	/* if the list is empty, just take minor=0 */
	if (list_empty(&zxfs_globals.ctl_devs)) {
		ctl_dev->devno = MKDEV(major, 0);
		list_add_tail(&ctl_dev->ctl_devs_link, &zxfs_globals.ctl_devs);
		zklog(Z_KDEB2, "ctl_devs list is empty, res=(%d,%d)", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));
		goto unlock;
	}

	/* go to the last entry, and take one last+1 */
	prev_ctl_dev = list_entry(zxfs_globals.ctl_devs.prev, struct zxfs_ctl_dev, ctl_devs_link);
	prev_ctl_dev_minor = MINOR(prev_ctl_dev->devno);
	if (prev_ctl_dev_minor < MAX_MINOR) {
		ctl_dev->devno = MKDEV(major, prev_ctl_dev_minor + 1);
		list_add_tail(&ctl_dev->ctl_devs_link, &zxfs_globals.ctl_devs); /* keep the list sorted */
		zklog(Z_KDEB2, "last=(%d,%d) res=(%d,%d)", 
			  MAJOR(prev_ctl_dev->devno), MINOR(prev_ctl_dev->devno),
			  MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));
		goto unlock;
	}

	/* search for the hole */
	prev_ctl_dev_minor = -1;
	list_for_each_entry(curr_ctl_dev, &zxfs_globals.ctl_devs, ctl_devs_link) {
		int curr_ctl_dev_minor = MINOR(curr_ctl_dev->devno);

		if (curr_ctl_dev_minor > prev_ctl_dev_minor + 1) {
			ctl_dev->devno = MKDEV(major, prev_ctl_dev_minor + 1);
			list_add_tail(&ctl_dev->ctl_devs_link, &curr_ctl_dev->ctl_devs_link); /* keep the list sorted */
			zklog(Z_KDEB2, "prev_minor=%d curr=(%d,%d) res=(%d,%d)",
				  prev_ctl_dev_minor, MAJOR(curr_ctl_dev->devno), MINOR(curr_ctl_dev->devno),
				  MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));
			goto unlock;
		}

		zklog(Z_KDEB2, "prev_minor=%d curr=(%d,%d) keep searching",
			  prev_ctl_dev_minor, MAJOR(curr_ctl_dev->devno), MINOR(curr_ctl_dev->devno));
		prev_ctl_dev_minor = curr_ctl_dev_minor;
	}

	/* no holes */
	error = -EOVERFLOW;

unlock:
	spin_unlock(&zxfs_globals.ctl_devs_lock);

out:
	if (error) {
		ctl_dev->devno = 0;
	} else {
		ZXFS_BUG_ON(MAJOR(ctl_dev->devno) == 0);
		ZXFS_BUG_ON(MAJOR(ctl_dev->devno) != major);
		ZXFS_BUG_ON(MINOR(ctl_dev->devno) > MAX_MINOR);
	}

	return error;
}

STATIC void free_ctl_minor(struct zxfs_ctl_dev *ctl_dev)
{
	spin_lock(&zxfs_globals.ctl_devs_lock);
	if (!list_empty(&ctl_dev->ctl_devs_link))
		list_del_init(&ctl_dev->ctl_devs_link);
	spin_unlock(&zxfs_globals.ctl_devs_lock);
}

/* init the per-FS control device structure */
void zxfs_control_init(struct zxfs_mount *zmp)
{
	struct zxfs_ctl_dev *ctl_dev = &zmp->m_ctl_dev;

	ctl_dev->devno = 0;
	INIT_LIST_HEAD(&ctl_dev->ctl_devs_link);

	ctl_dev->is_alive = false;
	atomic_set(&ctl_dev->open_cnt, 0);
	atomic_set(&ctl_dev->poll_mask, 0);
	init_waitqueue_head(&ctl_dev->poll_wait);
	init_waitqueue_head(&ctl_dev->wait_cleanup);
}

/* 
 * create & start the control device for this FS.
 */
int zxfs_control_start(xfs_mount_t *mp)
{
	int error = 0;
	struct zxfs_mount *zmp = &mp->m_zxfs;
	struct zxfs_ctl_dev *ctl_dev = &zmp->m_ctl_dev;
	struct device *device = NULL;

	error = alloc_ctl_minor(ctl_dev);
	if (error) {
		ZXFSLOG(mp, Z_KERR, "alloc_ctl_minor() error=%d", error);
		goto out;
	}

	cdev_init(&ctl_dev->cdev, &zxfs_globals.ctl_dev_fops);
	ctl_dev->cdev.owner = THIS_MODULE;

	ZXFSLOG(mp, Z_KINFO, "create CTL dev(%d,%d)", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));

	error = cdev_add(&ctl_dev->cdev, ctl_dev->devno, 1);
	if (error != 0) {
		ZXFSLOG(mp, Z_KERR, "cdev_add(devno=(%d,%d)) failed, error=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), error);
		free_ctl_minor(ctl_dev);
		goto out;
	}

	device = device_create(zxfs_globals.ctl_dev_class, NULL/*parent*/, ctl_dev->devno, NULL/*drvdata*/, ZXFS_CONTROL_DEVICE_NAME"-%s", mp->m_fsname);
	if (IS_ERR(device)) {
		error = PTR_ERR(device);
		ZXFSLOG(mp, Z_KERR, "device_create(devno=(%d,%d)) failed, errror=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), error);
		cdev_del(&ctl_dev->cdev);
		free_ctl_minor(ctl_dev);
		goto out;
	}

	ctl_dev->is_alive = true;

out:
	return error;
}

/*
 * Tear down the control device of this FS.
 */
void zxfs_control_stop(xfs_mount_t *mp)
{
	struct zxfs_mount *zmp = &mp->m_zxfs;
	struct zxfs_ctl_dev *ctl_dev = &zmp->m_ctl_dev;
	
	if (!ctl_dev->is_alive)
		return;

	ctl_dev->is_alive = false;

	/* if anybody is sleeping on poll, wake him up */
	zxfs_control_poll_wake_up(zmp, POLLHUP);

	/* wait until everybody is done with the device */
	while (atomic_read(&ctl_dev->open_cnt) > 0) {
		ZXFSLOG(mp, Z_KWARN, "control device still open: open_cnt=%d", atomic_read(&ctl_dev->open_cnt));
		wait_event_timeout(ctl_dev->wait_cleanup, atomic_read(&ctl_dev->open_cnt) == 0, 30 * HZ);
	}

	ZXFSLOG(mp, Z_KDEB1, "destroy CTL dev(devno=(%d,%d))", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));
	device_destroy(zxfs_globals.ctl_dev_class, ctl_dev->devno);
	cdev_del(&ctl_dev->cdev);
	free_ctl_minor(ctl_dev);
}

void zxfs_control_fini(struct zxfs_mount *zmp)
{
}

void zxfs_control_poll_wake_up(struct zxfs_mount *zmp, int poll_mask)
{
	struct zxfs_ctl_dev *ctl_dev = &zmp->m_ctl_dev;
	
	atomic_or(poll_mask, &ctl_dev->poll_mask);
	if (ctl_dev->is_alive)
		wake_up(&ctl_dev->poll_wait);
}

void zxfs_control_poll_reset(struct zxfs_mount *zmp)
{
	struct zxfs_ctl_dev *ctl_dev = &zmp->m_ctl_dev;

	atomic_set(&ctl_dev->poll_mask, 0);
}

STATIC unsigned int zxfs_control_poll(struct file *filp, struct poll_table_struct *pt)
{
	xfs_mount_t *mp = (xfs_mount_t*)filp->private_data;
	struct zxfs_mount *zmp = &mp->m_zxfs;
	struct zxfs_ctl_dev *ctl_dev = &zmp->m_ctl_dev;
	unsigned int mask = 0;

	if (!ctl_dev->is_alive) {
		mask = POLLHUP;		/* device has been already unregistered */
	} else {
		poll_wait(filp, &ctl_dev->poll_wait, pt);
		if (!ctl_dev->is_alive)
			mask = POLLHUP;	/* device has been already unregistered */
		else
			mask = atomic_read(&ctl_dev->poll_mask);
	}

	ZXFSLOG(mp, Z_KDEB1, "poll(devno=(%d,%d)): poll_mask=%#x", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), mask);

	return mask;
}

STATIC int zxfs_control_release(struct inode *inode, struct file *filp)
{
	struct zxfs_ctl_dev *ctl_dev = container_of(inode->i_cdev, struct zxfs_ctl_dev, cdev);
	struct zxfs_mount *zmp = container_of(ctl_dev, struct zxfs_mount, m_ctl_dev);
	xfs_mount_t *mp = container_of(zmp, xfs_mount_t, m_zxfs);
	int open_cnt = 0;

	ZXFS_BUG_ON(&zmp->m_ctl_dev != ctl_dev);

	open_cnt = atomic_dec_if_positive(&ctl_dev->open_cnt);
	ZXFS_WARN_ON(open_cnt < 0);
	ZXFSLOG(mp, Z_KDEB1, "release(devno=(%d,%d)): open_cnt=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), open_cnt);
	if (open_cnt == 0)
		wake_up(&ctl_dev->wait_cleanup);

	return 0;
}

STATIC int zxfs_control_open(struct inode *inode, struct file *filp)
{
	struct zxfs_ctl_dev *ctl_dev = container_of(inode->i_cdev, struct zxfs_ctl_dev, cdev);
	struct zxfs_mount *zmp = container_of(ctl_dev, struct zxfs_mount, m_ctl_dev);
	xfs_mount_t *mp = container_of(zmp, xfs_mount_t, m_zxfs);
	int open_cnt = 0;

	if (!ctl_dev->is_alive) {
		ZXFSLOG(mp, Z_KWARN, "open(devno=(%d,%d)): is_alive=%u", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), ctl_dev->is_alive);
		return -ENODEV;
	}

	filp->private_data = mp;
	open_cnt = atomic_inc_return(&ctl_dev->open_cnt);
	ZXFSLOG(mp, Z_KDEB1, "open(devno=(%d,%d)): open_cnt=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), open_cnt);
	
	return 0;
}

STATIC long xfs_control_ioctl_monitor_fs(xfs_mount_t *mp, void __user *uarg)
{
	int error = 0;
	struct zxfs_mount *zmp = &mp->m_zxfs;
	struct xfs_ioctl_monitor_fs_args arg;

	if (copy_from_user(&arg, uarg, sizeof(arg))) {
		error = -EFAULT;
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
			ZXFSLOG(mp, Z_KWARN, "POLL - SHUTDOWN");
		}
	}
	/* --- XFS_ZIOC_FS_CORRUPTED --- */
	if (atomic_read(&zmp->corruption_detected) != 0) {
		arg.fs_state |= XFS_ZIOC_FS_CORRUPTED;
		ZXFSLOG(mp, Z_KDEB1, "POLL - CORRUPTION");
	}

	if (copy_to_user(uarg, &arg, sizeof(arg))){
		error = -EFAULT;
	}

out:
	return error;
}

STATIC long zxfs_control_ioctl(struct file *filp, unsigned int cmd, unsigned long p)
{
	int error = 0;
	xfs_mount_t *mp = (xfs_mount_t*)filp->private_data;
	void __user *arg = (void __user *)p;

	switch (cmd) {
		case XFS_ZIOC_MONITOR_FS:
			error = xfs_control_ioctl_monitor_fs(mp, arg);
			break;
		default:
			error = -ENOTTY;
			break;
	}

	return error;
}

int zxfs_globals_control_init(void)
{
	int error = 0;

	/* all this stuff should fit into "int" */
	BUILD_BUG_ON((u64)MAX_MINORS > (u64)INT_MAX);
	BUILD_BUG_ON((u64)MAX_MINOR > (u64)INT_MAX);

	/* to distinguish a failure */
	zxfs_globals.ctl_base_devno = 0;

	INIT_LIST_HEAD(&zxfs_globals.ctl_devs);
	spin_lock_init(&zxfs_globals.ctl_devs_lock);

	zxfs_globals.ctl_dev_class = class_create(THIS_MODULE, ZXFS_CONTROL_DEVICE_NAME);
	if (IS_ERR(zxfs_globals.ctl_dev_class)) {
		error = PTR_ERR(zxfs_globals.ctl_dev_class);
		zxfs_globals.ctl_dev_class = NULL;
		zklog(Z_KERR, "class_create() failed, error=%d", error);
		goto out;
	}

	/* 
	 * note that in alloc_chrdev_region count is unsigned,
	 * but in __register_chrdev_region, which is called by it,
	 * it becomes int.
	 */
	error = alloc_chrdev_region(&zxfs_globals.ctl_base_devno, 0/*baseminor*/, MAX_MINORS/*count*/, ZXFS_CONTROL_DEVICE_NAME);
	if (error != 0) {
		zxfs_globals.ctl_base_devno = 0; /* just to be safe */
		zklog(Z_KERR, "alloc_chrdev_region() failed, error=%d", error);
		goto out;
	}
	if (MAJOR(zxfs_globals.ctl_base_devno) == 0 || MINOR(zxfs_globals.ctl_base_devno) != 0) {
		zklog(Z_KERR, "alloc_chrdev_region(): picked major=%u(must be non-zero) minor=%u(must be zero)",
			  MAJOR(zxfs_globals.ctl_base_devno), MINOR(zxfs_globals.ctl_base_devno));
		error = -EILSEQ;
		goto out;
	}

	zklog(Z_KINFO, "major for control devices: %u", MAJOR(zxfs_globals.ctl_base_devno));

	zxfs_globals.ctl_dev_fops.open           = zxfs_control_open;
	zxfs_globals.ctl_dev_fops.unlocked_ioctl = zxfs_control_ioctl;
	zxfs_globals.ctl_dev_fops.release        = zxfs_control_release;
	zxfs_globals.ctl_dev_fops.poll           = zxfs_control_poll;

out:
	if (error != 0)
		zxfs_globals_control_exit();

	return error;
}

void zxfs_globals_control_exit(void)
{
	ZXFS_WARN_ON(!list_empty(&zxfs_globals.ctl_devs));

	if (zxfs_globals.ctl_base_devno != 0) {
		unregister_chrdev_region(zxfs_globals.ctl_base_devno, MAX_MINORS/*count*/);
		zxfs_globals.ctl_base_devno = 0;
	}

	if (zxfs_globals.ctl_dev_class != NULL) {
		class_destroy(zxfs_globals.ctl_dev_class);
		zxfs_globals.ctl_dev_class = NULL;
	}
}

#endif /*CONFIG_XFS_ZADARA*/

