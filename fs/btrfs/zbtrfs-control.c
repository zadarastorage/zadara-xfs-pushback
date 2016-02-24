#ifdef CONFIG_BTRFS_ZADARA
#include <linux/device.h>
#include <linux/poll.h>
#include "ctree.h"

#define ZBTRFS_CONTROL_DEVICE_NAME	"zbtrfs"
#define MAX_MINORS (1U << MINORBITS)
#define MAX_MINOR   MINORMASK

static int zbtrfs_control_open(struct inode *inode, struct file *filp);
static int zbtrfs_control_release(struct inode *inode, struct file *filp);
static unsigned int zbtrfs_control_poll(struct file *filp, struct poll_table_struct *pt);

/********* Global stuff *****************/

int zbtrfs_globals_control_init(void)
{
	int rc;

	/* all this stuff should fit into "int" */
	BUILD_BUG_ON((u64)MAX_MINORS > (u64)INT_MAX);
	BUILD_BUG_ON((u64)MAX_MINOR > (u64)INT_MAX);

	INIT_LIST_HEAD(&zbtrfs_globals.ctl_devs);
	spin_lock_init(&zbtrfs_globals.ctl_devs_lock);

	zbtrfs_globals.ctl_dev_class = class_create(THIS_MODULE, ZBTRFS_CONTROL_DEVICE_NAME);
	if (unlikely(IS_ERR(zbtrfs_globals.ctl_dev_class))) {
		rc = PTR_ERR(zbtrfs_globals.ctl_dev_class);
		zbtrfs_globals.ctl_dev_class = NULL;
		goto out;
	}

	/*
	 * we used to ask here for ZBTRFS_MAX_POOL_ID+1 minors, because we used to create
	 * control devices only for block-virt mounts.
	 * but now we create a control device for any mount, so we ask for MAX_MINORS.
	 */
	rc = alloc_chrdev_region(&zbtrfs_globals.ctl_devno, 0/*baseminor*/, MAX_MINORS/*count*/, ZBTRFS_CONTROL_DEVICE_NAME);
	if (unlikely(rc!=0)) {
		zbtrfs_globals.ctl_devno = 0;
		zklog(Z_KERR, "alloc_chrdev_region() failed, rc=%d", rc);
		goto out;
	}
	if (MAJOR(zbtrfs_globals.ctl_devno) == 0 || MINOR(zbtrfs_globals.ctl_devno) != 0) {
		zklog(Z_KERR, "alloc_chrdev_region(): picked major=%u(must be non-zero) minor=%u(must be zero)",
			  MAJOR(zbtrfs_globals.ctl_devno), MINOR(zbtrfs_globals.ctl_devno));
		rc = -EILSEQ;
		goto out;
	}

	zklog(Z_KINFO, "major for control devices: %u", MAJOR(zbtrfs_globals.ctl_devno));

	zbtrfs_globals.ctl_dev_fops.open           = zbtrfs_control_open;
	zbtrfs_globals.ctl_dev_fops.release        = zbtrfs_control_release;
	zbtrfs_globals.ctl_dev_fops.poll           = zbtrfs_control_poll;

	rc = 0;

out:
	if (unlikely(rc!=0))
		zbtrfs_globals_control_exit();

	return rc;
}

void zbtrfs_globals_control_exit(void)
{
	ZBTRFS_WARN_ON(!list_empty(&zbtrfs_globals.ctl_devs));

	if (zbtrfs_globals.ctl_devno!=0) {
		unregister_chrdev_region(zbtrfs_globals.ctl_devno, MAX_MINORS/*count*/);
		zbtrfs_globals.ctl_devno = 0;
	}

	if (zbtrfs_globals.ctl_dev_class!=NULL) {
		class_destroy(zbtrfs_globals.ctl_dev_class);
		zbtrfs_globals.ctl_dev_class = NULL;
	}
}

/********** Per-FS stuff *******************/
static int alloc_ctl_minor(struct zbtrfs_ctl_dev *ctl_dev) 
{
	int ret = 0;
	int major = MAJOR(zbtrfs_globals.ctl_devno);
	struct zbtrfs_ctl_dev *prev_ctl_dev = NULL, *curr_ctl_dev = NULL;
	int prev_ctl_dev_minor = 0;

	if (ZBTRFS_WARN_ON(major == 0)) {
		ret = -ECANCELED;
		goto out;
	}

	spin_lock(&zbtrfs_globals.ctl_devs_lock);

	/* if the list is empty, just take minor=0 */
	if (list_empty(&zbtrfs_globals.ctl_devs)) {
		ctl_dev->devno = MKDEV(major, 0);
		list_add_tail(&ctl_dev->ctl_devs_link, &zbtrfs_globals.ctl_devs);
		zklog(Z_KDEB2, "ctl_devs list is empty, res=(%d,%d)", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));
		goto unlock;
	}

	/* go to the last entry, and take one last+1 */
	prev_ctl_dev = list_entry(zbtrfs_globals.ctl_devs.prev, struct zbtrfs_ctl_dev, ctl_devs_link);
	prev_ctl_dev_minor = MINOR(prev_ctl_dev->devno);
	if (prev_ctl_dev_minor < MAX_MINOR) {
		ctl_dev->devno = MKDEV(major, prev_ctl_dev_minor + 1);
		list_add_tail(&ctl_dev->ctl_devs_link, &zbtrfs_globals.ctl_devs); /* keep the list sorted from head to tail ASC */
		zklog(Z_KDEB2, "last=(%d,%d) res=(%d,%d)", 
			  MAJOR(prev_ctl_dev->devno), MINOR(prev_ctl_dev->devno),
			  MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));
		goto unlock;
	}

	/* search for the hole */
	prev_ctl_dev_minor = -1;
	list_for_each_entry(curr_ctl_dev, &zbtrfs_globals.ctl_devs, ctl_devs_link) {
		int curr_ctl_dev_minor = MINOR(curr_ctl_dev->devno);

		if (curr_ctl_dev_minor > prev_ctl_dev_minor + 1) {
			ctl_dev->devno = MKDEV(major, prev_ctl_dev_minor + 1);
			list_add_tail(&ctl_dev->ctl_devs_link, &curr_ctl_dev->ctl_devs_link); /* keep the list sorted from head to tail ASC */
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
	ret = -EOVERFLOW;

unlock:
	spin_unlock(&zbtrfs_globals.ctl_devs_lock);

out:
	if (ret) {
		ctl_dev->devno = 0;
	} else {
		ZBTRFS_BUG_ON(MAJOR(ctl_dev->devno) == 0);
		ZBTRFS_BUG_ON(MAJOR(ctl_dev->devno) != major);
		ZBTRFS_BUG_ON(MINOR(ctl_dev->devno) > MAX_MINOR);
	}

	return ret;
}

static void free_ctl_minor(struct zbtrfs_ctl_dev *ctl_dev)
{
	spin_lock(&zbtrfs_globals.ctl_devs_lock);
	if (!list_empty(&ctl_dev->ctl_devs_link))
		list_del_init(&ctl_dev->ctl_devs_link);
	spin_unlock(&zbtrfs_globals.ctl_devs_lock);
}

void zbtrfs_control_init(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;

	zfs_info->ctl_dev.devno = 0;
	INIT_LIST_HEAD(&zfs_info->ctl_dev.ctl_devs_link);

	zfs_info->ctl_dev.is_alive = false;
	atomic_set(&zfs_info->ctl_dev.open_cnt, 0);
	atomic_set(&zfs_info->ctl_dev.poll_mask, 0);
	init_waitqueue_head(&zfs_info->ctl_dev.poll_wait);
	init_waitqueue_head(&zfs_info->ctl_dev.wait_cleanup);
}

int zbtrfs_control_start(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_ctl_dev *ctl_dev = &fs_info->zfs_info.ctl_dev;
	struct device *device = NULL;
	int rc = 0;

	rc = alloc_ctl_minor(ctl_dev);
	if (rc) {
		zklog(Z_KERR, "alloc_ctl_minor() failed ret=%d" , rc);
		goto out;
	}

	ZBTRFSLOG(fs_info, Z_KINFO, "create control device [%d:%d] pool_id=%u", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), fs_info->zfs_info.pool_id);
	cdev_init(&ctl_dev->cdev, &zbtrfs_globals.ctl_dev_fops);

	ctl_dev->cdev.owner = THIS_MODULE;

	rc = cdev_add(&ctl_dev->cdev, ctl_dev->devno, 1);
	if (unlikely(rc!=0)) {
		ZBTRFSLOG(fs_info, Z_KERR, "cdev_add(devno=%d:%d) failed, rc=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), rc);
		kobject_put(&ctl_dev->cdev.kobj);
		free_ctl_minor(ctl_dev);
		goto out;
	}

	/*
	 * control device naming differs for block-virt mounts and FS mounts.
	 * for block-virt mount, we use pool_id, while for FS mount, we use sb->s_id, which
	 * is a canonical name of the block device, on which we mount (we mount always
	 * on a single block device!)
	 */
	if (ZBTRFS_IS_FULL_BLKVIRT_MOUNT(fs_info))
		device = device_create(zbtrfs_globals.ctl_dev_class, NULL/*parent*/, ctl_dev->devno, NULL/*drvdata*/, ZBTRFS_BLKVIRT_CONTROL_DEVICE_PREFIX"%d", fs_info->zfs_info.pool_id);
	else
		device = device_create(zbtrfs_globals.ctl_dev_class, NULL/*parent*/, ctl_dev->devno, NULL/*drvdata*/, ZBTRFS_FS_CONTROL_DEVICE_PREFIX"%s", fs_info->sb->s_id);
	if (unlikely(IS_ERR(device))) {
		rc = PTR_ERR(device);
		ZBTRFSLOG(fs_info, Z_KERR, "device_create(devno=%d:%d) failed, rc=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), rc);
		cdev_del(&ctl_dev->cdev);
		free_ctl_minor(ctl_dev);
		goto out;
	}

	ctl_dev->is_alive = true;

	rc = 0;

out:
	return rc;
}

void zbtrfs_control_stop(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_ctl_dev *ctl_dev = &fs_info->zfs_info.ctl_dev;
	const char *fs_name = fs_info->sb ? fs_info->sb->s_id : "---";

	if (!ctl_dev->is_alive)
		return;

	ctl_dev->is_alive = false;

	/* if anybody is sleeping on poll, wake him up */
	zbtrfs_control_poll_wake_up(fs_info, POLLHUP);

	/* wait until everybody is done with the device */
	while (atomic_read(&ctl_dev->open_cnt) > 0) {
		zklog(Z_KWARN, "FS[%s]: control device still open: open_cnt=%d", fs_name, atomic_read(&ctl_dev->open_cnt));
		wait_event_timeout(ctl_dev->wait_cleanup, atomic_read(&ctl_dev->open_cnt) == 0, 30 * HZ);
	}

	zklog(Z_KDEB1, "FS[%s]: device_destroy(devno=%d:%d)", fs_name, MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno));

	device_destroy(zbtrfs_globals.ctl_dev_class, ctl_dev->devno);
	/* 
	 * at this point, we really hope that refcnt inside cdev's kobject is 1,
	 * and kobject_cleanup will be called synchronously.
	 * otherwise, this call will return immediately, and we proceed and eventually
	 * free the btrfs_fs_info struct, and later kobject_cleanup calling cdev_default_release
	 * will result in use-after-free.
	 */
	cdev_del(&ctl_dev->cdev);
	free_ctl_minor(ctl_dev);
}

void zbtrfs_control_fini(struct btrfs_fs_info *fs_info)
{
}

void zbtrfs_control_poll_wake_up(struct btrfs_fs_info *fs_info, int poll_mask)
{
	struct zbtrfs_ctl_dev *ctl_dev = &fs_info->zfs_info.ctl_dev;

	zklog(Z_KDEB1, "FS[%s]: poll-wakeup, poll_mask |= %#x", fs_info->sb ? fs_info->sb->s_id : "---", poll_mask);
	atomic_or(poll_mask, &ctl_dev->poll_mask);
	if (ctl_dev->is_alive)
		wake_up(&ctl_dev->poll_wait);
}

void zbtrfs_control_poll_reset(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_ctl_dev *ctl_dev = &fs_info->zfs_info.ctl_dev;

	ZBTRFSLOG(fs_info, Z_KDEB1, "poll-reset, poll_mask = 0");
	atomic_set(&ctl_dev->poll_mask, 0);
}

static int zbtrfs_control_open(struct inode *inode, struct file *filp)
{
	struct zbtrfs_ctl_dev *ctl_dev = container_of(inode->i_cdev, struct zbtrfs_ctl_dev, cdev);
	struct zbtrfs_fs_info *zfs_info = container_of(ctl_dev, struct zbtrfs_fs_info, ctl_dev);
	struct btrfs_fs_info *fs_info = container_of(zfs_info, struct btrfs_fs_info, zfs_info);
	int open_cnt = 0;

	if (!ctl_dev->is_alive) {
		zklog(Z_KWARN, "FS[%s]: open(devno=%d:%d): is_alive=%d", fs_info->sb ? fs_info->sb->s_id : "---", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), ctl_dev->is_alive);
		return -ENODEV;
	}

	filp->private_data = fs_info;
	open_cnt = atomic_inc_return(&ctl_dev->open_cnt);
	ZBTRFSLOG(fs_info, Z_KDEB1, "open(devno=%d:%d): open_cnt=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), open_cnt);

	return 0;
}

static int zbtrfs_control_release(struct inode *inode, struct file *filp)
{
	struct zbtrfs_ctl_dev *ctl_dev = container_of(inode->i_cdev, struct zbtrfs_ctl_dev, cdev);
	struct zbtrfs_fs_info *zfs_info = container_of(ctl_dev, struct zbtrfs_fs_info, ctl_dev);
	struct btrfs_fs_info *fs_info = container_of(zfs_info, struct btrfs_fs_info, zfs_info);
	int open_cnt = 0;

	ZBTRFS_WARN_ON(fs_info != filp->private_data);

	open_cnt = atomic_dec_if_positive(&ctl_dev->open_cnt);
	WARN_ON(open_cnt < 0);
	ZBTRFSLOG(fs_info, Z_KDEB1, "release(devno=%d:%d): open_cnt=%d", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), open_cnt);
	if (open_cnt==0)
		wake_up(&ctl_dev->wait_cleanup);

	return 0;
}

static unsigned int zbtrfs_control_poll(struct file *filp, struct poll_table_struct *pt)
{
	struct btrfs_fs_info *fs_info = (struct btrfs_fs_info*)filp->private_data;
	struct zbtrfs_ctl_dev *ctl_dev = &fs_info->zfs_info.ctl_dev;
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

	ZBTRFSLOG(fs_info, Z_KDEB1, "poll(devno=%d:%d): poll_mask=%#x", MAJOR(ctl_dev->devno), MINOR(ctl_dev->devno), mask);

	return mask;
}
#endif /*CONFIG_BTRFS_ZADARA*/

