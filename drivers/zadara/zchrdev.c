#include <linux/device.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include "zchrdev.h"
#include "zklog.h"

static int zchrdev_open(struct inode *inode, struct file *filp);
static int zchrdev_release(struct inode *inode, struct file *filp);
static unsigned int zchrdev_poll(struct file *filp, struct poll_table_struct *pt);
static long zchrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long p);

static int zchrdev_alloc_minor(struct zchrdev_mgr_t *mgr, struct zchrdev_t *dev);
static void zchrdev_free_minor(struct zchrdev_mgr_t *mgr, struct zchrdev_t *dev);

static zklog_tag_t ZCHRDEV_TAG;
#define ZCHRDEV_LOG(level, fmt, ...)	zklog_tag((level), ZCHRDEV_TAG, "[%s] " fmt, mgr->name, ##__VA_ARGS__)

static struct class *zchrdev_class = NULL;

/************************************************************** 
 * init / exit
 ***************************************************************/

int zchrdev_init(void)
{
	int rc;

	rc = zklog_add_tag("zchr", "zchrdev", Z_KINFO, &ZCHRDEV_TAG);
	if (unlikely(rc != 0))
		return rc;

	zchrdev_class = class_create(THIS_MODULE, "zadara-chrdev");
	if (unlikely(IS_ERR(zchrdev_class))) {
		rc = PTR_ERR(zchrdev_class);
		zchrdev_class = NULL;
		zklog_tag(Z_KERR, ZCHRDEV_TAG, "class_create(zadara-chrdev) failed, rc=%d", rc);
		return rc;
	}

	return 0;
}

void zchrdev_exit(void)
{
	if (likely(zchrdev_class != NULL)) {
		class_destroy(zchrdev_class);
		zchrdev_class = NULL;
	}
}

int zchrdev_mgr_create(struct zchrdev_mgr_t *mgr, int minors_count, const char *name, bool poll, zchrdev_ioctl_func ioctl)
{
	int rc = 0;

	if (unlikely(minors_count < 1)) {
		ZCHRDEV_LOG(Z_KERR, "minors_count too small (%d)", minors_count);
		return -EINVAL;
	}

	memset(mgr, 0, sizeof(*mgr));

	INIT_LIST_HEAD(&mgr->devs_list);
	spin_lock_init(&mgr->devs_lock);

	mgr->name = kstrdup(name, GFP_KERNEL);
	if (unlikely(mgr->name == NULL)) {
		zchrdev_mgr_destroy(mgr);
		return -ENOMEM;
	}

	/* 
	 * note that in alloc_chrdev_region count is unsigned,
	 * but in __register_chrdev_region, which is called by it,
	 * it becomes int.
	 */
	rc = alloc_chrdev_region(&mgr->base_devno, 0/*baseminor*/, minors_count/*count*/, name);
	if (unlikely(rc != 0)) {
		ZCHRDEV_LOG(Z_KERR, "alloc_chrdev_region() failed, rc=%d", rc);
		goto out;
	}
	mgr->minors_count = minors_count;

	if (unlikely(MAJOR(mgr->base_devno) == 0 || MINOR(mgr->base_devno) != 0)) {
		ZCHRDEV_LOG(Z_KERR, "alloc_chrdev_region(): picked major=%u(must be non-zero) minor=%u(must be zero)",
				  MAJOR(mgr->base_devno), MINOR(mgr->base_devno));
		rc = -EILSEQ;
		goto out;
	}

	ZCHRDEV_LOG(Z_KINFO, "major for control devices: %u", MAJOR(mgr->base_devno));

	mgr->fops.open = zchrdev_open;
	mgr->fops.release = zchrdev_release;

	if (poll) {
		mgr->fops.poll = zchrdev_poll;
	}

	if (ioctl != NULL) {
		mgr->fops.unlocked_ioctl = zchrdev_ioctl;
		mgr->ioctl = ioctl;
	}

out:
	if (unlikely(rc != 0))
		zchrdev_mgr_destroy(mgr);

	return rc;
}
EXPORT_SYMBOL(zchrdev_mgr_create);

void zchrdev_mgr_destroy(struct zchrdev_mgr_t *mgr)
{
	WARN_ON(!list_empty(&mgr->devs_list));

	if (mgr->base_devno != 0) {
		unregister_chrdev_region(mgr->base_devno, mgr->minors_count/*count*/);
		mgr->base_devno = 0;
		mgr->minors_count = 0;
	}

	kfree(mgr->name);
}
EXPORT_SYMBOL(zchrdev_mgr_destroy);

static int zchrdev_open(struct inode *inode, struct file *filp)
{
	struct zchrdev_t *dev = container_of(inode->i_cdev, struct zchrdev_t, cdev);
	struct zchrdev_mgr_t *mgr = dev->mgr;

	int open_cnt = 0;

	if (!dev->is_alive) {
		ZCHRDEV_LOG(Z_KWARN, "open(devno=%d:%d): is_alive=%d", MAJOR(dev->devno), MINOR(dev->devno), dev->is_alive);
		return -ENODEV;
	}

	filp->private_data = dev;

	open_cnt = atomic_inc_return(&dev->open_cnt);
	ZCHRDEV_LOG(Z_KDEB1, "open(devno=%d:%d): open_cnt=%d", MAJOR(dev->devno), MINOR(dev->devno), open_cnt);

	return 0;
}

static int zchrdev_release(struct inode *inode, struct file *filp)
{
	struct zchrdev_t *dev = container_of(inode->i_cdev, struct zchrdev_t, cdev);
	struct zchrdev_mgr_t *mgr = dev->mgr;
	int open_cnt = 0;

	BUG_ON(filp->private_data != dev);

	open_cnt = atomic_dec_if_positive(&dev->open_cnt);
	WARN_ON(open_cnt < 0);
	ZCHRDEV_LOG(Z_KDEB1, "release(devno=%d:%d): open_cnt=%d", MAJOR(dev->devno), MINOR(dev->devno), open_cnt);
	if (open_cnt==0)
		wake_up(&dev->wait_cleanup);

	return 0;
}

static unsigned int zchrdev_poll(struct file *filp, struct poll_table_struct *pt)
{
	struct zchrdev_t *dev = (struct zchrdev_t*)filp->private_data;
	struct zchrdev_mgr_t *mgr = dev->mgr;
	unsigned int mask = 0;

	if (!dev->is_alive) {
		mask = POLLHUP;		/* device has been already unregistered */
	} else {
		poll_wait(filp, &dev->poll_wait, pt);
		if (!dev->is_alive)
			mask = POLLHUP;	/* device has been already unregistered */
		else
			mask = atomic_read(&dev->poll_mask);
	}

	ZCHRDEV_LOG(Z_KDEB1, "poll(devno=%d:%d): poll_mask=%#x", MAJOR(dev->devno), MINOR(dev->devno), mask);

	return mask;
}

static long zchrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long p)
{
	struct zchrdev_t *dev = (struct zchrdev_t*)filp->private_data;
	struct zchrdev_mgr_t *mgr = dev->mgr;

	if (dev->is_alive) {
		void __user *user_arg = (void __user *)p;
		ZCHRDEV_LOG(Z_KDEB1, "ioctl(devno=%d:%d, cmd=%#x, user_arg=%p)", MAJOR(dev->devno), MINOR(dev->devno), cmd, user_arg);
		return mgr->ioctl(dev, cmd, user_arg);
	}
	else {
		ZCHRDEV_LOG(Z_KWARN, "ioctl(devno=%d:%d, cmd=%#x): is_alive=%d", MAJOR(dev->devno), MINOR(dev->devno), cmd, dev->is_alive);
		return -ENODEV;
	}
}

/************************************************************** 
 * zchrdev_*
 ***************************************************************/

void zchrdev_create(struct zchrdev_mgr_t *mgr, struct zchrdev_t *dev, void *private_data)
{
	memset(dev, 0, sizeof(*dev));
	INIT_LIST_HEAD(&dev->devs_link);
	init_waitqueue_head(&dev->poll_wait);
	init_waitqueue_head(&dev->wait_cleanup);
	dev->mgr = mgr;
	dev->private_data = private_data;
}
EXPORT_SYMBOL(zchrdev_create);

void zchrdev_destroy(struct zchrdev_t *dev)
{
	dev->mgr = NULL;
}
EXPORT_SYMBOL(zchrdev_destroy);

int zchrdev_start(struct zchrdev_t *dev, int minor, const char *fmt, ...)
{
	struct zchrdev_mgr_t *mgr = dev->mgr;
	struct device *device = NULL;
	va_list vargs;
	int rc = 0;

	if (minor < 0) {
		rc = zchrdev_alloc_minor(mgr, dev);
		if (unlikely(rc != 0))
			goto out;
	}
	else {
		int major = MAJOR(mgr->base_devno);
		dev->devno = MKDEV(major, minor);
		spin_lock(&mgr->devs_lock);
		list_add_tail(&dev->devs_link, &mgr->devs_list);
		spin_unlock(&mgr->devs_lock);
	}


	ZCHRDEV_LOG(Z_KINFO, "create device [%d:%d]", MAJOR(dev->devno), MINOR(dev->devno));
	cdev_init(&dev->cdev, &mgr->fops);

	dev->cdev.owner = THIS_MODULE;

	rc = cdev_add(&dev->cdev, dev->devno, 1);
	if (unlikely(rc!=0)) {
		ZCHRDEV_LOG(Z_KERR, "cdev_add(devno=%d:%d) failed, rc=%d", MAJOR(dev->devno), MINOR(dev->devno), rc);
		kobject_put(&dev->cdev.kobj);
		zchrdev_free_minor(mgr, dev);
		goto out;
	}

	va_start(vargs, fmt);
	device = device_create_vargs(zchrdev_class, NULL/*parent*/, dev->devno, NULL/*drvdata*/, fmt, vargs);
	va_end(vargs);

	if (unlikely(IS_ERR(device))) {
		rc = PTR_ERR(device);
		ZCHRDEV_LOG(Z_KERR, "device_create(devno=%d:%d) failed, rc=%d", MAJOR(dev->devno), MINOR(dev->devno), rc);
		cdev_del(&dev->cdev);
		zchrdev_free_minor(mgr, dev);
		goto out;
	}

	dev->is_alive = true;

	rc = 0;

out:
	return rc;
}
EXPORT_SYMBOL(zchrdev_start);

void zchrdev_stop(struct zchrdev_t *dev)
{
	struct zchrdev_mgr_t *mgr = dev->mgr;

	if (!dev->is_alive)
		return;

	ZCHRDEV_LOG(Z_KINFO, "delete device devno=[%d:%d]", MAJOR(dev->devno), MINOR(dev->devno));

	dev->is_alive = false;

	/* if anybody is sleeping on poll, wake him up */
	zchrdev_poll_wakeup(dev, POLLHUP);

	/* wait until everybody is done with the device */
	while (atomic_read(&dev->open_cnt) > 0) {
		ZCHRDEV_LOG(Z_KWARN, "control device devno=%d:%d still open: open_cnt=%d", MAJOR(dev->devno), MINOR(dev->devno), atomic_read(&dev->open_cnt));
		wait_event_timeout(dev->wait_cleanup, atomic_read(&dev->open_cnt) == 0, 30 * HZ);
	}

	ZCHRDEV_LOG(Z_KDEB1, "device_destroy(devno=%d:%d)", MAJOR(dev->devno), MINOR(dev->devno));
	device_destroy(zchrdev_class, dev->devno);
	cdev_del(&dev->cdev);
	zchrdev_free_minor(mgr, dev);
}
EXPORT_SYMBOL(zchrdev_stop);

void zchrdev_poll_wakeup(struct zchrdev_t *dev, int poll_mask)
{
	struct zchrdev_mgr_t *mgr = dev->mgr;

	ZCHRDEV_LOG(Z_KDEB1, "poll-wakeup devno=%d:%d, poll_mask |= %#x", MAJOR(dev->devno), MINOR(dev->devno), poll_mask);
	atomic_or(poll_mask, &dev->poll_mask);
	if (dev->is_alive || (poll_mask&POLLHUP))
		wake_up(&dev->poll_wait);
}
EXPORT_SYMBOL(zchrdev_poll_wakeup);

void zchrdev_poll_reset(struct zchrdev_t *dev)
{
	struct zchrdev_mgr_t *mgr = dev->mgr;
	ZCHRDEV_LOG(Z_KDEB1, "poll-reset devno=%d:%d, poll_mask = 0", MAJOR(dev->devno), MINOR(dev->devno));
	atomic_set(&dev->poll_mask, 0);
}
EXPORT_SYMBOL(zchrdev_poll_reset);

static int zchrdev_alloc_minor(struct zchrdev_mgr_t *mgr, struct zchrdev_t *dev)
{
	int major = MAJOR(mgr->base_devno);
	struct zchrdev_t *prev_dev = NULL, *curr_dev = NULL;
	int prev_dev_minor = 0;
	int rc = 0;

	spin_lock(&mgr->devs_lock);

	if (WARN_ON(major == 0)) {
		rc = -ECANCELED;
		goto out;
	}

	/* If the list is empty, just take minor=0 */
	if (list_empty(&mgr->devs_list)) {
		dev->devno = MKDEV(major, 0);
		list_add_tail(&dev->devs_link, &mgr->devs_list);
		ZCHRDEV_LOG(Z_KDEB2, "devs_list is empty, res=(%d,%d)", MAJOR(dev->devno), MINOR(dev->devno));
		goto out;
	}

	/* Try to go to the last entry, and take one last+1 */
	prev_dev = list_entry(mgr->devs_list.prev, struct zchrdev_t, devs_link);
	prev_dev_minor = MINOR(prev_dev->devno);
	if (prev_dev_minor < mgr->minors_count - 1) {
		dev->devno = MKDEV(major, prev_dev_minor + 1);
		list_add_tail(&dev->devs_link, &mgr->devs_list); /* keep the list sorted from head to tail ASC */
		ZCHRDEV_LOG(Z_KDEB2, "last=(%d,%d) res=(%d,%d)", 
			  MAJOR(prev_dev->devno), MINOR(prev_dev->devno),
			  MAJOR(dev->devno), MINOR(dev->devno));
		goto out;
	}

	/* Search for the hole */
	prev_dev_minor = -1;
	list_for_each_entry(curr_dev, &mgr->devs_list, devs_link) {
		int curr_dev_minor = MINOR(curr_dev->devno);

		if (curr_dev_minor > prev_dev_minor + 1) {
			dev->devno = MKDEV(major, prev_dev_minor + 1);
			list_add_tail(&dev->devs_link, &curr_dev->devs_link); /* keep the list sorted from head to tail ASC */
			ZCHRDEV_LOG(Z_KDEB2, "prev_minor=%d curr=(%d,%d) res=(%d,%d)",
				  prev_dev_minor, MAJOR(curr_dev->devno), MINOR(curr_dev->devno),
				  MAJOR(dev->devno), MINOR(dev->devno));
			goto out;
		}

		ZCHRDEV_LOG(Z_KDEB2, "prev_minor=%d curr=(%d,%d) keep searching",
			  prev_dev_minor, MAJOR(curr_dev->devno), MINOR(curr_dev->devno));
		prev_dev_minor = curr_dev_minor;
	}

	/* no holes */
	rc = -EOVERFLOW;

out:
	spin_unlock(&mgr->devs_lock);

	if (unlikely(rc != 0))
		dev->devno = 0;

	return rc;
}

static void zchrdev_free_minor(struct zchrdev_mgr_t *mgr, struct zchrdev_t *dev)
{
	spin_lock(&mgr->devs_lock);
	if (!list_empty(&dev->devs_link))
		list_del_init(&dev->devs_link);
	spin_unlock(&mgr->devs_lock);
}

