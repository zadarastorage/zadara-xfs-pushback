#ifndef __ZUTILS_CHRDEV_HDR__
#define __ZUTILS_CHRDEV_HDR__

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>

struct zchrdev_mgr_t;
struct zchrdev_t;
typedef long (*zchrdev_ioctl_func) (struct zchrdev_t *dev, unsigned int cmd, void __user *user_arg);

struct zchrdev_mgr_t {
	char 					*name;

	struct file_operations	fops;
	dev_t					base_devno;
	int						minors_count;

	/* 
	 * The list is used for automatic minor assignment. 
	 * If automatic minor assignment is used, this list is
	 * sorted by their minor number, in ascending order
	 * from head to tail.
	 */
	struct list_head        devs_list;
	spinlock_t              devs_lock;

	zchrdev_ioctl_func      ioctl;
};

struct zchrdev_t {
	struct cdev			cdev;
	dev_t				devno;
	struct list_head	devs_link;		/* link in devs_list */
	bool				is_alive;
	atomic_t			open_cnt;
	atomic_t 			poll_mask;		/* mask to return in poll() */
	wait_queue_head_t	poll_wait;		/* used for poll() */
	wait_queue_head_t	wait_cleanup;	/* used to wait until everybody is done with the device */
	void				*private_data;
	struct zchrdev_mgr_t	*mgr;
};

int zchrdev_mgr_create(struct zchrdev_mgr_t *mgr, int minors_count, const char *name, bool poll, zchrdev_ioctl_func ioctl);
void zchrdev_mgr_destroy(struct zchrdev_mgr_t *mgr);

void zchrdev_create(struct zchrdev_mgr_t *mgr, struct zchrdev_t *dev, void *private_data);
void zchrdev_destroy(struct zchrdev_t *dev);
int zchrdev_start(struct zchrdev_t *dev, int minor, const char *fmt, ...);
void zchrdev_stop(struct zchrdev_t *dev);

void zchrdev_poll_wakeup(struct zchrdev_t *dev, int poll_mask);
void zchrdev_poll_reset(struct zchrdev_t *dev);


#endif /*__ZUTILS_CHRDEV_HDR__*/
