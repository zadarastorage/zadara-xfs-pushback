#ifdef CONFIG_XFS_ZADARA
#ifndef __ZXFS_HDR__
#define __ZXFS_HDR__

#include <linux/cdev.h>

/*********** zklog stuff **************************/
#include "/usr/local/include/zadara-iostat/zklog.h"
extern zklog_tag_t ZKLOG_TAG_DISCARD;

/************* zadara structures *********************/
struct zxfs_ctl_dev {
	struct cdev			cdev;
	
	dev_t				devno;
	struct list_head    ctl_devs_link;          /* link in zxfs_globals.ctl_devs list */

	bool				is_alive;
	atomic_t			open_cnt;
	atomic_t 			poll_mask;				/* mask to return in poll() */
	wait_queue_head_t	poll_wait;      		/* used for poll() */
	wait_queue_head_t	wait_cleanup;			/* used to wait until everybody is done with the device */
};

/* Zadara-specific part of xfs_mount */
struct zxfs_mount {
	
	struct zxfs_ctl_dev m_ctl_dev;

	/* tracks SHUTDOWN_XXX flags */
	atomic64_t shutdown_flags;
};

struct zxfs_globals_t {
	struct class			*ctl_dev_class;
	struct file_operations	ctl_dev_fops;
	dev_t					ctl_base_devno;

	/* 
	 * all control devices are linked here, and this
	 * list is sorted by their minor number, in 
	 * ascending order from head to tail.
	 */
	struct list_head        ctl_devs;
	spinlock_t              ctl_devs_lock;
};
extern struct zxfs_globals_t zxfs_globals;

/****************** #defines ****************************************/
#define ZXFS_BUG_ON(cond) BUG_ON(cond)

#define ZXFS_WARN(condition, format, ...) WARN(condition, format, ##__VA_ARGS__)

#define ZXFS_WARN_ON(cond) ZXFS_WARN(cond, "ZXFS WARNING: " #cond)

#define ZXFS_WARN_ON_ONCE(cond)	({				               \
	static bool __section(.data.unlikely) __warned;		           \
	int __ret_warn_once = !!(cond);			                       \
	if (unlikely(__ret_warn_once)) {                               \
		if (!__warned) {                                           \
			ZXFS_WARN(cond, "ZXFS ONE-TIME WARNING: " #cond);  \
			__warned = true;			                           \
		}                                                          \
	}                                                              \
	unlikely(__ret_warn_once);				                       \
})

#ifdef WARN_ON
#undef WARN_ON
#endif
#define WARN_ON(cond) ZXFS_WARN_ON(cond)

#ifdef WARN_ON_ONCE
#undef WARN_ON_ONCE
#endif
#define WARN_ON_ONCE(cond) ZXFS_WARN_ON_ONCE(cond)

/*
 * Most of XFS routines are supposed to return a positive errno.
 * This macro should be used if a routine in question is such,
 * but it calls routines that are "normal" WRT errno.
 * Aall our routines that need to return positive errno, should
 * be clearly commented as such, while all other routines should
 * return "normal" errno.
 */
#define ZXFS_POSITIVE_ERRNO(error) ((error)<0 ? -(error): (error))

/*********************************************************/
/********** function delcarations ************************/
/*********************************************************/

/****** MISC stuff ****************************************/

void xfs_uuid_table_free(void);

long xfs_zioctl(struct file	*filp, unsigned int	cmd, void __user *arg);

void zxfs_error(struct xfs_mount *mp, int flags);

void zxfs_mp_init(struct xfs_mount *mp);
void zxfs_mp_fini(struct xfs_mount *mp);
void zxfs_mp_stop(struct xfs_mount *mp);
int zxfs_mp_start(struct xfs_mount *mp);

int zinit_xfs_fs(void);
void zexit_xfs_fs(void);

int zxfs_globals_control_init(void);
void zxfs_globals_control_exit(void);

void zxfs_control_init(struct zxfs_mount *zmp);
int zxfs_control_start(struct xfs_mount *mp);
void zxfs_control_stop(struct xfs_mount *mp);
void zxfs_control_fini(struct zxfs_mount *zmp);
void zxfs_control_poll_wake_up(struct zxfs_mount *zmp, int poll_mask);
void zxfs_control_poll_reset(struct zxfs_mount *zmp);

#endif /*__ZXFS_HDR__*/
#endif /*CONFIG_XFS_ZADARA*/


