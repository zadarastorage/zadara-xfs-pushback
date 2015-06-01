#ifdef CONFIG_XFS_ZADARA
#ifndef __ZXFS_HDR__
#define __ZXFS_HDR__

#include <linux/cdev.h>

/*********** zklog stuff **************************/
#include "/usr/local/include/zadara-iostat/zklog.h"
extern zklog_tag_t ZKLOG_TAG_AGF;
extern zklog_tag_t ZKLOG_TAG_BUSY_EXT;
extern zklog_tag_t ZKLOG_TAG_DISCARD;
extern zklog_tag_t ZKLOG_TAG_RESIZE;
extern zklog_tag_t ZKLOG_TAG_XATTR;

#define ZXFSLOG(mp, level, fmt, ...)				zklog(level, "XFS(%s): "fmt, mp->m_fsname, ##__VA_ARGS__)
#define ZXFSLOG_TAG(mp, level, tag, fmt, ...)		zklog_tag(level, tag, "XFS(%s): "fmt, mp->m_fsname, ##__VA_ARGS__)
#define ZXFSLOG_RL(mp, level, fmt, ...)				zklog_ratelimited(level, "XFS(%s): "fmt, mp->m_fsname, ##__VA_ARGS__)
#define ZXFSLOG_TAG_RL(mp, level, tag, fmt, ...)	zklog_tag_ratelimited(level, tag, "XFS(%s): "fmt, mp->m_fsname, ##__VA_ARGS__)

#define ZXFS_SYSFS_PRINT(mp, buf, buf_size, level, tag, fmt, ...)	\
({																	\
	ssize_t __size = 0;												\
	if (buf)														\
		__size = scnprintf((buf), (buf_size),		 				\
						fmt"\n", ##__VA_ARGS__);					\
	ZXFSLOG_TAG((mp), (level), (tag), fmt, ##__VA_ARGS__);			\
	__size;															\
})

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

	/* remembers that XFS corruption has been seen at least once since mount */
	atomic_t corruption_detected;

	/* discard granularity in BBs or 0 */
	xfs_extlen_t discard_gran_bbs;

	/* 
	 * total amount of "struct zxfs_discard_range" 
	 * that we have in all AGs right now.
	 */
	atomic_t total_discard_ranges;

	/* for sysfs */
	struct kobject kobj;

	/* flags */
	unsigned int is_fs_frozen:1;
	unsigned int online_discard:1;
	/*
	 * zxfs_sysfs_stop() will call kobject_put() on this kobj,
	 * and the release function will reset kobj_in_use, indicating
	 * that all users are done with this kobject and we may proceed
	 * with the unmount.
	 */
	unsigned int kobj_in_use:1;

	/*
	 * VAC is able to set/unset this flag through a IOCTL,
	 * in order to cancel an ongoing resize.
	 */
	atomic_t allow_resize;
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

	kmem_zone_t				*xfs_extent_busy_zone; /* for allocation of "struct xfs_extent_busy" */
	kmem_zone_t				*xfs_discard_range_zone; /* for allocation of struct zxfs_discard_range */

	/* /sys/kernel/fs/xfs */
	struct kset 			*xfs_kset;

	/* for waiting untul everybody is done on per-FS kobj in umount */
	wait_queue_head_t kobj_release_wait_q;
};
extern struct zxfs_globals_t zxfs_globals;

/****************** #defines ****************************************/
#define ZXFS_BUG_ON(cond) BUG_ON(cond)

#define ZXFS_WARN(condition, format, ...) WARN(condition, format, ##__VA_ARGS__)
#define ZXFS_WARN_ONCE(condition, format, ...) WARN_ONCE(condition, format, ##__VA_ARGS__)

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
 * All our routines that need to return positive errno, should
 * be clearly commented as such, while all other routines should
 * return "normal" errno.
 */
#define ZXFS_POSITIVE_ERRNO(error) ((error)<0 ? -(error): (error))

/* xfs_daddr_t is s64, so -1 is a valid s64 */
#define NULLDADDR ((xfs_daddr_t)-1)

#define ZXFS_DISCARD_ENABLED(mp) (((mp)->m_flags & XFS_MOUNT_DISCARD) && (mp)->m_zxfs.discard_gran_bbs)
#define ZXFS_ONLINE_DISCARD_ENABLED(mp) (ZXFS_DISCARD_ENABLED(mp) && (mp)->m_zxfs.online_discard)

/*********************************************************/
/********** function delcarations ************************/
/*********************************************************/

/********** forward-declarations of xfs structures ***********/
struct xfs_mount;
typedef struct xfs_mount xfs_mount_t;

/****** MISC stuff ****************************************/

void xfs_uuid_table_free(void);
void xfs_free_perag_rcu_cb(struct rcu_head	*head);

long xfs_zioctl(struct file	*filp, unsigned int	cmd, void __user *arg);

void zxfs_error(xfs_mount_t *mp, int flags);
void zxfs_corruption_error(xfs_mount_t *mp);

void zxfs_set_discard_gran(xfs_mount_t *mp);
void zxfs_mp_init(xfs_mount_t *mp);
void zxfs_mp_fini(xfs_mount_t *mp);
void zxfs_mp_stop(xfs_mount_t *mp);
int zxfs_mp_start(xfs_mount_t *mp);

int zinit_xfs_fs(void);
void zexit_xfs_fs(void);

int zxfs_globals_control_init(void);
void zxfs_globals_control_exit(void);

int zxfs_globals_sysfs_init(void);
void zxfs_globals_sysfs_exit(void);
int zxfs_sysfs_start(xfs_mount_t *mp);
void zxfs_sysfs_stop(xfs_mount_t *mp); 

void zxfs_control_init(struct zxfs_mount *zmp);
int zxfs_control_start(xfs_mount_t *mp);
void zxfs_control_stop(xfs_mount_t *mp);
void zxfs_control_fini(struct zxfs_mount *zmp);
void zxfs_control_poll_wake_up(struct zxfs_mount *zmp, int poll_mask);
void zxfs_control_poll_reset(struct zxfs_mount *zmp);

#endif /*__ZXFS_HDR__*/
#endif /*CONFIG_XFS_ZADARA*/


