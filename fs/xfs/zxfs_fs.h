/*
 * IOCTLs added by Zadara.
 * This file is meant to be included directly from xfs_fs.h, 
 * so no #ifndef/#define/#endif protection or similar is needed.
 */

/******** The different Zadara IOCTL arg structs go here *************************/

struct xfs_ioctl_monitor_fs_args {
	__u8 is_periodic;                            /* in: hint whether this is a periodic call, or just an occasional call to check something specific */

#define XFS_ZIOC_FS_STATE_SHUTDOWN               (1ULL << 0)
	__u64 fs_state;                              /* out */
};

struct xfs_ioctl_refresh_discard_gran_args {
	__u32 discard_gran_sectors;                  /* out */
};

/********** Zadara IOCTLs go here ***************/
/* ATTENTION! "nr" can go only up to 255 */
enum {
	XFS_ZIOC_FIRST_NR = 200,
};

#define XFS_ZIOC_MONITOR_FS			    _IOWR('X', XFS_ZIOC_FIRST_NR +  0, struct xfs_ioctl_monitor_fs_args)
#define XFS_ZIOC_REFRESH_DISCARD_GRAN    _IOR('X', XFS_ZIOC_FIRST_NR +  1, struct xfs_ioctl_refresh_discard_gran_args)
#define XFS_ZIOC_ALLOW_RESIZE            _IOW('X', XFS_ZIOC_FIRST_NR +  2, __u8)


