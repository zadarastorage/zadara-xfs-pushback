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

/********** Zadara IOCTLs go here ***************/
enum {
	XFS_ZIOC_FIRST_NR = 200,
};

#define XFS_ZIOC_MONITOR_FS			    _IOWR('X', XFS_ZIOC_FIRST_NR +  0, struct xfs_ioctl_monitor_fs_args)


