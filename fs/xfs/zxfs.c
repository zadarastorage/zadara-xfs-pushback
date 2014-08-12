#ifdef CONFIG_XFS_ZADARA
#include "xfs.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_alloc.h"
#include "xfs_extent_busy.h"
#include <linux/poll.h>

struct zxfs_globals_t zxfs_globals;
struct zklog_module_ctx *ZKLOG_THIS_MODULE_CTX = NULL;
zklog_tag_t ZKLOG_TAG_AGF = 0;
zklog_tag_t ZKLOG_TAG_BUSY_EXT = 0;
zklog_tag_t ZKLOG_TAG_DISCARD = 0;
zklog_tag_t ZKLOG_TAG_RESIZE = 0;

/****** MISC stuff ****************************************/

/*
 * File system is being shutdown.
 * We need to notify whoever is polling us, that
 * we require umount ASAP.
 * @param flags one or more of SHUTDOWN_XXX flags
 */
void zxfs_error(xfs_mount_t *mp, int flags)
{
	struct zxfs_mount *zmp = &mp->m_zxfs;
	u64 old_flags = 0, new_flags = 0;

	/* atomic64_or */
	do {
		old_flags = atomic64_read(&zmp->shutdown_flags);
		new_flags = old_flags | flags;
	} while (atomic64_cmpxchg(&zmp->shutdown_flags, old_flags, new_flags) != old_flags);

	if (old_flags != new_flags) {
		ZXFS_WARN(1, "XFS(%s): SHUTDOWN!!! old_flags=0x%llX new_flags=0x%llX",
			      mp->m_fsname, old_flags, new_flags);
#define PRINT_FLAG(f) if ((new_flags & (f)) && !(old_flags & (f))) ZXFSLOG(mp, Z_KERR, "%s", #f)
		PRINT_FLAG(SHUTDOWN_META_IO_ERROR);
		PRINT_FLAG(SHUTDOWN_LOG_IO_ERROR);
		PRINT_FLAG(SHUTDOWN_FORCE_UMOUNT);
		PRINT_FLAG(SHUTDOWN_CORRUPT_INCORE);
		PRINT_FLAG(SHUTDOWN_REMOTE_REQ);
		PRINT_FLAG(SHUTDOWN_DEVICE_REQ);

		zxfs_control_poll_wake_up(zmp, POLLERR);
	}
}

/*
 * Fetches the discard granularity from the underlying
 * block device. FS needs to be "idle" at this point.
 */
void zxfs_set_discard_gran(xfs_mount_t *mp)
{
	struct zxfs_mount *zmp = &mp->m_zxfs;
	struct request_queue *q = bdev_get_queue(mp->m_ddev_targp->bt_bdev);
	xfs_extlen_t curr = zmp->discard_gran_bbs;
	char bdn[BDEVNAME_SIZE] = {'\0'};

	bdevname(mp->m_ddev_targp->bt_bdev, bdn);

	if (q == NULL) {
		ZXFSLOG(mp, Z_KWARN, "bdev[%s] queue is NULL", bdn);
		goto out;
	}
	if (!blk_queue_discard(q)) {
		ZXFSLOG(mp, Z_KWARN, "bdev[%s] QUEUE_FLAG_DISCARD is off", bdn);
		goto out;
	}
	ZXFSLOG(mp, Z_KINFO, "bdev[%s] queue: discard_granularity=%u (sb_blocksize=%u)", bdn,
		q->limits.discard_granularity, mp->m_sb.sb_blocksize);
	ZXFSLOG(mp, Z_KINFO, "bdev[%s] queue: max_discard_sectors=%u discard_alignment=%u discard_misaligned=%u",
		bdn, q->limits.max_discard_sectors, q->limits.discard_alignment,
		q->limits.discard_misaligned);
	if (q->limits.discard_granularity == 0 ||
		(q->limits.discard_granularity & (q->limits.discard_granularity - 1)) != 0 || /* must be power of 2 */
		q->limits.discard_granularity < mp->m_sb.sb_blocksize || /* must be larger than FSB */
		q->limits.discard_granularity % mp->m_sb.sb_blocksize != 0 || /* granularity must divide nicely by block-size */
		q->limits.max_discard_sectors < q->limits.discard_granularity ||
		q->limits.discard_alignment != 0 ||
		q->limits.discard_misaligned) {
		ZXFSLOG(mp, Z_KWARN, "bdev[%s] cannot enable discard support", bdn);
		goto out;
	}
		
	zmp->discard_gran_bbs = BTOBB(q->limits.discard_granularity);
	ZXFSLOG(mp, Z_KINFO, "bdev[%s] enable discard support discard_gran_bbs:%u=>%u", bdn, curr, zmp->discard_gran_bbs);

out:
	return;
}

/*
 * Called very early during the mount sequence, at the point when:
 * - mount options have been parsed
 * - mp->m_fsname is known 
 * - underlying block devices have been opened
 * - superblock has been read into mp->m_sb
 *
 * This function doesn't fail. 
 * After this function returns, it is guaranteeed, 
 * that zxfs_mp_fini() will be called.
 * It can be assumed that mp->m_zxfs memory is zeroed.
 */
void zxfs_mp_init(xfs_mount_t *mp)
{
	struct zxfs_mount *zmp = &mp->m_zxfs;

	ZXFSLOG(mp, Z_KINFO, "INIT");

	atomic64_set(&zmp->shutdown_flags, 0);
	atomic_set(&zmp->total_discard_ranges, 0);

	zmp->kobj_in_use = 0;

	atomic_set(&zmp->allow_resize, 1);

	/* 
	 * set up the discard support.
	 * we must set it here fully, because recovering
	 * the log might have to discard/allocate, so all data
	 * structures must be ready.
	 */
	zmp->online_discard = 1; /* default */
	zxfs_set_discard_gran(mp);

	zxfs_control_init(zmp);
}

/*
 * Called at the very end of the mount sequence.
 * It is not guaranteed that this function will be called,
 * but if yes, then it is guaranteed that zxfs_mp_stop()
 * will be called.
 * ZXFS_POSITIVE_ERRNO
 */
int zxfs_mp_start(xfs_mount_t *mp)
{
	int error = 0;

	ZXFSLOG(mp, Z_KINFO, "START");

	error = zxfs_control_start(mp);
	if (error) {
		ZXFSLOG(mp, Z_KERR, "zxfs_control_start() error=%d", error);
		goto out;
	}

	/* failure is tolerable */
	zxfs_sysfs_start(mp);

out:
	return ZXFS_POSITIVE_ERRNO(error);
}

/*
 * This function is guaranteed to be called if
 * zxfs_mp_start() has been called, and is supposed
 * to undo the effects of zxfs_mp_start(), even if
 * zxfs_mp_start() only partially succeeded.
 */
void zxfs_mp_stop(xfs_mount_t *mp)
{
	ZXFSLOG(mp, Z_KINFO, "STOP");

	zxfs_sysfs_stop(mp);
	zxfs_control_stop(mp);
}

/*
 * This function undoes the effects of zxfs_mp_init().
 * This function is guranteeed to be called zxfs_mp_init() has been called,
 * even if zxfs_mp_start() only partially succeeded 
 * or even has not been called at all.
 */
void zxfs_mp_fini(xfs_mount_t *mp)
{
	struct zxfs_mount * zmp = &mp->m_zxfs;

	ZXFSLOG(mp, Z_KINFO, "FINI");

	zxfs_control_fini(zmp);
}

STATIC void zexit_xfs_globals(void)
{
	zxfs_globals_sysfs_exit();

	/* NULL is handled inside */
	kmem_zone_destroy(zxfs_globals.xfs_extent_busy_zone);
	kmem_zone_destroy(zxfs_globals.xfs_discard_range_zone);

	zxfs_globals_control_exit();
}

STATIC int zinit_xfs_globals(void)
{
	int error = 0;

	error = zxfs_globals_control_init();
	if (error)
		goto out;

	zxfs_globals.xfs_extent_busy_zone = kmem_zone_init_flags(
		sizeof(struct xfs_extent_busy), "xfs_extent_busy",
		KM_ZONE_RECLAIM|KM_ZONE_SPREAD, NULL/*ctor*/);
	if (zxfs_globals.xfs_extent_busy_zone == NULL) {
		zklog(Z_KERR, "kmem_zone_init_flags(xfs_extent_busy) failed");
		error = -ENOMEM;
		goto out;
	}
	zxfs_globals.xfs_discard_range_zone = kmem_zone_init_flags(
		sizeof(struct zxfs_discard_range), "zxfs_discard_range",
		KM_ZONE_RECLAIM|KM_ZONE_SPREAD, NULL/*ctor*/);
	if (zxfs_globals.xfs_discard_range_zone == NULL) {
		zklog(Z_KERR, "kmem_zone_init_flags(zxfs_discard_range) failed");
		error = -ENOMEM;
		goto out;
	}

	error = zxfs_globals_sysfs_init();
	if (error)
		goto out;

out:
	return error;
}

STATIC void zexit_xfs_klog(void)
{
	zklog_unregister_module();
}

STATIC int zinit_xfs_klog(void)
{
	int error = 0;

	error = zklog_register_module(Z_KINFO);
	if (error != 0) {
		ZKLOG_RAW_LOG(KERN_ERR, "zinit_xfs_klog: zklog_register_module() failed, error=%d", error);
		return error;
	}

	error = zklog_add_tag("agf", "AGF", Z_KINFO, &ZKLOG_TAG_AGF);
	if (error != 0) {
		zklog(Z_KERR, "zklog_add_tag('agf') failed, error=%d", error);
		goto out;
	}
	error = zklog_add_tag("bs", "BusyExtents", Z_KINFO, &ZKLOG_TAG_BUSY_EXT);
	if (error != 0) {
		zklog(Z_KERR, "zklog_add_tag('bs') failed, error=%d", error);
		goto out;
	}
	error = zklog_add_tag("dc", "Discard", Z_KINFO, &ZKLOG_TAG_DISCARD);
	if (error != 0) {
		zklog(Z_KERR, "zklog_add_tag('dc') failed, error=%d", error);
		goto out;
	}
	error = zklog_add_tag("sz", "Resize", Z_KINFO, &ZKLOG_TAG_RESIZE);
	if (error != 0) {
		zklog(Z_KERR, "zklog_add_tag('sz') failed, ret=%d", error);
		goto out;
	}

	error = 0;

out:
	if (error)
		zexit_xfs_klog();

	return error;
}

int zinit_xfs_fs(void)
{
	int error = 0;

	error = zinit_xfs_klog();
	if (error)
		goto out;

#ifdef MODULE
	zklog(Z_KINFO, "srcversion=%s", THIS_MODULE->srcversion);
#endif /*MODULE*/

	error = zinit_xfs_globals();
	if (error)
		goto out_free_klog;

	return 0;

out_free_klog:
	zexit_xfs_klog();
out:
	return error;
}

void zexit_xfs_fs(void)
{
	/* https://bugzilla.kernel.org/show_bug.cgi?id=48651 */
	xfs_uuid_table_free();

	zexit_xfs_globals();

	zexit_xfs_klog();
}

#endif /*CONFIG_XFS_ZADARA*/

