#ifdef CONFIG_XFS_ZADARA
#include "xfs.h"
#include "xfs_sb.h"
#include "xfs_ag.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_alloc.h"
#include "xfs_extent_busy.h"
#include "xfs_sysfs.h"
#include "zxfs_tests.h"
#include <linux/kobject.h>

/********* global sysfs attributes ****************/
#define ZXFS_GLOBAL_ATTR(name, mode, show, store) \
static struct kobj_attribute zxfs_global_attr_##name = __ATTR(name, mode, show, store)

#define ZXFS_GLOBAL_RO_ATTR(name)	ZXFS_GLOBAL_ATTR(name, 0444, name##_show, NULL)
#define ZXFS_GLOBAL_WO_ATTR(name)	ZXFS_GLOBAL_ATTR(name, 0200, NULL,        name##_store)
#define ZXFS_GLOBAL_RW_ATTR(name)	ZXFS_GLOBAL_ATTR(name, 0644, name##_show, name##_store)

#define ZXFS_GLOBAL_ATTR_NOZSNAP(name, mode, show, store) \
static struct kobj_attribute zxfs_global_attr_##name = __ATTR(name.nozsnap, mode, show, store)

#define ZXFS_GLOBAL_RO_ATTR_NOZSNAP(name)	ZXFS_GLOBAL_ATTR_NOZSNAP(name, 0444, name##_show, NULL)
#define ZXFS_GLOBAL_WO_ATTR_NOZSNAP(name)	ZXFS_GLOBAL_ATTR_NOZSNAP(name, 0200, NULL,        name##_store)
#define ZXFS_GLOBAL_RW_ATTR_NOZSNAP(name)	ZXFS_GLOBAL_ATTR_NOZSNAP(name, 0644, name##_show, name##_store)

static ssize_t unit_tests_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int error = 0;
	ssize_t size = 0;
	
	size += scnprintf(buf + size, PAGE_SIZE - size, "Running extent_busy tests...\n");
	error = zxfs_test_busy_extents();
	size += scnprintf(buf + size, PAGE_SIZE - size, "DONE error=%d\n", error);

	return size;
}
ZXFS_GLOBAL_RO_ATTR_NOZSNAP(unit_tests);

int zxfs_globals_sysfs_init(void)
{
	/* kset_create_and_add is originally called by xfs in version 3.18. However, since  zxfs_globals_sysfs_init is called before xfs call it, 
		the function is called here and xfs is initialzed for zdara version  from zxfs_globals.xfs_kset */
	zxfs_globals.xfs_kset = kset_create_and_add("xfs", NULL, fs_kobj);
	if (zxfs_globals.xfs_kset == NULL) {
		zklog(Z_KERR, "kset_create_and_add(xfs) failed");
		return -ENOMEM;
	}

	/* if this fails, don't freak out */
	sysfs_create_file(&zxfs_globals.xfs_kset->kobj, &zxfs_global_attr_unit_tests.attr);

	return 0;
}


void zxfs_globals_sysfs_exit(void)
{
	/* No need for action done by xfs 3.18 */
}

/******** per-FS sysfs stuff ******************/
static s64 s_agno_for_dump = -1;

STATIC ssize_t fs_state_show(xfs_mount_t *mp, struct zxfs_mount *zmp, char *buf)
{
	ssize_t size = 0;
	u64 shutdown_flags = atomic64_read(&zmp->shutdown_flags);

	size += scnprintf(buf + size, PAGE_SIZE - size, "Discard-gran BBs:\t%u\n", zmp->discard_gran_bbs);
	size += scnprintf(buf + size, PAGE_SIZE - size, "Total discard-ranges:\t%d\n", atomic_read(&zmp->total_discard_ranges));
	size += scnprintf(buf + size, PAGE_SIZE - size, "Online discard enabled:\t%u\n", zmp->online_discard);
	size += scnprintf(buf + size, PAGE_SIZE - size, "Resize allowed:\t\t%u\n", atomic_read(&zmp->allow_resize));
	size += scnprintf(buf + size, PAGE_SIZE - size, "FS is frozen:\t\t%u\n", zmp->is_fs_frozen);

	size += scnprintf(buf + size, PAGE_SIZE - size, "Shutdown flags:\t\t0x%llu\n", shutdown_flags);
#define PRINT_FLAG(f) if (shutdown_flags & (f)) size += scnprintf(buf + size, PAGE_SIZE - size, "\t"#f"\n")
	PRINT_FLAG(SHUTDOWN_META_IO_ERROR);
	PRINT_FLAG(SHUTDOWN_LOG_IO_ERROR);
	PRINT_FLAG(SHUTDOWN_FORCE_UMOUNT);
	PRINT_FLAG(SHUTDOWN_CORRUPT_INCORE);
	PRINT_FLAG(SHUTDOWN_REMOTE_REQ);
	PRINT_FLAG(SHUTDOWN_DEVICE_REQ);

	size += scnprintf(buf + size, PAGE_SIZE - size, "Corruption seen:\t%s\n", atomic_read(&zmp->corruption_detected) != 0 ? "YES" : "NO");

	return size;
}

STATIC ssize_t ext_busy_tree_show(xfs_mount_t *mp, struct zxfs_mount *zmp, char *buf)
{
	ssize_t size = 0;
	
	if (s_agno_for_dump < 0) {
		xfs_agnumber_t agno = NULLAGNUMBER;
		for (agno = 0; agno < mp->m_sb.sb_agcount; ++agno) {
			xfs_perag_t *pag = xfs_perag_get(mp, agno);
			if (pag == NULL)
				break;

			size += zxfs_extent_busy_dump(mp, pag, buf + size, PAGE_SIZE - size, Z_KDEB1);
			xfs_perag_put(pag);
		}
	} else {
		xfs_perag_t *pag = xfs_perag_get(mp, s_agno_for_dump);
		if (pag) {
			size += zxfs_extent_busy_dump(mp, pag, buf + size, PAGE_SIZE - size, Z_KDEB1);
			xfs_perag_put(pag);
		} else {
			size += ZXFS_SYSFS_PRINT(mp, buf + size, PAGE_SIZE - size, Z_KDEB1, ZKLOG_TAG_BUSY_EXT,
						"AG[%lld] not found", s_agno_for_dump);
		}
	}

	return size;
}

STATIC ssize_t ext_busy_tree_store(xfs_mount_t *mp, struct zxfs_mount *zmp, const char *buf, size_t buf_size)
{
	ssize_t error = 0;
	s64 agno = -1;

	error = kstrtos64(buf, 0/*base*/, &agno);
	if (error == 0) {
		if (agno < 0)
			s_agno_for_dump = -1;
		else
			s_agno_for_dump = agno;
		error = buf_size;
	}

	return error;
}

STATIC ssize_t discard_range_tree_show(xfs_mount_t *mp, struct zxfs_mount *zmp, char *buf)
{
	ssize_t size = 0;

	if (s_agno_for_dump < 0) {
		xfs_agnumber_t agno = NULLAGNUMBER;
		for (agno = 0; agno < mp->m_sb.sb_agcount; ++agno) {
			xfs_perag_t *pag = xfs_perag_get(mp, agno);
			if (pag == NULL)
				break;

			size += zxfs_discard_range_dump(mp, pag, buf + size, PAGE_SIZE - size, Z_KDEB1);
			xfs_perag_put(pag);
		}
	} else {
		xfs_perag_t *pag = xfs_perag_get(mp, s_agno_for_dump);
		if (pag) {
			size += zxfs_discard_range_dump(mp, pag, buf + size, PAGE_SIZE - size, Z_KDEB1);
			xfs_perag_put(pag);
		} else {
			size += ZXFS_SYSFS_PRINT(mp, buf + size, PAGE_SIZE - size, Z_KDEB1, ZKLOG_TAG_BUSY_EXT,
						"AG[%lld] not found", s_agno_for_dump);
		}
	}

	return size;
}

STATIC ssize_t discard_range_tree_store(xfs_mount_t *mp, struct zxfs_mount *zmp, const char *buf, size_t buf_size)
{
	ssize_t error = 0;
	s64 agno = -1;

	error = kstrtos64(buf, 0/*base*/, &agno);
	if (error == 0) {
		if (agno < 0)
			s_agno_for_dump = -1;
		else
			s_agno_for_dump = agno;
		error = buf_size;
	}
	
	return error;
}

STATIC ssize_t online_discard_show(xfs_mount_t *mp, struct zxfs_mount *zmp, char *buf)
{
	ssize_t size = 0;
	unsigned int enabled = zmp->online_discard;

	size += scnprintf(buf + size, PAGE_SIZE - size, "%u (%s)\n", enabled, enabled ? "enabled" : "disabled");

	return size;
}

STATIC ssize_t online_discard_store(xfs_mount_t *mp, struct zxfs_mount *zmp, const char *buf, size_t buf_size)
{
	ssize_t error = 0;
	unsigned int enabled = 0;
	
	error = kstrtouint(buf, 0/*base*/, &enabled);
	if (error) {
		ZXFSLOG(mp, Z_KERR, "Failed parsing: [%s]", buf);
	} else {
		zmp->online_discard = enabled ? 1 : 0;
		ZXFSLOG(mp, Z_KINFO, "Online discard %s", enabled ? "enabled" : "disabled");
		error = buf_size;
	}

	return error;
}

STATIC ssize_t allow_resize_show(xfs_mount_t *mp, struct zxfs_mount *zmp, char *buf)
{
	ssize_t size = 0;
	int allowed = atomic_read(&zmp->allow_resize);

	size += scnprintf(buf + size, PAGE_SIZE - size, "%d (%s)\n", allowed, allowed ? "allowed" : "not allowed");

	return size;
}

STATIC ssize_t allow_resize_store(xfs_mount_t *mp, struct zxfs_mount *zmp, const char *buf, size_t buf_size)
{
	ssize_t error = 0;
	unsigned int new_allowed = 0;
	
	error = kstrtouint(buf, 0/*base*/, &new_allowed);
	if (error) {
		ZXFSLOG(mp, Z_KERR, "Failed parsing: [%s]", buf);
	} else {
		int prev_allowed = 0;

		new_allowed = new_allowed ? 1 : 0;
		prev_allowed = atomic_xchg(&zmp->allow_resize, new_allowed);
		ZXFSLOG(mp, Z_KINFO, "Allow resize: %d => %d", prev_allowed, new_allowed);
		error = buf_size;
	}

	return error;
}

struct zxfs_attr {
	struct kobj_attribute kattr;
	ssize_t (*zshow)(xfs_mount_t *mp, struct zxfs_mount *zmp, char *buf);
	ssize_t (*zstore)(xfs_mount_t *mp, struct zxfs_mount *zmp, const char *buf, size_t count);
};

static ssize_t kobj_attr_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct xfs_kobj *xkobj = to_kobj(kobj);
	xfs_mount_t *mp = container_of(xkobj, struct xfs_mount, m_kobj);
	struct zxfs_attr *zattr = container_of(attr, struct zxfs_attr, kattr);

	if (zattr->zshow == NULL)
		return -EPERM;

	return zattr->zshow(mp, &mp->m_zxfs, buf);
}

static ssize_t kobj_attr_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct xfs_kobj *xkobj = to_kobj(kobj);
	xfs_mount_t *mp = container_of(xkobj, struct xfs_mount, m_kobj);
	struct zxfs_attr *zattr = container_of(attr, struct zxfs_attr, kattr);

	if (zattr->zstore == NULL)
		return -EPERM;

	return zattr->zstore(mp, &mp->m_zxfs, buf, count);
}

#define __INIT_KOBJ_ATTR(_name, _mode, _show, _store)			\
{									\
	.attr	= { .name = __stringify(_name), .mode = _mode },	\
	.show	= _show,						\
	.store	= _store,						\
}

#define ZXFS_ATTR(name, mode, show, store)                                      \
static struct zxfs_attr zxfs_attr_##name = {                                    \
	.kattr = __INIT_KOBJ_ATTR(name, mode, kobj_attr_show, kobj_attr_store),     \
	.zshow = show,                                                              \
	.zstore = store,                                                            \
}

#define ZXFS_RO_ATTR(name) ZXFS_ATTR(name, 0444, name##_show, NULL)
#define ZXFS_WO_ATTR(name) ZXFS_ATTR(name, 0222, NULL, name##_store)
#define ZXFS_RW_ATTR(name) ZXFS_ATTR(name, 0644, name##_show, name##_store)

#define ZXFS_ATTR_NOZSNAP(name, mode, show, store)                                 \
static struct zxfs_attr zxfs_attr_##name = {                                     \
	.kattr = __INIT_KOBJ_ATTR(name.nozsnap, mode, kobj_attr_show, kobj_attr_store),  \
	.zshow = show,                                                                   \
	.zstore = store,                                                                 \
}

#define ZXFS_RO_ATTR_NOZSNAP(name) ZXFS_ATTR_NOZSNAP(name, 0444, name##_show, NULL)
#define ZXFS_WO_ATTR_NOZSNAP(name) ZXFS_ATTR_NOZSNAP(name, 0222, NULL, name##_store)
#define ZXFS_RW_ATTR_NOZSNAP(name) ZXFS_ATTR_NOZSNAP(name, 0644, name##_show, name##_store)

#define ZXFS_ATTR_IN_LIST(name) &zxfs_attr_##name.kattr.attr

ZXFS_RO_ATTR(fs_state);
ZXFS_RW_ATTR(online_discard);
ZXFS_RW_ATTR(allow_resize);
ZXFS_RW_ATTR_NOZSNAP(ext_busy_tree);
ZXFS_RW_ATTR_NOZSNAP(discard_range_tree);


static const struct attribute *zxfs_sysfs_attrs[] = {
	ZXFS_ATTR_IN_LIST(fs_state),
	ZXFS_ATTR_IN_LIST(online_discard),
	ZXFS_ATTR_IN_LIST(allow_resize),
	ZXFS_ATTR_IN_LIST(ext_busy_tree),
	ZXFS_ATTR_IN_LIST(discard_range_tree),
	NULL
};


int zxfs_sysfs_start(xfs_mount_t *mp)
{
	int error = 0;

	error = sysfs_create_files(&mp->m_kobj.kobject, zxfs_sysfs_attrs);
	if (error)
		ZXFSLOG(mp, Z_KWARN, "sysfs_create_files(%s) failed error=%d", mp->m_fsname, error);
	return error;
}

void zxfs_sysfs_stop(xfs_mount_t *mp)
{
}

#endif /*CONFIG_XFS_ZADARA*/

