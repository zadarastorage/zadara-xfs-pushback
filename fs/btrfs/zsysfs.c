/*
 * sysfs interfaces added by Zadara.
 * This file is meant to be included directly from fs/btrfs/sysfs.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

#include <linux/delay.h>
#include "rcu-string.h"
#include "tests/btrfs-tests.h"

/********* global sysfs attributes ****************/
#define ZBTRFS_GLOBAL_ATTR(name, mode, show, store) \
static struct kobj_attribute zbtrfs_global_attr_##name = __ATTR(name, mode, show, store)

#define ZBTRFS_GLOBAL_RO_ATTR(name)	ZBTRFS_GLOBAL_ATTR(name, 0444, name##_show, NULL)
#define ZBTRFS_GLOBAL_WO_ATTR(name)	ZBTRFS_GLOBAL_ATTR(name, 0200, NULL,        name##_store)
#define ZBTRFS_GLOBAL_RW_ATTR(name)	ZBTRFS_GLOBAL_ATTR(name, 0644, name##_show, name##_store)

#define ZBTRFS_GLOBAL_ATTR_NOZSNAP(name, mode, show, store) \
static struct kobj_attribute zbtrfs_global_attr_##name = __ATTR(name.nozsnap, mode, show, store)

#define ZBTRFS_GLOBAL_RO_ATTR_NOZSNAP(name)	ZBTRFS_GLOBAL_ATTR_NOZSNAP(name, 0444, name##_show, NULL)
#define ZBTRFS_GLOBAL_WO_ATTR_NOZSNAP(name)	ZBTRFS_GLOBAL_ATTR_NOZSNAP(name, 0200, NULL,        name##_store)
#define ZBTRFS_GLOBAL_RW_ATTR_NOZSNAP(name)	ZBTRFS_GLOBAL_ATTR_NOZSNAP(name, 0644, name##_show, name##_store)

/********* per-FS sysfs attributes ****************/
struct zbtrfs_attr {
	struct kobj_attribute kattr;
	ssize_t (*zshow)(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
	ssize_t (*zstore)(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count);
};

static ssize_t kobj_attr_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct btrfs_fs_info *fs_info = NULL;
	struct zbtrfs_attr *zattr = NULL;

	fs_info = to_fs_info(kobj);
	if (ZBTRFS_WARN_ON(fs_info == NULL))
		return -ECANCELED;

	zattr = container_of(attr, struct zbtrfs_attr, kattr);
	if (zattr->zshow == NULL)
		return -EPERM;

	return zattr->zshow(zattr, fs_info, buf);
}

static ssize_t kobj_attr_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct btrfs_fs_info *fs_info = NULL;
	struct zbtrfs_attr *zattr = NULL;

	fs_info = to_fs_info(kobj);
	if (ZBTRFS_WARN_ON(fs_info == NULL))
		return -ECANCELED;

	zattr = container_of(attr, struct zbtrfs_attr, kattr);
	if (zattr->zstore == NULL)
		return -EPERM;

	return zattr->zstore(zattr, fs_info, buf, count);
}

#define ZBTRFS_ATTR(name, mode, show, store)                                      \
static struct zbtrfs_attr zbtrfs_attr_##name = {                                  \
	.kattr = __INIT_KOBJ_ATTR(name, mode, kobj_attr_show, kobj_attr_store),       \
	.zshow = show,                                                                \
	.zstore = store,                                                              \
}

#define ZBTRFS_RO_ATTR(name)	ZBTRFS_ATTR(name, 0444, name##_show, NULL)
#define ZBTRFS_WO_ATTR(name)	ZBTRFS_ATTR(name, 0200, NULL,        name##_store)
#define ZBTRFS_RW_ATTR(name)	ZBTRFS_ATTR(name, 0644, name##_show, name##_store)

#define ZBTRFS_ATTR_NOZSNAP(name, mode, show, store)                                 \
static struct zbtrfs_attr zbtrfs_attr_##name = {                                     \
	.kattr = __INIT_KOBJ_ATTR(name.nozsnap, mode, kobj_attr_show, kobj_attr_store),  \
	.zshow = show,                                                                   \
	.zstore = store,                                                                 \
}

#define ZBTRFS_RO_ATTR_NOZSNAP(name)	ZBTRFS_ATTR_NOZSNAP(name, 0444, name##_show, NULL)
#define ZBTRFS_WO_ATTR_NOZSNAP(name)	ZBTRFS_ATTR_NOZSNAP(name, 0200, NULL,        name##_store)
#define ZBTRFS_RW_ATTR_NOZSNAP(name)	ZBTRFS_ATTR_NOZSNAP(name, 0644, name##_show, name##_store)

#define ZBTRFS_ATTR_PTR(name)	(&zbtrfs_attr_##name.kattr.attr)

static ssize_t fs_state_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR(fs_state);

static ssize_t deleting_subvols_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR(deleting_subvols);

static ssize_t mapping_system_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(mapping_system);
static ssize_t mapping_data_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(mapping_data);
static ssize_t mapping_metadata_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(mapping_metadata);
static ssize_t mapping_all_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(mapping_all);

static ssize_t space_info_system_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR(space_info_system);
static ssize_t space_info_data_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR(space_info_data);
static ssize_t space_info_metadata_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR(space_info_metadata);

static ssize_t block_group_system_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(block_group_system);
static ssize_t block_group_data_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(block_group_data);
static ssize_t block_group_metadata_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(block_group_metadata);
static ssize_t block_group_all_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(block_group_all);

#if 0
static ssize_t block_group_system_free_space_cache_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(block_group_system_free_space_cache);
static ssize_t block_group_data_free_space_cache_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(block_group_data_free_space_cache);
static ssize_t block_group_metadata_free_space_cache_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(block_group_metadata_free_space_cache);

static ssize_t free_space_cache_details_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
static ssize_t free_space_cache_details_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count);
ZBTRFS_RW_ATTR(free_space_cache_details);
#endif

static ssize_t metadata_reservation_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR(metadata_reservation);

static ssize_t ztenant_inmem_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(ztenant_inmem);

static ssize_t device_map_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
static ssize_t device_map_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count);
ZBTRFS_RW_ATTR_NOZSNAP(device_map);

static ssize_t zstats_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR(zstats);

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
static ssize_t fs_unit_tests_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf);
ZBTRFS_RO_ATTR_NOZSNAP(fs_unit_tests);

static ssize_t tree_corruption_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count);
ZBTRFS_WO_ATTR_NOZSNAP(tree_corruption);

static ssize_t force_abort_trans_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count);
ZBTRFS_WO_ATTR_NOZSNAP(force_abort_trans);
#endif /*CONFIG_BTRFS_FS_RUN_SANITY_TESTS*/

static const struct attribute *zbtrfs_attrs[] = {
	ZBTRFS_ATTR_PTR(fs_state),
	ZBTRFS_ATTR_PTR(deleting_subvols),
	ZBTRFS_ATTR_PTR(mapping_system),
	ZBTRFS_ATTR_PTR(mapping_data),
	ZBTRFS_ATTR_PTR(mapping_metadata),
	ZBTRFS_ATTR_PTR(mapping_all),
	ZBTRFS_ATTR_PTR(space_info_system),
	ZBTRFS_ATTR_PTR(space_info_data),
	ZBTRFS_ATTR_PTR(space_info_metadata),
	ZBTRFS_ATTR_PTR(block_group_system),
	ZBTRFS_ATTR_PTR(block_group_data),
	ZBTRFS_ATTR_PTR(block_group_metadata),
	ZBTRFS_ATTR_PTR(block_group_all),
#if 0
	ZBTRFS_ATTR_PTR(block_group_system_free_space_cache),
	ZBTRFS_ATTR_PTR(block_group_data_free_space_cache),
	ZBTRFS_ATTR_PTR(block_group_metadata_free_space_cache),
	ZBTRFS_ATTR_PTR(free_space_cache_details),
#endif
	ZBTRFS_ATTR_PTR(metadata_reservation),
	ZBTRFS_ATTR_PTR(ztenant_inmem),
	ZBTRFS_ATTR_PTR(device_map),
	ZBTRFS_ATTR_PTR(zstats),
#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
	ZBTRFS_ATTR_PTR(fs_unit_tests),
	ZBTRFS_ATTR_PTR(tree_corruption),
	ZBTRFS_ATTR_PTR(force_abort_trans),
#endif /*CONFIG_BTRFS_FS_RUN_SANITY_TESTS*/
	NULL
};

void zbtrfs_sysfs_init(struct btrfs_fs_info *fs_info)
{
}

void zbtrfs_sysfs_start(struct btrfs_fs_info *fs_info, const char *name)
{
	int ret = 0;

	ret = sysfs_create_files(&fs_info->super_kobj, zbtrfs_attrs);
	if (ret)
		ZBTRFSLOG(fs_info, Z_KERR, "sysfs_create_files ret=%d", ret);
}

void zbtrfs_sysfs_stop(struct btrfs_fs_info *fs_info)
{
}

void zbtrfs_sysfs_fini(struct btrfs_fs_info *fs_info)
{
}

static ssize_t fs_state_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	ssize_t size = 0;
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;

	size += scnprintf(buf + size, PAGE_SIZE - size, "FSID: [%pU]\n", fs_info->fsid);

	size += scnprintf(buf + size, PAGE_SIZE - size, "POOL INFO: pool_id=%u gran_bytes=%u data_devpath=%s\n",
		              zfs_info->pool_id, zfs_info->pool_gran_bytes, 
		              zfs_info->pool_data_devpath[0] != '\0' ? zfs_info->pool_data_devpath : "N/A");

	if (fs_info->sb->s_flags & MS_RDONLY)
		size += scnprintf(buf + size, PAGE_SIZE - size, "---- MOUNTED READ-ONLY!!! ----\n");

	{
		u64 total_rw_bytes = fs_info->fs_devices->total_rw_bytes;
		size += scnprintf(buf + size, PAGE_SIZE - size, "total_rw_bytes: %llu(%llu MB)\n", 
			              total_rw_bytes, BYTES_TO_MB(total_rw_bytes));
	}

	{
		u64 super_total_bytes = btrfs_super_total_bytes(fs_info->super_copy);
		size += scnprintf(buf + size, PAGE_SIZE - size, "super_total_bytes: %llu(%llu MB)\n", 
		                  super_total_bytes, BYTES_TO_MB(super_total_bytes));
	}

	/* print some information on devices */
	{
		unsigned int tries = 5;

		while (tries > 0) {
			struct btrfs_device *device = NULL;
			
			if (!mutex_trylock(&fs_info->fs_devices->device_list_mutex)) {
				cond_resched();
				--tries;
				continue;
			}

			list_for_each_entry(device, &fs_info->fs_devices->devices, dev_list) {
				rcu_read_lock();
				size += scnprintf(buf + size, PAGE_SIZE - size, 
					        "DEVICE: id=%llu(%s) total_bytes=%llu(%llu MB) disk_total_bytes=%llu(%llu MB) bytes_used=%llu(%llu MB)\n",
					        device->devid, rcu_str_deref(device->name),
					        btrfs_device_get_total_bytes(device), BYTES_TO_MB(btrfs_device_get_total_bytes(device)),
					        btrfs_device_get_disk_total_bytes(device), BYTES_TO_MB(btrfs_device_get_disk_total_bytes(device)),
					        btrfs_device_get_bytes_used(device), BYTES_TO_MB(btrfs_device_get_bytes_used(device)));
				rcu_read_unlock();
				size += scnprintf(buf + size, PAGE_SIZE - size, 
					        "\t\tcommit_total_bytes=%llu(%llu MB) commit_bytes_used=%llu(%llu MB)\n",
					        device->commit_total_bytes, BYTES_TO_MB(device->commit_total_bytes),
					        device->commit_bytes_used, BYTES_TO_MB(device->commit_bytes_used));
			}

			mutex_unlock(&fs_info->fs_devices->device_list_mutex);
			break;
		}
	}

	{
		u64 last_trans_committed = fs_info->last_trans_committed;
		size += scnprintf(buf + size, PAGE_SIZE - size, "LAST TRANS: %llu\n", last_trans_committed);
	}

	{
		u64 corrupted_tree_transid = 0;
		corrupted_tree_transid = atomic64_read(&zfs_info->corrupted_tree_transid);
		if (corrupted_tree_transid > 0)
			size += scnprintf(buf + size, PAGE_SIZE - size, "---- CORRUPTED TREE IN TRANS: %llu ----\n", corrupted_tree_transid);
		else
			size += scnprintf(buf + size, PAGE_SIZE - size, "FS TREES: OK\n");
	}

	size += scnprintf(buf + size, PAGE_SIZE - size, "FS STATE: %s\n", ZBTRFS_FS_ERROR(fs_info) ? "ERROR" : "OK");

	size += scnprintf(buf + size, PAGE_SIZE - size, "SYSTEM BLOCK-GROUPS TO WARM-UP:\t\t%d\n", atomic_read(&zfs_info->system_block_groups_to_warmup));
	size += scnprintf(buf + size, PAGE_SIZE - size, "METADATA BLOCK-GROUPS TO WARM-UP:\t%d\n", atomic_read(&zfs_info->metadata_block_groups_to_warmup));
	size += scnprintf(buf + size, PAGE_SIZE - size, "DATA BLOCK-GROUPS TO WARM-UP:\t\t%d\n", atomic_read(&zfs_info->data_block_groups_to_warmup));

	{
		unsigned long npagecache_now = fs_info->btree_inode->i_mapping->nrpages;
		size += scnprintf(buf + size, PAGE_SIZE - size, "PAGE-CACHE USAGE:\t%lu (%lu KB)\n", npagecache_now, (npagecache_now << PAGE_CACHE_SHIFT) >> 10);
	}

	return size;
}

static ssize_t deleting_subvols_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	ssize_t size = 0;
	struct btrfs_root *dead_root = NULL;
	struct zbtrfs_deleted_subvol_info *subv_info = NULL;

	spin_lock(&fs_info->trans_lock);

	list_for_each_entry(dead_root, &fs_info->dead_roots, root_list) {
		size += scnprintf(buf + size, PAGE_SIZE - size, "(%llu,%llu) DEAD\n", 
			              dead_root->objectid, btrfs_root_otransid(&dead_root->root_item));
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "(%llu,%llu) DEAD", 
			      dead_root->objectid, btrfs_root_otransid(&dead_root->root_item)); 
	}

	if (fs_info->zfs_info.curr_deleting_subvol_objectid != 0) {
		size += scnprintf(buf + size, PAGE_SIZE - size, "(%llu,%llu) DELETING\n", 
			        fs_info->zfs_info.curr_deleting_subvol_objectid,
			        fs_info->zfs_info.curr_deleting_subvol_otransid);
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "(%llu,%llu) DELETING",
			        fs_info->zfs_info.curr_deleting_subvol_objectid,
			        fs_info->zfs_info.curr_deleting_subvol_otransid);
	}

	spin_unlock(&fs_info->trans_lock);

	spin_lock(&fs_info->zfs_info.deleted_subvols_lock);
	list_for_each_entry(subv_info, &fs_info->zfs_info.deleted_subvols, deleted_subvols_link) {
		size += scnprintf(buf + size, PAGE_SIZE - size, "(%llu,%llu) DELETED in txn[%llu]\n",
			              subv_info->root_objectid, subv_info->otransid, subv_info->deletion_transid);
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "(%llu,%llu) DELETED in txn[%llu]",
			              subv_info->root_objectid, subv_info->otransid, subv_info->deletion_transid);
	}
	spin_unlock(&fs_info->zfs_info.deleted_subvols_lock);

	return size;
}

/*
 * Sysfs helper to dump virtual-to-physical mappings of a particular type
 */
static ssize_t __show_mappings(struct btrfs_fs_info *fs_info, u64 map_type, char *buf, size_t buf_size)
{
	ssize_t size = 0;
	struct extent_map_tree *mapping_tree = &fs_info->mapping_tree.map_tree;
	struct rb_node *curr = NULL;
	u64 prev_em_end = 0;

	read_lock(&mapping_tree->lock);
	for (curr = rb_first(&mapping_tree->map); curr != NULL; curr = rb_next(curr)) {
		unsigned int idx = 0;
		struct extent_map *em = rb_entry(curr, struct extent_map, rb_node);
		struct map_lookup *map = (struct map_lookup*)em->bdev;
		const char *type_str = NULL;

		/* if we are dumping all mappings, dump also holes */
		if (em->start > prev_em_end &&
			(map_type & BTRFS_BLOCK_GROUP_TYPE_MASK) == BTRFS_BLOCK_GROUP_TYPE_MASK) {
			size += scnprintf(buf + size, buf_size - size, "BG HOLE[%llu:%llu]\n", prev_em_end, em->start - prev_em_end);
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_CHUNK_ALLOC, "BG HOLE[%llu:%llu]", prev_em_end, em->start - prev_em_end);
		}
		prev_em_end = em->start + em->len;

		if (!(map->type & map_type))
			continue;

		type_str = btrfs_block_group_type_to_str(map->type);

		size += scnprintf(buf + size, buf_size - size, "[%llu:%llu] T=%s/%llu ns=%d sl=%d\n", 
					em->start, em->len, type_str, map->type, map->num_stripes, map->stripe_len);
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "MAP[%llu:%llu] type=%llu(%s) num_stripes=%d stripe_len=%d sub_stripes=%d sector_size=%d",
			em->start, em->len, map->type, type_str, map->num_stripes, map->stripe_len, map->sub_stripes, map->sector_size);

		for (idx = 0; idx < map->num_stripes; ++idx) {
			struct btrfs_bio_stripe *stripe = &map->stripes[idx];
			char bdevname_str[BDEVNAME_SIZE] = "???";

			if (stripe->dev && stripe->dev->bdev)
				bdevname(stripe->dev->bdev, bdevname_str);

			size += scnprintf(buf + size, buf_size - size, " <%llu> %s\n", stripe->physical, bdevname_str);
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "%u/%u\tSTRIPE<%llu> on [%s]", idx+1, map->num_stripes, stripe->physical, bdevname_str);
		}
	}
	read_unlock(&mapping_tree->lock);

	size += scnprintf(buf + size, buf_size - size, ".\n");

	return size;
}

static ssize_t mapping_system_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_mappings(fs_info, BTRFS_BLOCK_GROUP_SYSTEM, buf, PAGE_SIZE);
}

static ssize_t mapping_data_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_mappings(fs_info, BTRFS_BLOCK_GROUP_DATA, buf, PAGE_SIZE);
}

static ssize_t mapping_metadata_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_mappings(fs_info, BTRFS_BLOCK_GROUP_METADATA, buf, PAGE_SIZE);
}

static ssize_t mapping_all_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_mappings(fs_info, BTRFS_BLOCK_GROUP_TYPE_MASK, buf, PAGE_SIZE);
}

/* 
 * caller's responsibility to hold space_info->lock.
 * caller must not hold the global block reservation lock.
 * 'buf' can be NULL.
 */
ssize_t zbtrfs_show_space_info_spinlocked(struct btrfs_fs_info *fs_info, struct btrfs_space_info *si, 
	                                      char *buf, size_t buf_size,
	                                      const char *msg, 
	                                      enum zklog_level_t level, zklog_tag_t tag)
{
	ssize_t size = 0;
	s64 total_pinned = percpu_counter_sum(&si->total_bytes_pinned);
	u64 slack_bytes = si->total_bytes - si->bytes_used - si->bytes_pinned - si->bytes_reserved - si->bytes_may_use - si->bytes_readonly;
	u64 slack_bytes_adjusted = 0;
	u64 global_size = 0, global_reserved = 0;

	if (si->flags & BTRFS_BLOCK_GROUP_METADATA) {
		u64 bytes_may_used_adjusted = zbtrfs_adjust_bytes_may_use_space_info_spinlocked(fs_info, si, &global_size, &global_reserved);
		slack_bytes_adjusted = si->total_bytes - si->bytes_used - si->bytes_pinned - si->bytes_reserved - bytes_may_used_adjusted - si->bytes_readonly;
	}

	if (buf) {
		size += scnprintf(buf + size, buf_size - size, "t=\t%llu(%lluMB)\nu=\t%llu(%lluMB)\np=\t%llu(%lluMB)\ntp=\t%lld(%lldMB)\nr=\t%llu(%lluMB)\n",
					   si->total_bytes, 	 BYTES_TO_MB(si->total_bytes),
					   si->bytes_used,		 BYTES_TO_MB(si->bytes_used),
					   si->bytes_pinned,	 BYTES_TO_MB(si->bytes_pinned),
					   total_pinned,         BYTES_TO_MB(total_pinned),
					   si->bytes_reserved,	 BYTES_TO_MB(si->bytes_reserved));
		size += scnprintf(buf + size, buf_size - size, "ro=\t%llu(%lluMB)\nmu=\t%llu(%lluMB)\ndu=\t%llu(%lluMB)\ndt=\t%llu(%lluMB)\n",
					   si->bytes_readonly,	 BYTES_TO_MB(si->bytes_readonly),
					   si->bytes_may_use,	 BYTES_TO_MB(si->bytes_may_use),
					   si->disk_used,		 BYTES_TO_MB(si->disk_used),
					   si->disk_total,		 BYTES_TO_MB(si->disk_total));
		size += scnprintf(buf + size, buf_size - size, "slack=\t%llu(%lluMB)\n", slack_bytes, BYTES_TO_MB(slack_bytes));
		if (si->flags & BTRFS_BLOCK_GROUP_METADATA)
			size += scnprintf(buf + size, buf_size - size, "slack adjusted=\t%llu(%lluMB)\n", slack_bytes_adjusted, BYTES_TO_MB(slack_bytes_adjusted));
		size += scnprintf(buf + size, buf_size - size, "full:%u chunk_alloc:%u flush:%u force_alloc:%u\n",
					   si->full, si->chunk_alloc, si->flush, si->force_alloc);
		if (si->flags & BTRFS_BLOCK_GROUP_METADATA)
			size += scnprintf(buf + size, buf_size - size, "GLOBAL RSV:\tsize=%llu(%lluMB)\treserved=%llu(%lluMB)\n",
			                  global_size, BYTES_TO_MB(global_size), global_reserved, BYTES_TO_MB(global_reserved));
	}
	if (zklog_will_print_tag(level, tag)) {
		/* on Z_KERR use rate-limiting */
		static DEFINE_RATELIMIT_STATE(_rs, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
		if (level != (Z_KERR) || __ratelimit(&_rs)) {
			ZBTRFSLOG_TAG(fs_info, level, tag, "%s[%s t=%llu u=%llu p=%llu tp=%lld r=%llu ro=%llu mu=%llu du=%llu dt=%llu fll:%u all:%u fsh:%u frc:%u]",
				          msg, btrfs_block_group_type_to_str(si->flags),
				          si->total_bytes, si->bytes_used,
				          si->bytes_pinned, total_pinned,
				          si->bytes_reserved, si->bytes_readonly,
				          si->bytes_may_use, si->disk_used, si->disk_total,
				          si->full, si->chunk_alloc, si->flush, si->force_alloc);
			if (si->flags & BTRFS_BLOCK_GROUP_METADATA) {
				ZBTRFSLOG_TAG(fs_info, level, tag, "%s[slack=%llu(%lluMB) slack_adjusted=%llu(%lluMB)]", msg, 
					          slack_bytes, BYTES_TO_MB(slack_bytes), slack_bytes_adjusted, BYTES_TO_MB(slack_bytes_adjusted));
				ZBTRFSLOG_TAG(fs_info, level, tag, "%s %s[size=%llu(%lluMB) reserved=%llu(%lluMB)]", msg,
				              btrfs_block_rsv_type_to_str(BTRFS_BLOCK_RSV_GLOBAL), 
				              global_size, BYTES_TO_MB(global_size), global_reserved, BYTES_TO_MB(global_reserved));
			}
		}
	}

	return size;
}

static ssize_t __show_space_info(struct btrfs_fs_info *fs_info, u64 type, char *buf, size_t buf_size)
{
	ssize_t size = 0;
	struct btrfs_space_info *si = NULL;

	si = zbtrfs_find_space_info(fs_info, type);
	if (si == NULL)
		return 0;

	spin_lock(&si->lock);
	size = zbtrfs_show_space_info_spinlocked(fs_info, si, buf, buf_size, NULL/*msg*/, Z_KDEB1/*log_level*/, ZKLOG_TAG_SPACE_USAGE);
	spin_unlock(&si->lock);

	return size;
}

static ssize_t space_info_system_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_space_info(fs_info, BTRFS_BLOCK_GROUP_SYSTEM, buf, PAGE_SIZE);
}

static ssize_t space_info_data_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_space_info(fs_info, BTRFS_BLOCK_GROUP_DATA, buf, PAGE_SIZE);
}

static ssize_t space_info_metadata_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_space_info(fs_info, BTRFS_BLOCK_GROUP_METADATA, buf, PAGE_SIZE);
}

static ssize_t __show_block_group_info(struct btrfs_fs_info *fs_info, u64 type, char *buf, size_t buf_size)
{
	ssize_t size = 0;
	u64 curr_bytenr = 0;

	while (true) {
		struct btrfs_block_group_cache *cache = NULL;

		cache = zbtrfs_lookup_first_block_group(fs_info, curr_bytenr);
		if (cache == NULL)
			break;

		/* if we are dumping all block-groups, dump also holes */
		if (cache->key.objectid > curr_bytenr && 
			(type & BTRFS_BLOCK_GROUP_TYPE_MASK) == BTRFS_BLOCK_GROUP_TYPE_MASK) {
			size += scnprintf(buf + size, buf_size - size, "BG HOLE[%llu:%llu]\n", curr_bytenr, cache->key.objectid - curr_bytenr);
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_CHUNK_ALLOC, "BG HOLE[%llu:%llu]", curr_bytenr, cache->key.objectid - curr_bytenr);
		}

		if (cache->flags & type) {
			spin_lock(&cache->lock);
			size += scnprintf(buf + size, buf_size - size, "[%s:%s:%llu:%llu:%s] u=%llu p=%llu r=%llu super=%llu %s %s\n",
				      btrfs_block_group_type_to_str(cache->flags),
				      btrfs_raid_type_to_str(cache->flags), cache->key.objectid, cache->key.offset,
				      btrfs_block_group_caching_to_str(cache->cached),
				      btrfs_block_group_used(&cache->item), cache->pinned, cache->reserved, cache->bytes_super,
				      cache->dirty ? "DIRTY" : "", cache->ro ? "RO" : "");
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "[%s:%s:%llu:%llu:%s] u=%llu p=%llu r=%llu super=%llu %s %s",
				      btrfs_block_group_type_to_str(cache->flags),
				      btrfs_raid_type_to_str(cache->flags), cache->key.objectid, cache->key.offset,
				      btrfs_block_group_caching_to_str(cache->cached),
				      btrfs_block_group_used(&cache->item), cache->pinned, cache->reserved, cache->bytes_super,
				      cache->dirty ? "DIRTY" : "", cache->ro ? "RO" : "");
			spin_unlock(&cache->lock);
		}

		curr_bytenr = cache->key.objectid + cache->key.offset;
		btrfs_put_block_group(cache);
	}

	return size;
}

static ssize_t block_group_system_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_block_group_info(fs_info, BTRFS_BLOCK_GROUP_SYSTEM, buf, PAGE_SIZE);
}

static ssize_t block_group_data_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_block_group_info(fs_info, BTRFS_BLOCK_GROUP_DATA, buf, PAGE_SIZE);
}

static ssize_t block_group_metadata_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_block_group_info(fs_info, BTRFS_BLOCK_GROUP_METADATA, buf, PAGE_SIZE);
}

static ssize_t block_group_all_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_block_group_info(fs_info, BTRFS_BLOCK_GROUP_TYPE_MASK, buf, PAGE_SIZE);
}

#if 0
static ssize_t __show_block_group_free_space_cache_info(struct btrfs_fs_info *fs_info, u64 type, char *buf, size_t buf_size)
{
	ssize_t size = 0;
	struct btrfs_space_info *si = NULL;
	unsigned int idx = 0;

	si = zbtrfs_find_space_info(fs_info, type);
	if (si == NULL)
		return 0;

	down_read(&si->groups_sem);

	for (idx = 0; idx < BTRFS_NR_RAID_TYPES; ++idx) {
		struct btrfs_block_group_cache *cache = NULL;

		list_for_each_entry(cache, &si->block_groups[idx], list) {
			char type_str[4] = {'\0'};
			struct btrfs_free_space_ctl *ctl = cache->free_space_ctl;
			u64 conseq_bytes = 0, free_bytes = 0;

			if (ctl == NULL) {
				size += scnprintf(buf + size, buf_size - size, "[%s:%s:%llu:%llu:%s] - has no free_space_ctl???\n",
					              btrfs_block_group_type_to_str(cache->flags, type_str),
					              btrfs_raid_type_to_str(cache->flags), cache->key.objectid, cache->key.offset,
					              btrfs_block_group_caching_to_str(cache->cached));
				ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_FREE_SP_CACHE, "[%s:%s:%llu:%llu:%s] - has no free_space_ctl???",
					      btrfs_block_group_type_to_str(cache->flags, type_str),
					      btrfs_raid_type_to_str(cache->flags), cache->key.objectid, cache->key.offset,
					      btrfs_block_group_caching_to_str(cache->cached));
				continue;
			}

			spin_lock(&ctl->tree_lock);
			size += zbtrfs_sysfs_short_dump_locked(ctl, cache, buf + size, buf_size - size, Z_KDEB1, &conseq_bytes, &free_bytes);
			spin_unlock(&ctl->tree_lock);
		}
	}

	up_read(&si->groups_sem);

	return size;
}

static ssize_t block_group_system_free_space_cache_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_block_group_free_space_cache_info(fs_info, BTRFS_BLOCK_GROUP_SYSTEM, buf, PAGE_SIZE);
}

static ssize_t block_group_data_free_space_cache_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_block_group_free_space_cache_info(fs_info, BTRFS_BLOCK_GROUP_DATA, buf, PAGE_SIZE);
}

static ssize_t block_group_metadata_free_space_cache_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return __show_block_group_free_space_cache_info(fs_info, BTRFS_BLOCK_GROUP_METADATA, buf, PAGE_SIZE);
}

static u64 free_space_cache_bytenr = 0;

static ssize_t free_space_cache_details_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	ssize_t size = 0;
	u64 logical = free_space_cache_bytenr;
	char type_str[4] = {'\0'};
	struct btrfs_block_group_cache *cache = NULL;
	struct btrfs_free_space_ctl *ctl = NULL;

	cache = btrfs_lookup_block_group(fs_info, free_space_cache_bytenr);
	if (cache == NULL || cache->key.objectid != logical) {
		size += scnprintf(buf + size, PAGE_SIZE - size, "No block group found that starts at %llu\n", logical);
		goto out;
	}

	size += scnprintf(buf + size, PAGE_SIZE - size, "Dump free-space-cache of [%s:%llu:%llu:%s]:\n",
		              btrfs_block_group_type_to_str(cache->flags, type_str),
		              cache->key.objectid, cache->key.offset,
		              btrfs_block_group_caching_to_str(cache->cached));
	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_FREE_SP_CACHE, "Dump free-space-cache of [%s:%llu:%llu:%s]:",
		              btrfs_block_group_type_to_str(cache->flags, type_str),
		              cache->key.objectid, cache->key.offset,
		              btrfs_block_group_caching_to_str(cache->cached));

	if ((ctl = cache->free_space_ctl) == NULL) {
		size += scnprintf(buf + size, PAGE_SIZE - size, "No free-space-cache control???\n");
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_FREE_SP_CACHE, "No free-space-cache control???");
		goto out;
	}

	spin_lock(&ctl->tree_lock);
	size += zbtrfs_sysfs_dump_locked(ctl, cache,
		                             buf + size, PAGE_SIZE - size,
		                             Z_KDEB1);
	spin_unlock(&ctl->tree_lock);

out:
	if (cache)
		btrfs_put_block_group(cache);

	return size;
}

static ssize_t free_space_cache_details_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count)
{
	ssize_t ret = 0;

	ret = kstrtou64(buf, 0/*base*/, &free_space_cache_bytenr);
	if (ret < 0)
		zklog(Z_KERR, "Failed parsing `logical` out of: [%s]", buf);
	else
		ret = count;

	return ret;
}
#endif

atomic_t device_map_show_should_stop = ATOMIC_INIT(0);

static ssize_t device_map_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	int ret = 0;
	ssize_t size = 0;
	struct btrfs_path *path = NULL;
	struct btrfs_key key;
	u64 prev_dev_ext_end = 0;

	atomic_set(&device_map_show_should_stop, 0);

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	key.objectid = 1; /*first device id begins from 1 */
	key.type = BTRFS_DEV_EXTENT_KEY;
	key.offset = 0;

	ret = btrfs_search_slot(NULL/*trans*/, fs_info->dev_root, &key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret < 0) {
		size = ret;
		goto out;
	}

	while (1) {
		struct extent_buffer *leaf = path->nodes[0];
		struct btrfs_dev_extent *dev_ext = NULL;
		u64 logical = 0, dev_ext_len = 0;
		struct btrfs_block_group_cache *block_group = NULL;

		/* check if we need to abort the scan */
		if (atomic_read(&device_map_show_should_stop) != 0)
			break;

		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(fs_info->dev_root, path);
			if (ret < 0)
				goto out;
			if (ret)
				break;
			continue;
		}

		btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
		if (key.type != BTRFS_DEV_EXTENT_KEY)
			goto next_slot;

		dev_ext = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_dev_extent);
		logical = btrfs_dev_extent_chunk_offset(leaf, dev_ext);
		dev_ext_len = btrfs_dev_extent_length(leaf, dev_ext);

		/* find the block-group for the device extent */
		block_group = zbtrfs_lookup_first_block_group(fs_info, logical);
		if (block_group == NULL) {
			size += scnprintf(buf + size, PAGE_SIZE - size, "ERROR: devext[%llu:%llu:%llu] chunk_offset=%llu NO BLOCK_GROUP!!!\n",
				        key.objectid, key.offset, dev_ext_len, logical);
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CHUNK_ALLOC, "ERROR: devext[%llu:%llu:%llu] chunk_offset=%llu NO BLOCK_GROUP!!!", 
				      key.objectid, key.offset, dev_ext_len, logical);
			goto devext_done;
		}

		/* shouldn't happen */
		if (block_group->key.objectid != logical) {
			size += scnprintf(buf + size, PAGE_SIZE - size, "ERROR: devext[%llu:%llu:%llu] chunk_offset=%llu but BG[%llu:%llu]\n",
				              key.objectid, key.offset, dev_ext_len,
				              logical, block_group->key.objectid, block_group->key.offset);
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CHUNK_ALLOC, "ERROR: devext[%llu:%llu:%llu] chunk_offset=%llu but BG[%llu:%llu]",
				      key.objectid, key.offset, dev_ext_len,
				      logical, block_group->key.objectid, block_group->key.offset);
		}

		size += scnprintf(buf + size, PAGE_SIZE - size, "[%llu:%llu:%llu]=>[%s:%s:%llu:%llu:%s]\n",
				          key.objectid, key.offset, dev_ext_len,
				          btrfs_block_group_type_to_str(block_group->flags),
				          btrfs_raid_type_to_str(block_group->flags), 
				          block_group->key.objectid, block_group->key.offset,
				          btrfs_block_group_caching_to_str(block_group->cached));
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "[%llu:%llu:%llu]=>[%s:%s:%llu:%llu:%s]",
			      key.objectid, key.offset, dev_ext_len,
				  btrfs_block_group_type_to_str(block_group->flags),
				  btrfs_raid_type_to_str(block_group->flags), 
				  block_group->key.objectid, block_group->key.offset,
				  btrfs_block_group_caching_to_str(block_group->cached));

		btrfs_put_block_group(block_group);

devext_done:
		/* 
		 * warn on holes - only if they are on the same raid-group.
		 * otherwise, it's ok to have a hole between different
		 * raid-groups
		 */
		if (key.offset > prev_dev_ext_end) {
			size += scnprintf(buf + size, PAGE_SIZE - size, "DEV HOLE: %llu => %llu\n",
				              prev_dev_ext_end, key.offset);
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_CHUNK_ALLOC, "DEV HOLE: %llu => %llu",
				      prev_dev_ext_end, key.offset);
		}

		prev_dev_ext_end = key.offset + dev_ext_len;

next_slot:
		++path->slots[0];
	}

out:
	btrfs_free_path(path);

	return size;
}

static ssize_t device_map_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count)
{
	atomic_set(&device_map_show_should_stop, 1);

	return count;
}

static ssize_t metadata_reservation_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	struct btrfs_fs_devices *fs_devices = fs_info->fs_devices;
	unsigned int tries = 5;
	ssize_t size = 0;

	while (tries > 0) {
		struct zbtrfs_mdata_rsv_ctx ctx;
		struct btrfs_device *device = NULL;

		if (!mutex_trylock(&fs_info->chunk_mutex)) {
			msleep(500);
			--tries;
			continue;
		}

		if (list_empty(&fs_devices->alloc_list))
			break;

		device = list_first_entry(&fs_devices->alloc_list, struct btrfs_device, dev_alloc_list);
		zbtrfs_mdata_rsv_ctx_init(&ctx, device, false/*for_shrink*/);
		
		size += scnprintf(buf + size, PAGE_SIZE - size, ZBTRFS_MDATA_RSV_CTX_FMT"\n", ZBTRFS_MDATA_RSV_CTX_PRINT(&ctx, device));

		if (device->dev_alloc_list.next != &fs_devices->alloc_list)
			size += scnprintf(buf + size, PAGE_SIZE - size, "MORE THAN ONE DEVICE!!!\n");

		mutex_unlock(&fs_info->chunk_mutex);
		break;
	}

	if (tries == 0)
		size += scnprintf(buf + size, PAGE_SIZE - size, "Failed locking chunk_mutex!\n");

	return size;
}

static ssize_t ztenant_inmem_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return zbtrfs_ztenant_inmem_show(fs_info, buf, PAGE_SIZE, Z_KDEB1);
}

static ssize_t zstats_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	ssize_t size = 0;

	size += zbtrfs_zstats_show(fs_info, buf, PAGE_SIZE);

	return size;
}

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS

/* Never have this in production!!! */
#if 0
static ssize_t fs_unit_tests_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	int ret = 0;
	ssize_t size = 0;
	
	ZBTRFS_SET_IN_UNIT_TEST(true);
	
	size += scnprintf(buf + size, PAGE_SIZE - size, "Running FS ztenant tests...\n");
	ret = zbtrfs_test_fs_ztenant(fs_info);
	size += scnprintf(buf + size, PAGE_SIZE - size, "DONE ret=%d\n", ret);
	
	ZBTRFS_SET_IN_UNIT_TEST(false);
	
	return size;
}

static ssize_t tree_corruption_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count)
{
	ZBTRFS_WARN(1, "FS[%s]: faking tree corruption!", fs_info->sb->s_id);
	ZBTRFS_TREE_CORRUPTION(fs_info);

	return count;
}

static ssize_t force_abort_trans_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count)
{
	int ret = 0;
	struct btrfs_trans_handle* trans = NULL;
	unsigned int input = 0;
	bool fake_tree_corruption = false;

	ret = kstrtouint(buf, 0, &input);
	if (ret == 0 && input == 17) {
		ZBTRFS_WARN(1, "FS[%s]: force tree corruption + abort transaction through SYSFS!", fs_info->sb->s_id);
		fake_tree_corruption = true;
	} else {
		ZBTRFS_WARN(1, "FS[%s]: force abort transaction through SYSFS!", fs_info->sb->s_id);
	}

	/* if transaction has been already aborted, we will not be able to attach */
	trans = btrfs_attach_transaction(fs_info->tree_root);
	if (IS_ERR(trans)) {
		int ret = PTR_ERR(trans);
		zklog(Z_KWARN, "FS[%s]: btrfs_attach_transaction() ret=%d", fs_info->sb->s_id, ret);
		trans = NULL;
	} else {
		zklog(Z_KWARN, "FS[%s]: force-aborting transid=%llu", fs_info->sb->s_id, trans->transid);
	}

	if (fake_tree_corruption)
		atomic64_set(&fs_info->zfs_info.corrupted_tree_transid, trans ? trans->transid : 1);
	zbtrfs_force_abort_transaction(trans, fs_info->tree_root, -EIO);

	if (trans)
		btrfs_end_transaction(trans, fs_info->tree_root);

	return count;
}

#else

static ssize_t fs_unit_tests_show(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, char *buf)
{
	return
		scnprintf(buf, PAGE_SIZE, "per-FS unit tests are disabled!\n");
}

static ssize_t tree_corruption_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count)
{
	ZBTRFSLOG(fs_info, Z_KWARN, "fake tree corruption disabled!");
	return -EACCES;
}

static ssize_t force_abort_trans_store(struct zbtrfs_attr *attr, struct btrfs_fs_info *fs_info, const char *buf, size_t count)
{
	ZBTRFSLOG(fs_info, Z_KWARN, "transaction abort through sysfs disabled!");
	return -EACCES;
}

#endif
#endif /*CONFIG_BTRFS_FS_RUN_SANITY_TESTS*/

