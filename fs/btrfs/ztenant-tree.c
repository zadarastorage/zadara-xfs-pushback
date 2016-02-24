#include "ctree.h"
#include "transaction.h"
#include "disk-io.h"

/* runtime entry for each tenant */
struct zbtrfs_ztenant_info {
	u16 tenant_id;
	
	/* used up to the latest transaction commit */
	atomic64_t bytes_used_synced;
	/* used including the currently-running transaction */
	atomic64_t bytes_used;
	
	/* link in dirty_ztenants */
	struct list_head dirty_link;
};

static struct kmem_cache *ztenant_cachep = NULL;

static void __ztenant_free(struct zbtrfs_ztenant_info *zt)
{
	if (zt)
		kmem_cache_free(ztenant_cachep, zt);
}

static struct zbtrfs_ztenant_info* __ztenant_alloc(u16 tenant_id, s64 bytes_used_synced, s64 bytes_used)
{
	struct zbtrfs_ztenant_info *zt = kmem_cache_alloc(ztenant_cachep, GFP_NOFS);
	if (zt) {
		zt->tenant_id = tenant_id;
		atomic64_set(&zt->bytes_used_synced, bytes_used_synced);
		atomic64_set(&zt->bytes_used, bytes_used);
		INIT_LIST_HEAD(&zt->dirty_link);
	}
	return zt;
}

static int __ztenant_add(struct btrfs_fs_info *fs_info, u16 tenant_id, s64 bytes_used_synced, s64 bytes_used)
{
	int ret = 0;
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	struct zbtrfs_ztenant_info *zt = NULL;

	zt = __ztenant_alloc(tenant_id, bytes_used_synced, bytes_used);
	if (zt == NULL) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "__ztenant_alloc(id=%u) failed", tenant_id);
		ret = -ENOMEM;
		goto out;
	}

	ret = radix_tree_preload(GFP_NOFS);
	if (ret) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "ztenant[%u]: radix_tree_preload() ret=%d", tenant_id, ret);
		goto out;
	}
	spin_lock(&zt_cfg->ztenants_lock);
	ret = radix_tree_insert(&zt_cfg->ztenants_radix, zt->tenant_id, zt);
	spin_unlock(&zt_cfg->ztenants_lock);
	radix_tree_preload_end();

	if (ret && ret != -EEXIST)
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "ztenant[%u]: radix_tree_insert() ret=%d", tenant_id, ret);

out:
	if (ret)
		__ztenant_free(zt);
	return ret;
}

/*
 * add or update ZTENANT_INFO item in the tenant tree.
 * @path - used only for storage, i.e., to avoid allocating it each time.
 */
static int __ztenant_add_or_update_item(struct btrfs_fs_info *fs_info, struct btrfs_trans_handle *trans, struct btrfs_path *path, 
                                        u16 tenant_id, s64 bytes_used)
{
	int ret = 0;
	struct btrfs_key key;
	struct extent_buffer *leaf = NULL;
	struct btrfs_ztenant_info_item *zt_item = NULL;
	bool new_item = false;

	ZBTRFS_BUG_ON(bytes_used < 0 || bytes_used > LLONG_MAX);

	key.objectid = tenant_id;
	key.type = BTRFS_ZTENANT_INFO_KEY;
	key.offset = 0;

	memset(path, 0, sizeof(*path));
	path->leave_spinning = 1;

	ret = btrfs_search_slot(trans, fs_info->ztenant_root, &key, path, 0/*ins_len*/, 1/*cow*/);
	if (ret < 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "ztenant[%u] btrfs_search_slot(len=0,cow=1) ret=%d", tenant_id, ret);
		goto out;
	}
	if (ret) {
		new_item = true;

		btrfs_release_path(path);

		memset(path, 0, sizeof(*path));
		path->leave_spinning = 1;

		ret = btrfs_insert_empty_item(trans, fs_info->ztenant_root, path, &key, sizeof(*zt_item));
		if (ret < 0) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "ztenant[%u] btrfs_insert_empty_item() ret=%d", tenant_id, ret);
			goto out;
		}
		if (ret) {
			ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "ztenant[%u] btrfs_insert_empty_item() ret=%d", tenant_id, ret);
			ret = -ENOENT;
			goto out;
		}
	}

	leaf = path->nodes[0];
	zt_item = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_ztenant_info_item);
	if (zklog_will_print_tag(Z_KDEB1, ZKLOG_TAG_ZTENANT)) {
		if (!new_item) {
			u64 prev_bytes_used = btrfs_ztenant_bytes_used(leaf, zt_item);
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u] UPDATE %llu=>%llu", tenant_id, prev_bytes_used, bytes_used);
		} else {
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u] NEW %llu", tenant_id, bytes_used);
		}
	}

	btrfs_set_ztenant_bytes_used(leaf, zt_item, bytes_used);
	btrfs_mark_buffer_dirty(leaf);

out:
	btrfs_release_path(path);
	return ret;
}

/*
 * delete ZTENANT_INFO item from the tenant tree.
 * @path - used only for storage, i.e., to avoid allocating it each time.
 */
static int __ztenant_delete_item(struct btrfs_fs_info *fs_info, struct btrfs_trans_handle *trans, struct btrfs_path *path, 
                                 u16 tenant_id)
{
	int ret = 0;
	struct btrfs_key key;

	key.objectid = tenant_id;
	key.type = BTRFS_ZTENANT_INFO_KEY;
	key.offset = 0;

	memset(path, 0, sizeof(*path));

	ret = btrfs_search_slot(trans, fs_info->ztenant_root, &key, path, -1/*ins_len*/, 1/*cow*/);
	if (ret < 0)
		goto out;
	if (ret) {
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_ZTENANT, "ztenant[%u]: ZTENANT_INFO not found", tenant_id);
		ret = 0;
		goto out;
	}

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u] DEL", tenant_id);

	ret = btrfs_del_item(trans, fs_info->ztenant_root, path);
	if (ret)
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "ztenant[%u]: btrfs_del_item() ret=%d", tenant_id, ret);

out:
	btrfs_release_path(path);
	return ret;
}

void zbtrfs_ztenant_init_config(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;

	/* will be modified under spinlock, hence GFP_ATOMIC */
	INIT_RADIX_TREE(&zt_cfg->ztenants_radix, GFP_ATOMIC);
	INIT_LIST_HEAD(&zt_cfg->dirty_ztenants);
	spin_lock_init(&zt_cfg->ztenants_lock);
	atomic_set(&zt_cfg->updaters, 0);
	atomic_set(&zt_cfg->syncing, 0);
}

void zbtrfs_ztenant_free_config(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	unsigned int ztenants = 0;
	LIST_HEAD(ztenants_to_free);

	ZBTRFS_WARN_ON(atomic_read(&zt_cfg->updaters));
	ZBTRFS_WARN_ON(atomic_read(&zt_cfg->syncing));

	do {
		void* results[16] = {NULL};
		unsigned int zt_idx = 0;

		/* lookup a bunch of tenants under spinlock, and delete them from the radix */
		spin_lock(&zt_cfg->ztenants_lock);

		ztenants = radix_tree_gang_lookup(&zt_cfg->ztenants_radix, results, 0/*first_index*/, ARRAY_SIZE(results));
		for (zt_idx = 0; zt_idx < ztenants; ++zt_idx) {
			struct zbtrfs_ztenant_info *zt = results[zt_idx];
			struct zbtrfs_ztenant_info *zt_del = NULL;

			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "freeing ztenant[%u]", zt->tenant_id);

			zt_del = radix_tree_delete(&zt_cfg->ztenants_radix, zt->tenant_id);
			ZBTRFS_WARN_ON(zt_del != zt);

			list_del_init(&zt->dirty_link); /* in case it was dirty */
			list_add_tail(&zt->dirty_link, &ztenants_to_free); /* we will free it later */
		}

		spin_unlock(&zt_cfg->ztenants_lock);

	} while (ztenants != 0);

	/* if we have somebody to free, we need a grace period */
	if (!list_empty(&ztenants_to_free)) {
		struct zbtrfs_ztenant_info *zt = NULL, *zt_bckp = NULL;

		synchronize_rcu();

		/* now we can free all those guys */
		list_for_each_entry_safe(zt, zt_bckp, &ztenants_to_free, dirty_link) {
			list_del_init(&zt->dirty_link);
			__ztenant_free(zt);
		}
	}

	ZBTRFS_WARN_ON(!list_empty(&zt_cfg->dirty_ztenants));
}

/*
 * loads the tenants tree and populates the in-memory config.
 * called during mount sequence.
 */
int zbtrfs_ztenant_load_config(struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	struct btrfs_path *path = NULL;
	struct btrfs_key key;

	if (fs_info->ztenant_root == NULL)
		goto out;

	path = btrfs_alloc_path();
	if (path == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	path->reada = 1;

	key.objectid = 0;
	key.type = BTRFS_ZTENANT_INFO_KEY;
	key.offset = 0;

	ret = btrfs_search_slot(NULL/*trans*/, fs_info->ztenant_root, &key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret < 0)
		goto out;

	while (true) {
		int slot = path->slots[0];
		struct extent_buffer *leaf = path->nodes[0];
		struct btrfs_key found_key;

		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(fs_info->ztenant_root, path);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			/* no more tenants in the tree */
			ret = 0;
			break;
		}

		btrfs_item_key_to_cpu(leaf, &found_key, slot);
		if (found_key.type == BTRFS_ZTENANT_INFO_KEY && found_key.offset == 0) {
			struct btrfs_ztenant_info_item *zt_item = NULL;
			u64 bytes_used = 0;

			zt_item = btrfs_item_ptr(leaf, slot, struct btrfs_ztenant_info_item);
			bytes_used = btrfs_ztenant_bytes_used(leaf, zt_item);
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%llu]: bytes_used=%llu", found_key.objectid, bytes_used);

			/* if the values are bogus, ignore this tenant */
			if (ZBTRFS_WARN((found_key.objectid > ZBTRFS_ZTENANT_MAX_ID || bytes_used > LLONG_MAX),
				            "FS[%s]: ztenant[%llu](max tenant ID=%u) bytes_used=%llu(max bytes used=%llu)",
				            fs_info->sb->s_id, found_key.objectid, ZBTRFS_ZTENANT_MAX_ID,
				            bytes_used, LLONG_MAX))
				goto next_slot;

			/* castings are safe now */
			ret = __ztenant_add(fs_info, (u16)found_key.objectid, (s64)bytes_used, (s64)bytes_used);
			/* if this tenant already existed...somehow...let's move on */
			if (ret && ret != -EEXIST)
				break;

			ret = 0;
		}

next_slot:
		path->slots[0]++;
	}

out:
	btrfs_free_path(path);
	return ret;
}

/*
 * called when a new data EXTENT_ITEM is added to the extent tree or
 * when a data EXTENT_ITEM is removed from the extent tree.
 * accounts the space for a particular tenant by updating
 * the in-memory info.
 * @param trans currently not used, just to ensure that caller is attached to a transaction
 */
int zbtrfs_ztenant_account_usage(struct btrfs_fs_info *fs_info, struct btrfs_trans_handle *trans, u16 tenant_id, s64 bytes_delta)
{
	int ret = 0;
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	bool added_tenant = false;
	struct zbtrfs_ztenant_info *zt = NULL;

	/* quickly ensure that we are not syncing the tenant info right now */
	atomic_inc(&zt_cfg->updaters);
	if (ZBTRFS_WARN(atomic_read(&zt_cfg->syncing), 
		"FS[%s]: trying to update ztenants while they are syncing", fs_info->sb->s_id)) {
		ret = -EBUSY;
		goto out;
	}

	if (ZBTRFS_WARN(IS_ERR_OR_NULL(trans), "FS[%s]: must be called with a transaction!", fs_info->sb->s_id)) {
		ret = -EINVAL;
		goto out;
	}

search_again:
	rcu_read_lock();
	zt = radix_tree_lookup(&zt_cfg->ztenants_radix, tenant_id);
	if (zt) {
		s64 new_used = atomic64_add_return(bytes_delta, &zt->bytes_used);
		bool set_dirty = false;

		/* we need to mark the tenant as 'dirty' */
		if (list_empty(&zt->dirty_link)) {
			/* note that we are upgrading RCU reader to RCU updater here */
			spin_lock(&zt_cfg->ztenants_lock);
			if (list_empty(&zt->dirty_link)) {
				list_add_tail(&zt->dirty_link, &zt_cfg->dirty_ztenants);
				set_dirty = true;
			}
			spin_unlock(&zt_cfg->ztenants_lock);
		}

		if (zklog_will_print_tag(Z_KDEB2, ZKLOG_TAG_ZTENANT)) {
			s64 old_used = new_used - bytes_delta;
			if (bytes_delta >= 0)
				ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_ZTENANT, "ztenant[%u]: old(%lld)+delta(%lld)=%lld",
					          zt->tenant_id, old_used, bytes_delta, new_used);
			else
				ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_ZTENANT, "ztenant[%u]: old(%lld)-delta(%lld)=%lld",
					          zt->tenant_id, old_used, -bytes_delta, new_used);
		}
		if (ZBTRFS_WARN(new_used < 0, "FS[%s]: ztenant[%u]: old(%lld)+delta(%lld)=%lld(<0)",
			fs_info->sb->s_id, zt->tenant_id, new_used - bytes_delta, bytes_delta, new_used)) {
			/*
			 * ideally, we should abort transaction here,
			 * but then it might happen on each subsequent mount.
			 * so for now, just rollback the operation.
			 */
			atomic64_add_return(-bytes_delta, &zt->bytes_used);
		}

		if (zklog_will_print_tag(Z_KDEB1, ZKLOG_TAG_ZTENANT) && set_dirty)
			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u]: becomes dirty with used=%lld(delta=%lld)",
				          zt->tenant_id, new_used, bytes_delta);

		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();

	/* alloc a new tenant and insert into radix */
	if (ZBTRFS_WARN(added_tenant,
		"FS[%s]: ztenant[%u]: dissappeared after we added it???",
		fs_info->sb->s_id, zt->tenant_id)) {
		ret = -ECANCELED;
		goto out;
	}

	ret = __ztenant_add(fs_info, tenant_id, 0/*bytes_used_synced*/, 0/*bytes_used*/);
	if (ret == -EEXIST) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u]: was already inserted", tenant_id);
		ret = 0;
	}
	if (ret == 0) {
		added_tenant = true;
		goto search_again;
	}

out:
	atomic_dec(&zt_cfg->updaters);
	return ret;
}

/*
 * called during transaction commit.
 * syncs the dirty tenant information into the tenant tree.
 * the caller guarantees that nobody will be adding/deleting
 * any data EXTENT_ITEMs until the transaction commits.
 */
int zbtrfs_run_ztenants(struct btrfs_trans_handle *trans, struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	struct zbtrfs_ztenant_info *zt = NULL, *zt_bckp = NULL;
	int prev_syncing = 0;
	struct btrfs_path *path = NULL;
	LIST_HEAD(ztenants_to_free);

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "run tenants");

	prev_syncing = atomic_inc_return(&zt_cfg->syncing) - 1;
	if (ZBTRFS_WARN(prev_syncing != 0, "FS[%s]: prev_syncing=%d ???", fs_info->sb->s_id, prev_syncing)) {
		ret = -ECANCELED;
		goto out;
	}
	if (ZBTRFS_WARN(atomic_read(&zt_cfg->updaters), "FS[%s]: there are updaters while we are syncing!!!", fs_info->sb->s_id)) {
		ret = -ECANCELED;
		goto out;
	}

	/* 
	 * we don't have to lock the list here; we are
	 * the only one accessing it right now.
	 */
	list_for_each_entry_safe(zt, zt_bckp, &zt_cfg->dirty_ztenants, dirty_link) {
		s64 bytes_used_synced = atomic64_read(&zt->bytes_used_synced);
		s64 bytes_used = atomic64_read(&zt->bytes_used);

		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u]: dirty %lld=>%lld", zt->tenant_id, bytes_used_synced, bytes_used);
		if (ZBTRFS_WARN(bytes_used < 0, "FS[%s]: ztenant[%u] bytes_used=%lld (synced=%lld)",
			            fs_info->sb->s_id, zt->tenant_id, bytes_used, bytes_used_synced)) {
			ret = -EILSEQ;
			break;
		}

		/* alloc path once */
		if (path == NULL) {
			path = btrfs_alloc_path();
			if (path == NULL) {
				ret = -ENOMEM;
				break;
			}
		}

		/* sync into the tenant tree */
		if (bytes_used > 0)
			ret = __ztenant_add_or_update_item(fs_info, trans, path, zt->tenant_id, bytes_used);
		else
			ret = __ztenant_delete_item(fs_info, trans, path, zt->tenant_id);
		if (ret)
			break;

		/* update in-memory info */
		list_del_init(&zt->dirty_link); /* not dirty anymore! */
		atomic64_set(&zt->bytes_used_synced, bytes_used);
		if (bytes_used == 0) {
			struct zbtrfs_ztenant_info *zt_del = NULL;

			ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u]: remove", zt->tenant_id);

			/* 
			 * we need to lock the radix, because there might be
			 * concurrent readers via RCU.
			 */
			spin_lock(&zt_cfg->ztenants_lock);
			zt_del = radix_tree_delete(&zt_cfg->ztenants_radix, zt->tenant_id);
			ZBTRFS_WARN_ON(zt_del != zt);
			spin_unlock(&zt_cfg->ztenants_lock);

			/* we will free it later */
			list_add_tail(&zt_del->dirty_link, &ztenants_to_free);
		}
	}

	/* if we have to free somebody, we must do a grace period */
	if (!list_empty(&ztenants_to_free)) {
		synchronize_rcu();

		/* now we can free all those guys */
		list_for_each_entry_safe(zt, zt_bckp, &ztenants_to_free, dirty_link) {
			list_del_init(&zt->dirty_link);
			__ztenant_free(zt);
		}
	}

out:
	btrfs_free_path(path);
	/*
	 * if we failed, transaction will be aborted, but 
	 * anyways, we cleanup.
	 */
	if (ret)
		atomic_dec(&zt_cfg->syncing);
	return ret;
}

/*
 * at this point, we are ready to commit.
 * we must not have any new dirty tenants.
 */
void zbtrfs_ztenants_assert_uptodate(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	int syncing = 0;

	/* we are syncing */
	ZBTRFS_BUG_ON(atomic_read(&zt_cfg->syncing) != 1);

	/* there should not be any updaters right now */
	ZBTRFS_BUG_ON(atomic_read(&zt_cfg->updaters));

	/* should not be any dirty tenants */
	ZBTRFS_BUG_ON(!list_empty(&zt_cfg->dirty_ztenants));

	/* done syncing */
	syncing = atomic_dec_return(&zt_cfg->syncing);
	ZBTRFS_BUG_ON(syncing != 0);
}

void zbtrfs_ztenant_get_used(struct btrfs_fs_info *fs_info, u16 tenant_id, u64 *bytes_used, u64 *bytes_used_synced)
{
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	struct zbtrfs_ztenant_info *zt = NULL;

	rcu_read_lock();
	zt = radix_tree_lookup(&zt_cfg->ztenants_radix, tenant_id);
	if (zt == NULL) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_ZTENANT, "ztenant[%u] not found", tenant_id);
		*bytes_used = 0;
		*bytes_used_synced = 0;
	} else {
		*bytes_used = atomic64_read(&zt->bytes_used);
		*bytes_used_synced = atomic64_read(&zt->bytes_used_synced);
	}
	rcu_read_unlock();
}

/* sysfs support */
ssize_t zbtrfs_ztenant_inmem_show(struct btrfs_fs_info *fs_info, char *buf, size_t buf_size, enum zklog_level_t level)
{
	ssize_t size = 0;
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	unsigned int ztenants = 0;
	unsigned long tenant_id = 0;
	u64 total_bytes_used_synced = 0, total_bytes_used = 0;

	if (buf)
		size += scnprintf(buf + size, buf_size - size, "upd=%d syncing=%d\n", atomic_read(&zt_cfg->updaters), atomic_read(&zt_cfg->syncing));
	ZBTRFSLOG_TAG(fs_info, level, ZKLOG_TAG_ZTENANT, "upd=%d syncing=%d", atomic_read(&zt_cfg->updaters), atomic_read(&zt_cfg->syncing));

	do {
		void* results[16] = {NULL};
		unsigned int zt_idx = 0;

		rcu_read_lock();
		ztenants = radix_tree_gang_lookup(&zt_cfg->ztenants_radix, results, tenant_id, ARRAY_SIZE(results));
		for (zt_idx = 0; zt_idx < ztenants; ++zt_idx) {
			struct zbtrfs_ztenant_info *zt = results[zt_idx];
			u64 bytes_used_synced = atomic64_read(&zt->bytes_used_synced);
			u64 bytes_used = atomic64_read(&zt->bytes_used);

			if (buf)
				size += scnprintf(buf + size, buf_size - size, "ID=%u used=%lld(%lldMB) synced=%lld(%lldMB)%s\n",
							zt->tenant_id,
							bytes_used, bytes_used / ONE_MB,
							bytes_used_synced, bytes_used_synced / ONE_MB,
							list_empty(&zt->dirty_link) ? "" : " DIRTY");
			ZBTRFSLOG_TAG(fs_info, level, ZKLOG_TAG_ZTENANT, "ztenant[%u]: used=%lld(%lldMB) synced=%lld(%lldMB)%s",
				zt->tenant_id,
				bytes_used, bytes_used / ONE_MB,
				bytes_used_synced, bytes_used_synced / ONE_MB,
				list_empty(&zt->dirty_link) ? "" : " DIRTY");

			total_bytes_used_synced += bytes_used_synced;
			total_bytes_used += bytes_used;

			/* for next gang lookup */
			tenant_id = zt->tenant_id + 1;
		}
		rcu_read_unlock();

	} while (ztenants != 0);

	if (buf)
		size += scnprintf(buf + size, buf_size - size, "TOTAL used=%lld(%lldMB) synced=%lld(%lldMB)\n",
		                  total_bytes_used, total_bytes_used / ONE_MB,
		                  total_bytes_used_synced, total_bytes_used_synced / ONE_MB);
	ZBTRFSLOG_TAG(fs_info, level, ZKLOG_TAG_ZTENANT, "TOTAL used=%lld(%lldMB) synced=%lld(%lldMB)",
		total_bytes_used, total_bytes_used / ONE_MB,
		total_bytes_used_synced, total_bytes_used_synced / ONE_MB);

	return size;
}

/*
 * At this point, the FS is clean and there is no other activity. 
 * In case we are upgrading from older kernel, we need to
 * create the tenant tree, and to account for all used DATA
 * under tenantid=ZBTRFS_ZTENANT_SYSTEM_ID.
 */
int zbtrfs_ztenant_create_tree_if_needed(struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	struct btrfs_trans_handle * trans = NULL;
	struct btrfs_root *ztenant_root = NULL;
	struct btrfs_space_info *sinfo = NULL;
	u64 bytes_used = 0;

	if (fs_info->ztenant_root)
		goto out;

	/* an extra protection; we should not be called on read-only mount */
	if (ZBTRFS_WARN(fs_info->sb->s_flags & MS_RDONLY, "FS[%s]: should not be called on read-only mount!", fs_info->sb->s_id)) {
		ret = -EROFS;
		goto out;
	}

	ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_ZTENANT, "creating a new ztenant tree");
	/*
	 * We shouldn't use "btrfs_start_transaction" here.
	 * The reason is that if somehow the new transaction gets BLOCKED
	 * (which really should not happen), we will wait for it in wait_current_trans,
	 * but nobody will commit it, because commit thread is now waiting for us.
	 */
	trans = btrfs_join_transaction(fs_info->tree_root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		trans = NULL;
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "btrfs_start_transaction() ret=%d", ret);
		goto out;
	}
		
	ztenant_root = btrfs_create_tree(trans, fs_info, BTRFS_ZTENANT_TREE_OBJECTID);
	if (IS_ERR(ztenant_root)) {
		ret = PTR_ERR(ztenant_root);
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_ZTENANT, "btrfs_create_tree(BTRFS_ZTENANT_TREE_OBJECTID) ret=%d", ret);
		btrfs_abort_transaction(trans, fs_info->tree_root, ret);
		btrfs_end_transaction(trans, fs_info->tree_root);
		goto out;
	}
	ztenant_root->block_rsv = &fs_info->global_block_rsv;
	fs_info->ztenant_root = ztenant_root;

	/*
	 * now we need to account for tenantid=ZBTRFS_ZTENANT_SYSTEM_ID.
	 * since we know that FS is clean and quiet right now,
	 * we just take all the DATA space-infos, and this will be
	 * the needed value.
	 */
	ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_ZTENANT, "scanning space_infos");
	rcu_read_lock();
	list_for_each_entry_rcu(sinfo, &fs_info->space_info, list) {
		if (btrfs_mixed_space_info(sinfo)) {
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_ZTENANT, "FS[%s]: skipping MIXES space_info", fs_info->sb->s_id);
			continue;
		}
		if (sinfo->flags == BTRFS_BLOCK_GROUP_DATA) {
			s64 total_bytes_pinned = 0;

			spin_lock(&sinfo->lock);

			zbtrfs_show_space_info_spinlocked(fs_info, sinfo, NULL/*buf*/, 0/*buf_size*/, "DATA", Z_KINFO, ZKLOG_TAG_ZTENANT);
			/* everything should be quiet */
			ZBTRFS_WARN_ON(sinfo->bytes_pinned > 0);
			ZBTRFS_WARN_ON(sinfo->bytes_reserved > 0);
			total_bytes_pinned = percpu_counter_sum(&sinfo->total_bytes_pinned);
			ZBTRFS_WARN_ON(total_bytes_pinned != 0);

			bytes_used += sinfo->bytes_used;

			spin_unlock(&sinfo->lock);
		}
	}
	rcu_read_unlock();

	if (bytes_used > 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_ZTENANT, "account tenant=%u for %llu bytes and commmit", ZBTRFS_ZTENANT_SYSTEM_ID, bytes_used);
		ret = zbtrfs_ztenant_account_usage(fs_info, trans, ZBTRFS_ZTENANT_SYSTEM_ID, bytes_used);
	} else {
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_ZTENANT, "FS[%s]: no DATA was allocated", fs_info->sb->s_id);
	}
	if (ret) {
		btrfs_abort_transaction(trans, fs_info->tree_root, ret);
		btrfs_end_transaction(trans, fs_info->tree_root);
	} else {
		ret = btrfs_commit_transaction(trans, fs_info->tree_root);
	}

out:
	return ret;
}

int zbtrfs_ztenant_init(void)
{
	ztenant_cachep = kmem_cache_create("zbtrfs_ztenant",
			sizeof(struct zbtrfs_ztenant_info), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
			NULL);
	if (ztenant_cachep == NULL) {
		zklog_tag(Z_KERR, ZKLOG_TAG_ZTENANT, "kmem_cache_create(zbtrfs_ztenant) failed");
		return -ENOMEM;
	}

	return 0;
}

void zbtrfs_ztenant_exit(void)
{
	if (ztenant_cachep) {
		kmem_cache_destroy(ztenant_cachep);
		ztenant_cachep = NULL;
	}
}


