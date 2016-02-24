/*
 * extent-tree-related code (etc) added by Zadara.
 * This file is meant to be included directly from fs/btrfs/extent-tree.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 * If Zadara changes are ever accepted by the community, the contents of this file
 * will move into extent-tree.c and this file will disappear.
 */

#include "zjournal.h"

/************************ chunk allocation **********************************/

/*
 * Used in cases, where we don't want to account space_info->bytes_may_use fully.
 * Decrement from it whatever is in global reserve, because it can be used for allocations.
 * But make sure some space is still left in the global reserve.
 * Note: space_info must be spinlocked, but global reserve must not be
 */
u64 zbtrfs_adjust_bytes_may_use_space_info_spinlocked(struct btrfs_fs_info *fs_info, struct btrfs_space_info *space_info,
                                                      u64 *global_rsv_size, u64 *global_rsv_reserved)
{
	struct btrfs_block_rsv *global_rsv = &fs_info->global_block_rsv;
	u64 bytes_may_use = space_info->bytes_may_use;

	/* only METADATA and not mixed relevant here */
	if (!((space_info->flags & BTRFS_BLOCK_GROUP_METADATA) && !btrfs_mixed_space_info(space_info)))
		goto out;

	assert_spin_locked(&space_info->lock);

	spin_lock(&global_rsv->lock);

	if (global_rsv_size)
		*global_rsv_size = global_rsv->size;
	if (global_rsv_reserved)
		*global_rsv_reserved = global_rsv->reserved;

	if (ZBTRFS_WARN(bytes_may_use < global_rsv->reserved, "FS[%s]: bytes_may_use(%llu) < %s[size=%llu reserved=%llu]",
					fs_info->sb->s_id, bytes_may_use,
					btrfs_block_rsv_type_to_str(global_rsv->type), global_rsv->size, global_rsv->reserved)) {
		spin_unlock(&global_rsv->lock);
		goto out;
	}

	if (global_rsv->reserved > ZBTRFS_GLOBAL_RSV_SLACK_BYTES)
		bytes_may_use -= (global_rsv->reserved - ZBTRFS_GLOBAL_RSV_SLACK_BYTES);

	spin_unlock(&global_rsv->lock);

out:
	return bytes_may_use;
}

/************************ misc **********************************/

struct btrfs_space_info* zbtrfs_find_space_info(struct btrfs_fs_info *fs_info, u64 type)
{
	return __find_space_info(fs_info, type);
}

struct btrfs_block_group_cache *
zbtrfs_lookup_first_block_group(struct btrfs_fs_info *info, u64 bytenr)
{
	return btrfs_lookup_first_block_group(info, bytenr);
}

/************************ device-extent allocation adjustments *************/

/*
 * This function is called during chunk allocation, or at least when
 * chunk_mutex is locked. Or the caller can somehow ensure that device->total_bytes
 * will not change suddenly.
 * We assume:
 * - SINGLE policy is used for METADATA and SYSTEM
 * - we have a single device
 *
 * @param for_shrink true iff we are now in the process of shrinking the device
 */
void zbtrfs_mdata_rsv_ctx_init(struct zbtrfs_mdata_rsv_ctx *ctx, struct btrfs_device *device, bool for_shrink)
{
	struct btrfs_fs_info *fs_info = device->dev_root->fs_info;
	struct btrfs_space_info *si = NULL;

	ZBTRFS_WARN_ON(!mutex_is_locked(&fs_info->chunk_mutex));

	memset(ctx, 0, sizeof(struct zbtrfs_mdata_rsv_ctx));

	/*
	 * Note: there might be pending chunks, which still exist only in memory,
	 * and extent tree/chunk tree/device tree might not be updated about
	 * their existance yet.
	 * However, space_infos that we are going to traverse ARE already updated
	 * about pending chunks (via btrfs_make_block_group),
	 * so we will take them into account as well.
	 */
	rcu_read_lock();
	list_for_each_entry_rcu(si, &device->dev_root->fs_info->space_info, list) {
		/* we use SINGLE policy everywhere, so total_bytes==disk_bytes */
		ZBTRFS_WARN_ON(si->total_bytes != si->disk_total);

		/* we should not have mixed stuff in production - leave it alone */
		if (btrfs_mixed_space_info(si))
			continue;

		/* not taking the spinlock here, because we are unde chunk_lock, and si->total_bytes should not change */
		if (si->flags & BTRFS_BLOCK_GROUP_DATA)
			ctx->data_bytes_allocated += si->total_bytes;
		else if ((si->flags & BTRFS_BLOCK_GROUP_SYSTEM) || (si->flags & BTRFS_BLOCK_GROUP_METADATA))
			ctx->metadata_and_system_bytes_allocated += si->total_bytes;
	}
	rcu_read_unlock();

	/* reserve 2% of total space for META+SYSTEM */
	ctx->total_reserved_meta_system_bytes = div_factor_fine(btrfs_device_get_total_bytes(device), 2);
	/* align to 1gb */
	if (ctx->total_reserved_meta_system_bytes % ONE_GB != 0)
		ctx->total_reserved_meta_system_bytes += ONE_GB - (ctx->total_reserved_meta_system_bytes % ONE_GB);
	/* add 128Mb */
	ctx->total_reserved_meta_system_bytes += 128*ONE_MB;

	/* 
	 * if total_allocated > total_bytes, then it's already some 
	 * problem in the allocator logic. but can't insist on reserving
	 * anything else at this point.
	 */
	if (ZBTRFS_WARN(ctx->data_bytes_allocated + ctx->metadata_and_system_bytes_allocated > btrfs_device_get_total_bytes(device),
		            "FS[%s]: data_allocated + meta/system_allocated > total_bytes", fs_info->sb->s_id)) {
		ctx->to_reserve_meta_system_bytes = 0;
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CHUNK_ALLOC, ZBTRFS_MDATA_RSV_CTX_FMT, ZBTRFS_MDATA_RSV_CTX_PRINT(ctx, device));
		return;
	}

	/* how much we still need to reserve */
	if (ctx->metadata_and_system_bytes_allocated < ctx->total_reserved_meta_system_bytes)
		ctx->to_reserve_meta_system_bytes = ctx->total_reserved_meta_system_bytes - ctx->metadata_and_system_bytes_allocated;
	else
		ctx->to_reserve_meta_system_bytes = 0;

	/*
	 * for really-really small devices, it can happen that 
	 * we insist to reserve too much, so it will happen that
	 * total_allocated + to_reserve > total_bytes.
	 * so make sure it doesn't happen. it should never happen for 
	 * devices >= 2Gb, so let's issue a warning here.
	 * note: this can also happen when we're shrinking the device.
	 */
	if (ctx->data_bytes_allocated + ctx->metadata_and_system_bytes_allocated + ctx->to_reserve_meta_system_bytes >
		btrfs_device_get_total_bytes(device)) {
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_CHUNK_ALLOC, "total_allocated + to_reserve > total_bytes");
		/*
		 * if we are shrinking, do not fix this up, because the shrinking
		 * code wants to know the real situation.
		 */
		if (!for_shrink) {
			ctx->to_reserve_meta_system_bytes = btrfs_device_get_total_bytes(device) - (ctx->data_bytes_allocated + ctx->metadata_and_system_bytes_allocated);
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_CHUNK_ALLOC, "after: "ZBTRFS_MDATA_RSV_CTX_FMT, ZBTRFS_MDATA_RSV_CTX_PRINT(ctx, device));
		}
	}

	ZBTRFSLOG_TAG(fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, ZBTRFS_MDATA_RSV_CTX_FMT, ZBTRFS_MDATA_RSV_CTX_PRINT(ctx, device));
}

/*
 * Make sure that by allocating a new DATA extent, we
 * we not violating METADATA reservation.
 */
static void zbtrfs_adjust_free_dev_extent_data_final(struct zbtrfs_mdata_rsv_ctx *ctx,
		struct btrfs_device *device,
		u64 extent_start, u64 extent_size,
		u64 *out_adjusted_extent_start, u64 *out_adjusted_extent_size)
{
	struct btrfs_fs_info *fs_info = device->dev_root->fs_info;
	u64 max_extent_size = 0;

	*out_adjusted_extent_start = extent_start;

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, ZBTRFS_MDATA_RSV_CTX_FMT, ZBTRFS_MDATA_RSV_CTX_PRINT(ctx, device));

	/* 
	 * if total_allocated > total_bytes, then it's already some 
	 * problem in the allocator logic. cannot allow any allocation.
	 */
	if (ZBTRFS_WARN(ctx->data_bytes_allocated + ctx->metadata_and_system_bytes_allocated > btrfs_device_get_total_bytes(device),
		            "FS[%s]: data_allocated + meta/system_allocated > total_bytes", fs_info->sb->s_id)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_CHUNK_ALLOC, ZBTRFS_MDATA_RSV_CTX_FMT, ZBTRFS_MDATA_RSV_CTX_PRINT(ctx, device));
		*out_adjusted_extent_size = 0;
		return;
	}

	/*
	 * we need to make sure that after allocating this extent,
	 * the following will hold:
	 * total_allocated + extent_size + to_reserve <= total_bytes
	 * note that we already made sure that:
	 * total_allocated + to_reserve <= total_bytes
	 */
	max_extent_size = btrfs_device_get_total_bytes(device) - (ctx->metadata_and_system_bytes_allocated + ctx->data_bytes_allocated + ctx->to_reserve_meta_system_bytes);
	if (extent_size > max_extent_size) {
		*out_adjusted_extent_size = max_extent_size;
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "CUT devextent[%llu:%llu]=>[%llu:%llu]",
			          extent_start, extent_size, *out_adjusted_extent_start, *out_adjusted_extent_size);
	} else {
		*out_adjusted_extent_size = extent_size;
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "ALLOW devextent[%llu:%llu]",
			          *out_adjusted_extent_start, *out_adjusted_extent_size);
	}
}

#define SEARCH_EXTENT_OK(search_start, search_end_not_incl, extent_start, extent_end_not_incl, lowest_addr, highest_addr_not_incl) \
({                                                                                                                                 \
	bool __ok = true;                                                                                                              \
	bool __ok_left = false, __ok_right = false;                                                                                    \
	/* extent is valid by itself, and not too small */                                                                             \
	__ok = __ok && (search_start < search_end_not_incl && search_start + BTRFS_STRIPE_LEN <= search_end_not_incl);                 \
	/* extent is within the search range */                                                                                        \
	__ok = __ok && (search_start >= extent_start && search_end_not_incl <= extent_end_not_incl);                                   \
                                                                                                                                   \
	/* extent is whether inside left "good" range or "right" good range */                                                         \
	__ok_left = search_end_not_incl <= lowest_addr;                                                                                \
	__ok_right = search_start >= highest_addr_not_incl;                                                                            \
	__ok = __ok && (__ok_left || __ok_right);                                                                                      \
	__ok;                                                                                                                          \
})

/*
 * This function is called during allocation of METATADA/SYSTEM device extents.
 * The idea is that during journal replay, we need to avoid allocating
 * areas on device, where we still have un-replayed journal entries.
 * We assume we have only once device, on which our BTRFS sits
 */
static void zbtrfs_adjust_free_dev_extent_mdata_or_system(struct btrfs_device *device, 
		u64 extent_start, u64 extent_size,
		u64 requested_alloc_size, u64 alloc_type,
		u64 *out_adjusted_extent_start, u64 *out_adjusted_extent_size)
{
	int ret = 0;
	const char *type_str = btrfs_block_group_type_to_str(alloc_type);
	struct btrfs_fs_info *fs_info = device->dev_root->fs_info;
	u64 extent_end_not_incl = extent_start + extent_size;
	u64 lowest_addr = 0, highest_addr = 0, highest_addr_not_incl = 0;
	u64 search_start = 0, cnt = 0;

	/* we shouldn't be called with DATA */
	ZBTRFS_BUG_ON(alloc_type & BTRFS_BLOCK_GROUP_DATA);

	/* if don't have real journal, we are ok */
	if (fs_info->zfs_info.pool_id == 0) {
		*out_adjusted_extent_start = extent_start;
		*out_adjusted_extent_size = extent_size;
		return;
	}

	/* assume worst */
	*out_adjusted_extent_start = extent_start;
	*out_adjusted_extent_size = 0;

	/* if we have already completed replaying, we are ok */
	{
		bool replay_done = false;
		ret = zjournal_is_replayed(fs_info->zfs_info.pool_id, &replay_done);
		if (ZBTRFS_WARN_ON(ret)) /* should not happen, but not sure what we can do */
			return;
		if (likely(replay_done)) {
			*out_adjusted_extent_start = extent_start;
			*out_adjusted_extent_size = extent_size;
			return;
		}
	}

	ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] requested=%llu",
		          type_str, extent_start, extent_size, requested_alloc_size);

	ret = zjournal_get_unreplayed_addresses(fs_info->zfs_info.pool_id, extent_start, extent_size, &lowest_addr, &highest_addr);
	if (ret == -EEXIST) {
		/* pool was already replayed, we are ok */
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "already replayed");
		*out_adjusted_extent_start = extent_start;
		*out_adjusted_extent_size = extent_size;
		return;
	}
	if (ZBTRFS_WARN_ON(ret)) /* should not happen, but not sure what we can do */
		return;
	if (lowest_addr == (u64)-1 && highest_addr == 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] - no unreplayed entries",
			          type_str, extent_start, extent_size);
		*out_adjusted_extent_start = extent_start;
		*out_adjusted_extent_size = extent_size;
		return;
	}

	ZBTRFS_BUG_ON(fs_info->zfs_info.pool_gran_bytes == 0);
	highest_addr_not_incl = highest_addr + fs_info->zfs_info.pool_gran_bytes;
	ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] l=%llu h=%llu hni=%llu",
		          type_str, extent_start, extent_size,
		          lowest_addr, highest_addr, highest_addr_not_incl);
	ZBTRFS_BUG_ON(lowest_addr  < extent_start || lowest_addr  >= extent_end_not_incl ||
		          highest_addr < extent_start || highest_addr >= extent_end_not_incl ||
		          lowest_addr > highest_addr); /* logic error */

	/*
	 * Device extents are allocated sequentially, until device fills up.
	 * Holes can appear if a block-group in the middle is delete, which we
	 * don't do currently. Without holes, extent sizes will be fixed
	 * per allocation type, except maybe the last extent on the device.
	 * Let's keep with this strategy, and do the following logic:
	 *  - find an extent of requested_alloc_size, aligned by requested_alloc_size, 
	 *    which is outside the bad range
	 *  - if we cannot find such, let's prefer "left" range over "right"
	 */
	for (search_start = extent_start, cnt = 0;
	     search_start < extent_end_not_incl; 
		 search_start += requested_alloc_size, ++cnt) {
		if (SEARCH_EXTENT_OK(search_start, search_start + requested_alloc_size,
			                 extent_start, extent_end_not_incl, lowest_addr, highest_addr_not_incl)) {
			ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] take aligned extent #%llu [%llu:%llu]",
				          type_str, extent_start, extent_size,
				          cnt, search_start, requested_alloc_size);
			*out_adjusted_extent_start = search_start;
			*out_adjusted_extent_size = requested_alloc_size;
			return;
		}
	}

	/* try left range, it's start should already be aligned by BTRFS_STRIPE_LEN */
	if (SEARCH_EXTENT_OK(extent_start, lowest_addr,
		                 extent_start, extent_end_not_incl, lowest_addr, highest_addr_not_incl)) {
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] take LEFT extent [%llu:%llu]",
			          type_str, extent_start, extent_size,
			          extent_start, lowest_addr - extent_start);
		*out_adjusted_extent_start = extent_start;
		*out_adjusted_extent_size = lowest_addr - extent_start;
		return;
	}
	/* try right range, make sure to align it by BTRFS_STRIPE_LEN */
	if (highest_addr_not_incl % BTRFS_STRIPE_LEN != 0) {
		u64 new_hni = highest_addr_not_incl + BTRFS_STRIPE_LEN - (highest_addr_not_incl % BTRFS_STRIPE_LEN);
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] hni not-aligned by BTRFS_STRIPE_LEN, %llu=>%llu",
			          type_str, extent_start, extent_size,
			          highest_addr_not_incl, new_hni);
		highest_addr_not_incl = new_hni;
	}

	if (SEARCH_EXTENT_OK(highest_addr_not_incl, extent_end_not_incl, 
		                 extent_start, extent_end_not_incl, lowest_addr, highest_addr_not_incl)) {
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] take RIGHT extent [%llu:%llu]",
			          type_str, extent_start, extent_size,
			          highest_addr_not_incl, extent_end_not_incl - highest_addr_not_incl);
		*out_adjusted_extent_start = highest_addr_not_incl;
		*out_adjusted_extent_size = extent_end_not_incl - highest_addr_not_incl;
		return;
	}

	/* not found */
	ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_CHUNK_ALLOC, "alloc-in-replay %s[%llu:%llu] - no good extent found",
	              type_str, extent_start, extent_size);
	
	ZBTRFS_BUG_ON(*out_adjusted_extent_size != 0);
}

/*
 * If we need to allocate non-DATA extent, make sure it doesn't
 * go onto journal's unreplayed entries.
 */
void zbtrfs_adjust_free_dev_extent(struct zbtrfs_mdata_rsv_ctx *ctx,
		struct btrfs_device *device,
		u64 extent_start, u64 extent_size,
		u64 requested_alloc_size, u64 alloc_type,
		u64 *out_adjusted_extent_start, u64 *out_adjusted_extent_size)
{
	/* don't care about DATA or mixed allocation types here */
	if (alloc_type & BTRFS_BLOCK_GROUP_DATA) {
		*out_adjusted_extent_start = extent_start;
		*out_adjusted_extent_size = extent_size;
		return;
	}

	zbtrfs_adjust_free_dev_extent_mdata_or_system(device, 
		extent_start, extent_size, requested_alloc_size, alloc_type,
		out_adjusted_extent_start, out_adjusted_extent_size);
}

/*
 * If we allocate a DATA extent, make sure we don't
 * violate our metadata reservation.
 */
void zbtrfs_adjust_free_dev_extent_final(struct zbtrfs_mdata_rsv_ctx *ctx,
		struct btrfs_device *device,
		u64 extent_start, u64 extent_size, u64 alloc_type,
		u64 *out_adjusted_extent_start, u64 *out_adjusted_extent_size)
{
	/* don't care about METADATA/SYSTEM or mixed allocations here */
	if ((alloc_type & BTRFS_BLOCK_GROUP_METADATA) || (alloc_type & BTRFS_BLOCK_GROUP_SYSTEM)) {
		*out_adjusted_extent_start = extent_start;
		*out_adjusted_extent_size = extent_size;
		return;
	}

	zbtrfs_adjust_free_dev_extent_data_final(ctx, device,
		extent_start, extent_size,
		out_adjusted_extent_start, out_adjusted_extent_size);
}

/*********** cache warmup tracking ************/

/*
 * This function is called from two places:
 * - on SOD
 * - on new device-extent (and, therefore, btrfs-chunk and block-group) allocation.
 * This function is called only under btrfs_space_info.groups_sem write-locked.
 */
void zbtrfs_block_group_warmup_init(struct btrfs_block_group_cache *block_group)
{
	bool warming_up = !block_group_cache_done(block_group);

	/* 
	 * track cache warmup.
	 * note that this is relevant only for SOD,
	 * because newly-created block-groups are always
	 * considered as fully-empty, so no warmup is required
	 * for them.
	 */
	if (warming_up) {
		struct btrfs_fs_info *fs_info = block_group->fs_info;

		/* we don't care for MIXED case here */
		if (block_group->flags & BTRFS_BLOCK_GROUP_SYSTEM)
			atomic_inc(&fs_info->zfs_info.system_block_groups_to_warmup);
		else if (block_group->flags & BTRFS_BLOCK_GROUP_METADATA)
			atomic_inc(&fs_info->zfs_info.metadata_block_groups_to_warmup);
		else
			atomic_inc(&fs_info->zfs_info.data_block_groups_to_warmup);
	}
}

void zbtrfs_block_group_warmup_finished(struct btrfs_block_group_cache *block_group)
{
	char *type_str = NULL;
	atomic_t *to_dec = NULL;
	int still_to_warmup = 0;

	if (block_group->flags & BTRFS_BLOCK_GROUP_SYSTEM) {
		type_str = "SYSTEM";
		to_dec = &block_group->fs_info->zfs_info.system_block_groups_to_warmup;
	} else if (block_group->flags & BTRFS_BLOCK_GROUP_METADATA) {
		type_str = "METADATA";
		to_dec = &block_group->fs_info->zfs_info.metadata_block_groups_to_warmup;
	} else {
		type_str = "DATA";
		to_dec = &block_group->fs_info->zfs_info.data_block_groups_to_warmup;
	}

	still_to_warmup = atomic_dec_return(to_dec);
	ZBTRFS_WARN(still_to_warmup < 0, "FS[%s]: BG[%llu:%llu] %s still_to_warmup=%d",
		 block_group->fs_info->sb->s_id,
		 block_group->key.objectid, block_group->key.offset,
		 type_str, still_to_warmup);
	if (still_to_warmup == 0)
		zklog_tag(Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "FS[%s]: %s SPACE CACHE WARM-UP COMPLETED",
		          block_group->fs_info->sb->s_id, type_str);
}

/************** btrfs_shrink ****************/

/*
 * The idea here is that we want to ensure that the specified
 * block-groups is empty. If it is, we set it as read-only.
 * This is modelled after set_block_group_ro(), make sure to
 * keep it in sync.
 */
int zbtrfs_set_block_group_ro(struct btrfs_block_group_cache *cache, int *was_rw)
{
	int ret = 0;
	struct btrfs_space_info *sinfo = cache->space_info;
	bool trigger_cache_in = false;

	spin_lock(&sinfo->lock);
	spin_lock(&cache->lock);

	/*
	 * as an extra precaution, if cache->ro is already set, we still do the checks below.
	 * if they pass, we leave the block-group as ro with no further modificatiosn,
	 * otherwise, we fail.
	 */

	/* 
	 * we need the caching to complete, in order to properly
	 * check that the block-group indeed is empty.
	 */
	switch (cache->cached) {
		case BTRFS_CACHE_NO:
			ZBTRFSLOG_TAG(cache->fs_info, Z_KWARN, ZKLOG_TAG_RESIZE,
				"BG[%s:%llu:%llu:%s] - BTRFS_CACHE_NO",
				btrfs_block_group_type_to_str(cache->flags),
				cache->key.objectid, cache->key.offset,
				btrfs_block_group_caching_to_str(cache->cached));
			trigger_cache_in = true;
			ret = -EAGAIN;
			goto out;

		case BTRFS_CACHE_STARTED:
		case BTRFS_CACHE_FAST:
			ZBTRFSLOG_TAG(cache->fs_info, Z_KWARN, ZKLOG_TAG_RESIZE,
				"BG[%s:%llu:%llu:%s] - still caching-in",
				btrfs_block_group_type_to_str(cache->flags),
				cache->key.objectid, cache->key.offset,
				btrfs_block_group_caching_to_str(cache->cached));
			ret = -EAGAIN;
			goto out;

		case BTRFS_CACHE_FINISHED:
			break;

		case BTRFS_CACHE_ERROR:
			ZBTRFSLOG_TAG(cache->fs_info, Z_KERR, ZKLOG_TAG_RESIZE,
				"BG[%s:%llu:%llu:%s] - had cache-in error",
				btrfs_block_group_type_to_str(cache->flags),
				cache->key.objectid, cache->key.offset,
				btrfs_block_group_caching_to_str(cache->cached));
			ret = -EIO;
			goto out;

		default:
			WARN(1, "FS[%s]: BG[%s:%llu:%llu] invalid cached=%d",
				 cache->fs_info->sb->s_id, 
				 btrfs_block_group_type_to_str(cache->flags),
				 cache->key.objectid, cache->key.offset,
				 cache->cached);
			ret = -ECANCELED;
			goto out;
	}

	if (btrfs_block_group_used(&cache->item) > 0 || cache->reserved > 0 || cache->pinned > 0 || cache->delalloc_bytes > 0) {
		ZBTRFSLOG_TAG(cache->fs_info, Z_KERR, ZKLOG_TAG_RESIZE,
			      "BG[%s:%llu:%llu:%s] - used=%llu reserved=%llu pinned=%llu delalloc_bytes=%llu IN USE",
			      btrfs_block_group_type_to_str(cache->flags),
			      cache->key.objectid, cache->key.offset,
			      btrfs_block_group_caching_to_str(cache->cached),
			      btrfs_block_group_used(&cache->item), cache->reserved, cache->pinned, cache->delalloc_bytes);
		ret = -ENOSPC;
		goto out;
	}

	ZBTRFSLOG_TAG(cache->fs_info, Z_KDEB1, ZKLOG_TAG_RESIZE, "BG[%s:%llu:%llu:%s] ro:%u=>%u bytes_super=%llu",
		      btrfs_block_group_type_to_str(cache->flags),
		      cache->key.objectid, cache->key.offset,
		      btrfs_block_group_caching_to_str(cache->cached),
		      cache->ro, 1,
		      cache->bytes_super);
	if (!cache->ro) {
		/*
		 * num_bytes = cache->key.offset - cache->reserved - cache->pinned -
			           cache->bytes_super - btrfs_block_group_used(&cache->item);
		 * sinfo->bytes_readonly += num_bytes;
		 */
		sinfo->bytes_readonly += cache->key.offset - cache->bytes_super;
		cache->ro = 1;
		*was_rw = 1;
	} else {
		*was_rw = 0;
	}

	/* 
	 * we don't have to check the free-space-ctl, because if anybody
	 * has just allocated from there, but did not set 'reserved' yet,
	 * then he will receive EAGAIN from btrfs_update_reserved_bytes().
	 */

out:
	spin_unlock(&cache->lock);
	spin_unlock(&sinfo->lock);

	if (trigger_cache_in)
		cache_block_group(cache, 0/*load_cache_only*/);

	return ret;
}

/********************** extent allocation ********************************/

/**
 * This is our equivalent of btrfs_alloc_reserved_file_extent (please keep
 * them in sync). Here we also allocate an extent_op, that will carry tenant ID,
 * and eventually it will end up in EXTENT_ITEM.flags.
 */
int zbtrfs_alloc_reserved_file_extent(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     u64 root_objectid, u64 owner,
				     u64 offset, struct btrfs_key *ins,
				     u16 tenant_id)
{
	int ret = 0;
	struct btrfs_delayed_extent_op *extent_op = NULL;

	ZBTRFS_BUG_ON(root_objectid == BTRFS_TREE_LOG_OBJECTID);

	/* alloc extent_op and encode tenant_id within it */
	extent_op = btrfs_alloc_delayed_extent_op();
	if (unlikely(extent_op == NULL)) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_DREF, 
			          "[%llu:%llu:%llu] alloc (%llu EXTENT_ITEM %llu), failed to alloc extent_op tenant_id=%u",
			          root_objectid, owner, offset,
			          ins->objectid, ins->offset, tenant_id);
		ret = -ENOMEM;
		goto out;
	}
	extent_op->is_data = 1;
	extent_op->update_key = 0;
	extent_op->update_flags = 1;
	extent_op->level = 0; /* not needed for "is_data" extent ops, but be explicit */
	ret = btrfs_ztenant_id_to_extent_item_flags(0/*flags*/, tenant_id, &extent_op->flags_to_set);
	if (unlikely(ret)) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_DREF, 
			          "[%llu:%llu:%llu] alloc (%llu EXTENT_ITEM %llu), tenant_id=%u => flags, ret=%d",
			          root_objectid, owner, offset,
			          ins->objectid, ins->offset, tenant_id, ret);
		goto out;
	}

	ret = btrfs_add_delayed_data_ref(root->fs_info, trans, ins->objectid,
					 ins->offset, 0/*parent*/,
					 root_objectid, owner, offset,
					 BTRFS_ADD_DELAYED_EXTENT, extent_op, 1/*no_quota*/);

out:
	if (ret)
		btrfs_free_delayed_extent_op(extent_op);

	return ret;
}

/********************** async delayed refs ********************************/
struct zbtrfs_async_delayed_refs {
	struct btrfs_root *root;
	unsigned long count;
	u64 transid;
	u64 req_id;
	struct btrfs_work bwork;
};

static void zbtrfs_async_delayed_ref_start(struct btrfs_work *work)
{
	struct zbtrfs_async_delayed_refs *async = container_of(work, struct zbtrfs_async_delayed_refs, bwork);
	struct btrfs_fs_info *fs_info = async->root->fs_info;
	struct btrfs_trans_handle *trans = NULL;
	int ret = 0;

	/* if our transaction has already committed, forget it */
	if (fs_info->generation != async->transid) {
		ZBTRFSLOG_TAG_RL(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "async[req=0x%llx txn=%llu]!=generation[%llu]", async->req_id, async->transid, fs_info->generation);
		goto out;
	}

	trans = btrfs_join_transaction(async->root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		trans = NULL;
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_TXN, "async[req=0x%llx txn=%llu] btrfs_join_transaction ret=%d", async->req_id, async->transid, ret);
		goto out;
	}

	/* if our transaction has already committed, forget it */
	if (trans->transid != async->transid) {
		ZBTRFSLOG_TAG_RL(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "async[req=0x%llx txn=%llu]!=joined_trans[%llu]", async->req_id, async->transid, trans->transid);
		goto out;
	}

	/*
	 * trans->sync means that when we call end_transaciton, we won't
	 * wait on delayed refs
	 */
	trans->sync = true;
	ret = btrfs_run_delayed_refs(trans, async->root, async->count);

out:
	if (trans) {
		int end_ret = btrfs_end_transaction(trans, async->root);
		if (ret == 0)
			ret = end_ret;
	}

	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_TXN, "async[req=0x%llx txn=%llu] ret=%d", async->req_id, async->transid, ret);

	kmem_cache_free(zbtrfs_globals.async_delayed_refs_cachep, async);
}

void zbtrfs_async_run_delayed_refs(struct btrfs_root *root, unsigned long count, u64 transid)
{
	static atomic64_t s_req_id = ATOMIC64_INIT(0);

	struct zbtrfs_async_delayed_refs *async = NULL;
	u64 req_id = atomic64_inc_return(&s_req_id);

	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_TXN, "async[req=0x%llx txn=%llu]", req_id, transid);

	async = kmem_cache_alloc(zbtrfs_globals.async_delayed_refs_cachep, GFP_NOFS);
	if (async == NULL) {
		ZBTRFSLOG_TAG_RL(root->fs_info, Z_KERR, ZKLOG_TAG_TXN, "async[req=0x%llx txn=%llu] ENOMEM", req_id, transid);
		return;
	}

	async->root = root;
	async->count = count;
	async->transid = transid;
	async->req_id = req_id;
	btrfs_init_work(&async->bwork, btrfs_extent_refs_helper, zbtrfs_async_delayed_ref_start, NULL, NULL);
	btrfs_queue_work(root->fs_info->extent_workers, &async->bwork);
}

size_t zbtrfs_async_delayed_refs_size(void)
{
	return sizeof(struct zbtrfs_async_delayed_refs);
}


