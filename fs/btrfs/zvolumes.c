/*
 * This is our version of "find_free_device_extent".
 *   - apply the following patches:
 *      "Btrfs: fix chunk allocation regression leading to transaction abort"
 *      "Btrfs: fix find_free_dev_extent() malfunction in case device tree has hole"
 *      "btrfs: Fix tail space processing in find_free_dev_extent()"
 *   - add "alloc_type" parameter
 *   - call our extent adjustement functions.
 *   - add some prints
 */
int zbtrfs_find_free_dev_extent(struct btrfs_trans_handle *trans,
			 struct btrfs_device *device, u64 num_bytes, u64 alloc_type,
			 u64 *start, u64 *len)
{
	struct btrfs_key key;
	struct btrfs_root *root = device->dev_root;
	struct btrfs_dev_extent *dev_extent;
	struct btrfs_path *path;
	u64 hole_size;
	u64 max_hole_start;
	u64 max_hole_size;
	u64 extent_end;
	u64 search_start;
	u64 search_end = device->total_bytes;
	int ret;
	int slot;
	struct extent_buffer *l;
	struct zbtrfs_mdata_rsv_ctx mdata_rsv_ctx;

	/* zadara */
	zbtrfs_mdata_rsv_ctx_init(&mdata_rsv_ctx, device, false/*for_shrink*/);

	/* FIXME use last free of some kind */

	/* we don't want to overwrite the superblock on the drive,
	 * so we make sure to start at an offset of at least 1MB
	 */
	search_start = max(root->fs_info->alloc_start, 1024ull * 1024);

	ZBTRFSLOG_TAG(root->fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "alloc_type=%s num_bytes=%llu search[%llu-%llu]",
		          btrfs_block_group_type_to_str(alloc_type), num_bytes, search_start, search_end);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	max_hole_start = search_start;
	max_hole_size = 0;

again:
	if (search_start >= search_end || device->is_tgtdev_for_dev_replace) {
		ret = -ENOSPC;
		goto out;
	}

	path->reada = 2;
	path->search_commit_root = 1;
	path->skip_locking = 1;

	key.objectid = device->devid;
	key.offset = search_start;
	key.type = BTRFS_DEV_EXTENT_KEY;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out;
	if (ret > 0) {
		ret = btrfs_previous_item(root, path, key.objectid, key.type);
		if (ret < 0)
			goto out;
	}

	while (1) {
		l = path->nodes[0];
		slot = path->slots[0];
		if (slot >= btrfs_header_nritems(l)) {
			ret = btrfs_next_leaf(root, path);
			if (ret == 0)
				continue;
			if (ret < 0)
				goto out;

			break;
		}
		btrfs_item_key_to_cpu(l, &key, slot);

		if (key.objectid < device->devid)
			goto next;

		if (key.objectid > device->devid)
			break;

		if (key.type != BTRFS_DEV_EXTENT_KEY)
			goto next;

		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "devext[%llu] search[%llu-%llu]",
			          key.offset, search_start, search_end);

		if (key.offset > search_start) {
			hole_size = key.offset - search_start;

			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "devext[%llu] search[%llu-%llu] hole[%llu:%llu]",
						  key.offset, search_start, search_end, search_start, hole_size);

			/*
			 * Have to check before we set max_hole_start, otherwise
			 * we could end up sending back this offset anyway.
			 */
			if (contains_pending_extent(trans, device,
						    &search_start,
						    hole_size)) {
				if (key.offset >= search_start) {
					hole_size = key.offset - search_start;
				} else {
					WARN_ON_ONCE(1);
					hole_size = 0;
				}
				ZBTRFSLOG_TAG(root->fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "devext[%llu] contains_pending search[%llu-%llu] hole[%llu:%llu]",
							  key.offset, search_start, search_end, search_start, hole_size);
			}

			/* zadara */
			zbtrfs_adjust_free_dev_extent(&mdata_rsv_ctx, device, search_start, hole_size,
				                          num_bytes, alloc_type,
				                          &search_start, &hole_size);

			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "devext[%llu] adjust search[%llu-%llu] hole[%llu:%llu]",
						  key.offset, search_start, search_end, search_start, hole_size);

			if (hole_size > max_hole_size) {
				max_hole_start = search_start;
				max_hole_size = hole_size;
				ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "devext[%llu] search[%llu-%llu] maxhole[%llu:%llu]",
							  key.offset, search_start, search_end, max_hole_start, max_hole_size);
			}

			/*
			 * If this free space is greater than which we need,
			 * it must be the max free space that we have found
			 * until now, so max_hole_start must point to the start
			 * of this free space and the length of this free space
			 * is stored in max_hole_size. Thus, we return
			 * max_hole_start and max_hole_size and go back to the
			 * caller.
			 */
			if (hole_size >= num_bytes) {
				ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "devext[%llu] search[%llu-%llu] maxhole[%llu:%llu] OK",
					  key.offset, search_start, search_end, max_hole_start, max_hole_size);
				ret = 0;
				goto out;
			}
		}

		dev_extent = btrfs_item_ptr(l, slot, struct btrfs_dev_extent);
		extent_end = key.offset + btrfs_dev_extent_length(l,
								  dev_extent);
		if (extent_end > search_start)
			search_start = extent_end;
		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "after devext[%llu-%llu] search[%llu-%llu]",
			          key.offset, extent_end, search_start, search_end);
next:
		path->slots[0]++;
		cond_resched();
	}

	ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "search[%llu-%llu] no more devexts", search_start, search_end);

	/*
	 * At this point, search_start should be the end of
	 * allocated dev extents, and when shrinking the device,
	 * search_end may be smaller than search_start.
	 */
	if (search_end > search_start) {
		hole_size = search_end - search_start;

		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "END search[%llu-%llu] hole[%llu:%llu]", search_start, search_end, search_start, hole_size);

		if (contains_pending_extent(trans, device, &search_start,
					    hole_size)) {
			btrfs_release_path(path);
			ZBTRFSLOG_TAG(root->fs_info, Z_KINFO, ZKLOG_TAG_CHUNK_ALLOC, "END contains_pending search[%llu-%llu] AGAIN", search_start, search_end);
			goto again;
		}

		/* zadara */
		zbtrfs_adjust_free_dev_extent(&mdata_rsv_ctx, device, search_start, hole_size,
			                          num_bytes, alloc_type,
			                          &search_start, &hole_size);

		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB2, ZKLOG_TAG_CHUNK_ALLOC, "END adjust search[%llu-%llu] hole[%llu:%llu]",
			          search_start, search_end, search_start, hole_size);

		if (hole_size > max_hole_size) {
			max_hole_start = search_start;
			max_hole_size = hole_size;
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_CHUNK_ALLOC, "END search[%llu-%llu] maxhole[%llu:%llu]",
				          search_start, search_end, max_hole_start, max_hole_size);
		}
	}

	/* See above. */
	if (max_hole_size < num_bytes)
		ret = -ENOSPC;
	else
		ret = 0;

out:
	btrfs_free_path(path);

	if (ret == 0 || ret == -ENOSPC) {
		zbtrfs_adjust_free_dev_extent_final(&mdata_rsv_ctx, device, 
			max_hole_start, max_hole_size,
			alloc_type,
			&max_hole_start, &max_hole_size);
		/* adjust return value if needed */
		if (max_hole_size < num_bytes)
			ret = -ENOSPC;
		else
			ret = 0;
		ZBTRFSLOG_TAG(root->fs_info, ret == 0 ? Z_KINFO : Z_KERR, ZKLOG_TAG_CHUNK_ALLOC, "ret=%d found dev_extent[%llu:%llu] num_bytes=%llu alloc_type=%s",
			          ret, max_hole_start, max_hole_size, num_bytes, btrfs_block_group_type_to_str(alloc_type));
	}

	*start = max_hole_start;
	if (len)
		*len = max_hole_size;
	return ret;
}

/*
 * shrinking a device means finding all of the device extents past
 * the new size, and then following the back refs to the chunks.
 * The chunk relocation code actually frees the device extent.
 *
 * AlexL-Zadara:
 * Our own version of 'btrfs_shrink_device'; make sure to keep it in-sync
 * with the original version.
 * Our version is simplified in terms that we don't do real block-group relocation.
 * Also, our version has the following patch partially applied:
 *  "Btrfs: check pending chunks when shrinking fs to avoid corruption"
 */
int zbtrfs_shrink_device(struct btrfs_device *device, u64 new_size)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = device->dev_root;
	struct btrfs_dev_extent *dev_extent = NULL;
	struct btrfs_path *path;
	u64 length;
	u64 chunk_tree;
	u64 chunk_objectid;
	u64 chunk_offset;
	int ret = 0;
	int slot;
	struct extent_buffer *l;
	struct btrfs_key key;
	struct btrfs_super_block *super_copy = root->fs_info->super_copy;
	u64 old_total = btrfs_super_total_bytes(super_copy);
	u64 old_size = btrfs_device_get_total_bytes(device);
	u64 diff = old_size - new_size;

	zklog_tag_in_rcu(Z_KNOTE, ZKLOG_TAG_RESIZE, "FS[%s]: SHRINK devid=%llu(%s) to %llu(%llu MB)",
	      root->fs_info->sb->s_id,
	      device->devid, rcu_str_deref(device->name), new_size, BYTES_TO_MB(new_size));

	if (device->is_tgtdev_for_dev_replace)
		return -EINVAL;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->reada = 2;

	lock_chunks(root);

	btrfs_device_set_total_bytes(device, new_size);
	if (device->writeable) {
		device->fs_devices->total_rw_bytes -= diff;
		spin_lock(&root->fs_info->free_chunk_lock);
		root->fs_info->free_chunk_space -= diff;
		spin_unlock(&root->fs_info->free_chunk_lock);
	}
	unlock_chunks(root);

	key.objectid = device->devid;
	key.offset = (u64)-1;
	key.type = BTRFS_DEV_EXTENT_KEY;

	do {
		int loop_ret = 0;

		loop_ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (loop_ret < 0) {
			ret = loop_ret;
			goto done;
		}

		loop_ret = btrfs_previous_item(root, path, 0, key.type);
		if (loop_ret < 0) {
			ret = loop_ret;
			goto done;
		}
		if (loop_ret) {
			btrfs_release_path(path);
			/* ret is updated here */
			break;
		}

		l = path->nodes[0];
		slot = path->slots[0];
		btrfs_item_key_to_cpu(l, &key, path->slots[0]);

		if (key.objectid != device->devid) {
			btrfs_release_path(path);
			/* ret is updated here */
			break;
		}

		dev_extent = btrfs_item_ptr(l, slot, struct btrfs_dev_extent);
		length = btrfs_dev_extent_length(l, dev_extent);

		ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_RESIZE, "looking at devext[%llu:%llu](=%llu) new_size=%llu", key.offset, length, key.offset + length, new_size);

		if (key.offset + length <= new_size) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KDEB1, ZKLOG_TAG_RESIZE, "Done traversing devexts");
			btrfs_release_path(path);
			/* ret is updated here */
			break;
		}

		chunk_tree = btrfs_dev_extent_chunk_tree(l, dev_extent);
		chunk_objectid = btrfs_dev_extent_chunk_objectid(l, dev_extent);
		chunk_offset = btrfs_dev_extent_chunk_offset(l, dev_extent);
		btrfs_release_path(path);

		loop_ret = btrfs_relocate_chunk(root, chunk_tree, chunk_objectid, chunk_offset);
		if (loop_ret && loop_ret != -EAGAIN) {
			ret = loop_ret;
			goto done;
		}
		/*
		 * on EAGAIN, keep scanning the device extents, but remember
		 * to exit the loop with EAGAIN status (or worse, if we encounter
		 * a real error later on). the idea here is to trigger caching
		 * of all the block-groups on first pass.
		 */
		if (loop_ret == -EAGAIN && ret == 0)
			ret = loop_ret;
	} while (key.offset-- > 0);

	/* -EAGAIN??? */
	if (ret)
		goto done;

	/* Shrinking succeeded, else we would be at "done". */
	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_RESIZE, "btrfs_start_transaction() ret=%d", ret);
		goto done;
	}

	lock_chunks(root);

	/*
	 * We checked in the above loop all device extents that were already in
	 * the device tree. However before we have updated the device's
	 * total_bytes to the new size, we might have had chunk allocations that
	 * have not complete yet (new block groups attached to transaction
	 * handles), and therefore their device extents were not yet in the
	 * device tree and we missed them in the loop above. So if we have any
	 * pending chunk using a device extent that overlaps the device range
	 * that we can not use anymore, commit the current transaction and
	 * repeat the search on the device tree - this way we guarantee we will
	 * not have chunks using device extents that end beyond 'new_size'.
	 *
	 * AlexL-Zadara: to be a bit safer, let's not commit the transaction,
	 *               but return -EAGAIN. Our shrink operation is intended
	 *               only for special cases anyways (when customer by mistake
	 *               expanded the pool).
	 */
	{
		u64 start = new_size;
		u64 len = old_size - new_size;

		if (contains_pending_extent(trans, device,
					    &start, len)) {
		    ZBTRFSLOG_TAG(root->fs_info, Z_KWARN, ZKLOG_TAG_RESIZE, "contains_pending in [%llu:%llu] => EAGAIN", new_size, len);
			unlock_chunks(root);
			btrfs_end_transaction(trans, root);
			ret = -EAGAIN;
			goto done;
		}
	}

	/*
	 * check that we are not violating the metadata reservation
	 * after shrinking the device.
	 */
	{
		struct zbtrfs_mdata_rsv_ctx mdata_rsv_ctx;

		zbtrfs_mdata_rsv_ctx_init(&mdata_rsv_ctx, device, true/*for_shrink*/);
		ZBTRFSLOG_TAG(root->fs_info, Z_KINFO, ZKLOG_TAG_RESIZE, ZBTRFS_MDATA_RSV_CTX_FMT, ZBTRFS_MDATA_RSV_CTX_PRINT(&mdata_rsv_ctx, device));

		/* 
		 * if we have still something to reserve, and cannot make it after shrinking,
		 * we will cancel the shrinking. note that we are using the "new"
		 * device->total_bytes here, but "old" metadata reservation values.
		 */
		if (mdata_rsv_ctx.to_reserve_meta_system_bytes > 0
			&&
			mdata_rsv_ctx.metadata_and_system_bytes_allocated + mdata_rsv_ctx.data_bytes_allocated + mdata_rsv_ctx.to_reserve_meta_system_bytes > 
			new_size) {
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_RESIZE, "shrinking violates metadata reservation");
			ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_RESIZE, "m/s_alloc(%llu %lluMB) + d_alloc(%llu %lluMB) + to_reserve(%llu %lluMB) > new_size(%llu %lluMB)",
				  mdata_rsv_ctx.metadata_and_system_bytes_allocated, BYTES_TO_MB(mdata_rsv_ctx.metadata_and_system_bytes_allocated),
				  mdata_rsv_ctx.data_bytes_allocated, BYTES_TO_MB(mdata_rsv_ctx.data_bytes_allocated),
				  mdata_rsv_ctx.to_reserve_meta_system_bytes, BYTES_TO_MB(mdata_rsv_ctx.to_reserve_meta_system_bytes),
				  new_size, BYTES_TO_MB(new_size));
			unlock_chunks(root);
			btrfs_end_transaction(trans, root);
			ret = -ENOSPC;
			goto done;
		}
	}

	ZBTRFSLOG_TAG(root->fs_info, Z_KINFO, ZKLOG_TAG_RESIZE, "COMMIT SHRINK to %llu(%llu MB)", new_size, BYTES_TO_MB(new_size));

	btrfs_device_set_disk_total_bytes(device, new_size);
	if (list_empty(&device->resized_list))
		list_add_tail(&device->resized_list,
			      &root->fs_info->fs_devices->resized_devices);

	WARN_ON(diff > old_total);
	btrfs_set_super_total_bytes(super_copy, old_total - diff);
	unlock_chunks(root);

	/* Now btrfs_update_device() will change the on-disk size. */
	ret = btrfs_update_device(trans, device);
	if (ret) {
		zbtrfs_force_abort_transaction(trans, root, ret);
		btrfs_end_transaction(trans, root);
	} else {
		ret = btrfs_commit_transaction(trans, root);
	}

done:
	btrfs_free_path(path);

	zklog_tag_in_rcu(ret == 0 ? Z_KNOTE : Z_KERR, ZKLOG_TAG_RESIZE, 
		  "FS[%s]: SHRINK devid=%llu(%s) ret=%d", root->fs_info->sb->s_id,
	      device->devid, rcu_str_deref(device->name), ret);

	if (ret) {
		ZBTRFSLOG_TAG(root->fs_info, Z_KWARN, ZKLOG_TAG_RESIZE, "ROLLBACK in-memory values ret=%d", ret);

		lock_chunks(root);
		btrfs_device_set_total_bytes(device, old_size);
		if (device->writeable)
			device->fs_devices->total_rw_bytes += diff;
		spin_lock(&root->fs_info->free_chunk_lock);
		root->fs_info->free_chunk_space += diff;
		spin_unlock(&root->fs_info->free_chunk_lock);
		unlock_chunks(root);

		/*
		 * we didn't manage to shrink; apparently there was some
		 * used space after "new_size". our changed logic within
		 * btrfs_relocate_chunk() would still return ENOSPC in
		 * that path. so convert the return value to EFBIG
		 * to better reflect what really happened.
		 */
		if (ret == -ENOSPC)
			ret = -EFBIG;
	}

	return ret;
}

