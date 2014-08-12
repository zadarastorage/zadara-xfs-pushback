/*
 * This file is meant to be included directly from fs/xfs/xfs_discard.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

/*
 * Discard all the struct zxfs_discard_ranges
 * in the list. Do not modify the list.
 */
void 
zxfs_discard_ranges(
	struct xfs_mount *mp,
	struct list_head *discard_ranges)
{
	struct zxfs_discard_range *dr = NULL;

	if (!ZXFS_ONLINE_DISCARD_ENABLED(mp))
		return;

	list_for_each_entry(dr, discard_ranges, link) {
		int error = 0;

		ZXFS_WARN_ON(!(dr->flags & XFS_EXTENT_BUSY_DISCARDED));
		ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_DISCARD, "DISCARD [%llu:%u]",
			dr->discard_daddr, dr->discard_bbs);

		/* ALEXL-TODO be more efficient than blkdev_issue_discard */
		error = blkdev_issue_discard(mp->m_ddev_targp->bt_bdev, 
					dr->discard_daddr, dr->discard_bbs,
					GFP_NOFS, 0/*flags*/);
		if (error)
			ZXFSLOG_TAG_RL(mp, Z_KERR, ZKLOG_TAG_DISCARD,
				"DISCARD [%llu:%u] err=%d", 
				dr->discard_daddr, dr->discard_bbs, error);
	}
}

