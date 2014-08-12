/*
 * This file is meant to be included directly from fs/xfs/xfs_extent_busy.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

#include "xfs_error.h"
#include "xfs_discard.h"

STATIC struct zxfs_discard_range*
zxfs_discard_range_alloc(
	xfs_daddr_t discard_daddr,
	xfs_extlen_t discard_bbs,
	xfs_km_flags_t km_flags)
{
	struct zxfs_discard_range *dr = kmem_zone_alloc(zxfs_globals.xfs_discard_range_zone, km_flags);
	if (dr) {
		dr->flags = 0;
		dr->discard_daddr = discard_daddr;
		dr->discard_bbs = discard_bbs;
	}

	return dr;
}

void
zxfs_discard_range_free(	
	struct zxfs_discard_range *dr)
{
	kmem_zone_free(zxfs_globals.xfs_discard_range_zone, dr);
}

/*
 * Insert a discard-range into the specified AG's
 * discard-ranges tree.
 * The pagb_lock is assumed to be locked.
 * @return error in case there was an overlapping discard-range in the 
 *         discard-ranges tree
 * ZXFS_POSITIVE_ERRNO
 */
STATIC int
__zxfs_discard_range_register(
	xfs_mount_t *mp,
	xfs_perag_t *pag,
	struct zxfs_discard_range *dr)
{
	int error = 0;
	struct rb_node **rbp = &pag->pagb_zdr_tree.rb_node;
	struct rb_node *parent = NULL;

	assert_spin_locked(&pag->pagb_lock);

	while (*rbp) {
		struct zxfs_discard_range *ex_dr = rb_entry(*rbp, struct zxfs_discard_range, dr_tree_node);
		
		parent = *rbp;
		
		if (dr->discard_daddr < ex_dr->discard_daddr) {
			if (ZXFS_WARN(dr->discard_daddr + dr->discard_bbs > ex_dr->discard_daddr,
				"XFS(%s): new dr[%lld:%u] overlaps from left existing dr[%lld:%u]",
				mp->m_fsname,
				dr->discard_daddr, dr->discard_bbs, 
				ex_dr->discard_daddr, ex_dr->discard_bbs)) {
				error = XFS_ERROR(EFSCORRUPTED);
				break;
			}
			rbp = &((*rbp)->rb_left);
		} else if (dr->discard_daddr > ex_dr->discard_daddr) {
			if (ZXFS_WARN(ex_dr->discard_daddr + ex_dr->discard_bbs > dr->discard_daddr,
				"XFS(%s): new dr[%lld:%u] overlaps from right existing dr[%lld:%u]",
				mp->m_fsname,
				dr->discard_daddr, dr->discard_bbs, 
				ex_dr->discard_daddr, ex_dr->discard_bbs)) {
				error = XFS_ERROR(EFSCORRUPTED);
				break;
			}
			rbp = &((*rbp)->rb_right);
		} else {
			ZXFS_WARN(dr->discard_daddr == ex_dr->discard_daddr,
				"XFS(%s): new dr[%lld:%u] has same daddr as existing dr[%lld:%u]",
				mp->m_fsname,
				dr->discard_daddr, dr->discard_bbs, 
				ex_dr->discard_daddr, ex_dr->discard_bbs);
			error = XFS_ERROR(EFSCORRUPTED);
			break;
		}
	}

	if (error == 0) {
		rb_link_node(&dr->dr_tree_node, parent, rbp);
		rb_insert_color(&dr->dr_tree_node, &pag->pagb_zdr_tree);
	}

	return error;
}

/*
 * Delete the discard-range from the specified
 * AG's discard-ranges tree.
 * The pagb_lock is assumed to be locked. 
 */
STATIC void
__zxfs_discard_range_deregister(
	xfs_mount_t *mp,
	xfs_perag_t *pag,
	struct zxfs_discard_range *dr)
{
	assert_spin_locked(&pag->pagb_lock);
	rb_erase(&dr->dr_tree_node, &pag->pagb_zdr_tree);
}

/*
 * Convert a discard-range to AG coordinates.
 * ZXFS_POSITIVE_ERRNO
 */
int
__zxfs_discard_range_to_ag(
	xfs_mount_t *mp,
	xfs_perag_t *pag,
	struct zxfs_discard_range *dr,
	xfs_agnumber_t *dagno,
	xfs_agblock_t *dagbno,
	xfs_extlen_t *dlen
	)
{
	*dagno = xfs_daddr_to_agno(mp, dr->discard_daddr);
	*dagbno = xfs_daddr_to_agbno(mp, dr->discard_daddr);
	*dlen = XFS_BB_TO_FSBT(mp, dr->discard_bbs);

	if (ZXFS_WARN(*dagno != pag->pag_agno, 
		"XFS(%s): AG[%u]: dr[%llu:%u] yields agno=%u (m_blkbb_log=%u sb_agblocks=%u)",
		mp->m_fsname, pag->pag_agno, dr->discard_daddr, dr->discard_bbs,
		*dagno, mp->m_blkbb_log, mp->m_sb.sb_agblocks))
		return XFS_ERROR(EFSCORRUPTED);
	
	if (ZXFS_WARN(*dagbno + *dlen > mp->m_sb.sb_agblocks,
		"XFS(%s): AG[%u]: dr[%llu:%u] yields [%u:%u] > sb_agblocks=%u",
		mp->m_fsname, pag->pag_agno, dr->discard_daddr, dr->discard_bbs,
		*dagbno, *dlen, mp->m_sb.sb_agblocks))
		return XFS_ERROR(EFSCORRUPTED);

	/* discard-range len should align nicely to blocks */
	if (unlikely(dr->discard_bbs % *dlen)) {
		ZXFS_WARN(1, "XFS(%s): AG[%u]: dr[%llu:%u] yields [%u:%u] but discard_bbs mod dlen!=0",
			mp->m_fsname, pag->pag_agno, dr->discard_daddr, dr->discard_bbs,
			*dagbno, *dlen);
		return XFS_ERROR(EFSCORRUPTED);
	}

	return 0;
}

/* move daddr "d" down to the previous multiple of "gran" */
#define XFS_DADDR_DOWN_TO_GRAN(d, gran) ((d) - (d) % (gran))

/* 
 * move daddr "d" up to the next multiple of "gran".
 * step1: figure out how much we need to add to "d"
 * step2: needed for case that "d" is already multiple of "gran"
 * step3: add to d
 */
#define XFS_DADDR_UP_TO_GRAN(d, gran) ({            \
	xfs_daddr_t __res = (gran) - ((d) % (gran));    \
	__res %= gran;                                  \
	__res = (d) + (__res);                          \
	__res;                                          \
})

/*
 * After an extent is freed, an attempt is made to merge the freed extent
 * with its adjacent neighbours in the by-bno free-space btree, in order
 * to end up with larger free extent. This merge can result in an extent
 * large-enough for discard. This function figures out the block-device
 * area, which may have become suitable for discard.
 * @param ano the relevant AG
 * @param bno the block number (relative to AG) of the freed extent
 * @param len the length of the freed extent in FSBs
 * @param merged_bno the block number (relative to AG) of the merged extent
 * @param merged_len the length of the merged extent in FSBs
 * @return a discard-range or NULL
 */
struct zxfs_discard_range*
zxfs_extent_busy_merged_to_discard_range(
	xfs_mount_t *mp,
	xfs_agnumber_t agno, 
	xfs_agblock_t bno, xfs_extlen_t len,
	xfs_agblock_t merged_bno, xfs_extlen_t merged_len)
{
	xfs_extlen_t gran_bbs = 0;
	xfs_daddr_t start_d = NULLDADDR;
	xfs_daddr_t end_d = NULLDADDR;
	xfs_daddr_t m_start_d = NULLDADDR;
	xfs_daddr_t m_end_d = NULLDADDR;
	xfs_daddr_t mn_start_d = NULLDADDR;
	xfs_daddr_t mn_end_d = NULLDADDR;
	xfs_daddr_t res_start_d = NULLDADDR, res_end_d = NULLDADDR;
	struct zxfs_discard_range *dr = NULL;

	/* 
	 * XFS_EXTENT_BUSY_SKIP_DISCARD - we could check it as well,
	 * but for such extent [merged_bno:merged_len] will be [NULLAGBLOCK:0].
	 */
	if (merged_bno == NULLAGBLOCK || merged_len == 0 ||
		!ZXFS_ONLINE_DISCARD_ENABLED(mp))
		goto out;

	gran_bbs = mp->m_zxfs.discard_gran_bbs;
	start_d = XFS_AGB_TO_DADDR(mp, agno, bno);
	end_d = start_d + XFS_FSB_TO_BB(mp, len);
	m_start_d = XFS_AGB_TO_DADDR(mp, agno, merged_bno);
	m_end_d = m_start_d + XFS_FSB_TO_BB(mp, merged_len);
	/* 
	 * narrow the merged extent down to discard-gran.
	 * even if AG is not aligned by discard-gran,
	 * the narrowed merged extent is for sure within
	 * AG limits.
	 */
	mn_start_d = XFS_DADDR_UP_TO_GRAN(m_start_d, gran_bbs);
	mn_end_d = XFS_DADDR_DOWN_TO_GRAN(m_end_d, gran_bbs);

	ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
		"AG[%u] f[%u:%u] m[%u:%u] => f[%lld-%lld] m[%lld-%lld] mn[%lld-%lld]",
		agno, bno, len, merged_bno, merged_len,
		start_d, end_d, m_start_d, m_end_d, mn_start_d, mn_end_d);

	if (ZXFS_WARN(start_d < m_start_d || end_d > m_end_d,
		"XFS(%s): illegal merged range: [%u:%u:%u] after merge[%u:%u:%u]",
		mp->m_fsname, agno, bno, len, agno, merged_bno, merged_len))
		goto out;

	/* figure out what we can discard */
	if (start_d < mn_start_d) {
		res_start_d = mn_start_d;
		ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
			"start_d(%lld)<mn_start_d(%lld)=>start_d=mn_start_d=%lld",
			start_d, mn_start_d, mn_start_d);
	} else {
		/* 
		 * move back to the next gran-chunk.
		 * note that we can in principle do: res_start_d = mn_start_d,
		 * but mn_start_d could cover more chunks, and we
		 * only want to discard the minimal discard-range, in
		 * which the freed extent was.
		 * note that the case of start_d == mn_start_d is also
		 * covered here.
		 */
		res_start_d = XFS_DADDR_DOWN_TO_GRAN(start_d, gran_bbs);
		ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
			"start_d(%lld)>=mn_start_d(%lld)=> DOWN_TO_GRAN(start_d)=%lld",
			start_d, mn_start_d, res_start_d);
	}
	if (end_d > mn_end_d) {
		res_end_d = mn_end_d;
		ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
			"end_d (%lld)>mn_end_d(%lld)=>end_d=mn_end_d=%lld",
			end_d, mn_end_d, mn_end_d);
	} else {
		/* same here - discard the minimal range */
		res_end_d = XFS_DADDR_UP_TO_GRAN(end_d, gran_bbs);
		ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
			"end_d(%lld)<=mn_end_d(%lld)=> UP_TO_GRAN(end_d)=%lld",
			end_d, mn_end_d, res_end_d);
	}

	if (res_end_d > res_start_d) {
		/* verify that our discard range is within AG */
		if (ZXFS_WARN_ON(res_start_d < XFS_AGB_TO_DADDR(mp, agno, 0)) ||
			ZXFS_WARN_ON(res_end_d > XFS_AGB_TO_DADDR(mp, agno + 1, 0)))
			goto out;

		ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
			"discard[%lld-%lld] => [%lld:%lld]", res_start_d, res_end_d, res_start_d, res_end_d - res_start_d);
		if (ZXFS_WARN(res_start_d % gran_bbs || res_end_d % gran_bbs,
			"XFS(%s): res_start_d(%llu) or res_end_d(%llu) not multiple of gran=%u",
			mp->m_fsname, res_start_d, res_end_d, gran_bbs))
			BUG();

		dr = zxfs_discard_range_alloc(res_start_d, res_end_d - res_start_d, KM_MAYFAIL);
		if (dr == NULL)
			ZXFSLOG_TAG(mp, Z_KWARN, ZKLOG_TAG_BUSY_EXT,
				"busy[%u:%u:%u] failed allocating zxfs_discard_range, will not discard[%lld:%lld] (%lld chunks)",
				agno, bno, len, res_start_d, res_end_d - res_start_d, 
				(res_end_d - res_start_d) / gran_bbs);
	} else {
		ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
			"f[%lld-%lld] m[%lld-%lld] mn[%lld-%lld] NO DISCARD",
			start_d, end_d, m_start_d, m_end_d, mn_start_d, mn_end_d);
	}

out:
	return dr;
}

/*
 * Adjust the specified discard range [dbno-dend], such
 * that [abno-aend] does not overlap it.
 * The result can be one of the following:
 * - no adjusted discard range, i.e., the original discard-range must be deleted
 * - one adjusted discard-range, i.e., the original discard-range must be
 *   converted to the adjusted discard-range
 * - two adjusted discard-ranges, i.e., a new discard-range must be allocated.
 */
STATIC void
__zxfs_discard_range_adjust_overlap(
	xfs_mount_t *mp, 
	xfs_agnumber_t agno, 
	xfs_agblock_t abno, xfs_agblock_t aend,
	xfs_agblock_t dbno, xfs_agblock_t dend,
	xfs_daddr_t *ldaddr, xfs_extlen_t *lbbs,
	xfs_daddr_t *rdaddr, xfs_extlen_t *rbbs)
{
	xfs_extlen_t gran_bbs = mp->m_zxfs.discard_gran_bbs;
	xfs_daddr_t ldaddr_start = NULLDADDR, ldaddr_end = NULLDADDR;
	xfs_daddr_t rdaddr_start = NULLDADDR, rdaddr_end = NULLDADDR;

	/* avoid using gran_bbs that is not alright */
	if (!ZXFS_DISCARD_ENABLED(mp))
		goto out;
	/* proper start and end */
	if (ZXFS_WARN_ON(abno >= aend || dbno >= dend))
		goto out;
	/* they should overlap */
	if (ZXFS_WARN_ON(aend <= dbno || dend <= abno))
		goto out;

	/*
	 * alloc-extent fully covers the discard-range:
	 *
	 * |aaaaaaaaaaaaaaaaaaaaaaaaaaa|
	 *     |ddddddddddddddddddddddd|
	 *
	 * |aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|
	 *	  |ddddddddddddddddddddddd|
	 *
	 * |aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|
	 * |ddddddddddddddddddddddd|
	 *
	 * |aaaaaaaaaaaaaaaaaaaaaaa|
	 * |ddddddddddddddddddddddd|
	 */
	if (abno <= dbno && aend >= dend) {
		ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, "a[%u:%u:%u] d[%u:%u:%d] alloc fully overlaps",
			agno, abno, aend - abno, agno, dbno, dend - dbno);
		goto out;
	}

	 /*
	  * the only case, where we might need 
	  * to split the discard-range.
	  *
	  *       |aaaa|
	  * |dddddddddddddddd|
	  */
	 if (abno > dbno && aend < dend) {
	 	ldaddr_start = XFS_AGB_TO_DADDR(mp, agno, dbno);
		ldaddr_start = XFS_DADDR_UP_TO_GRAN(ldaddr_start, gran_bbs);
		ldaddr_end = XFS_AGB_TO_DADDR(mp, agno, abno);
		ldaddr_end = XFS_DADDR_DOWN_TO_GRAN(ldaddr_end, gran_bbs);
		
		rdaddr_start = XFS_AGB_TO_DADDR(mp, agno, aend);
		rdaddr_start = XFS_DADDR_UP_TO_GRAN(rdaddr_start, gran_bbs);
		rdaddr_end = XFS_AGB_TO_DADDR(mp, agno, dend);
		rdaddr_end = XFS_DADDR_DOWN_TO_GRAN(rdaddr_end, gran_bbs);

		ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, "a[%u:%u:%u] d[%u:%u:%d] split dl[%llu:%llu] dr[%llu:%llu]",
			agno, abno, aend - abno, agno, dbno, dend - dbno,
			ldaddr_start, ldaddr_end - ldaddr_start,
			rdaddr_start, rdaddr_end - rdaddr_start);
		goto out;
	 }

	 /*
	  * alloc-extent overlaps from left
	  *
	  * |aaaaaaaaa|
	  *      |dddddddddddddddd|
	  *
	  * |aaaaaaaaa|
	  * |ddddddddddddddddddddd|
	  */
	 if (abno <= dbno && aend < dend) {
	 	ldaddr_start = XFS_AGB_TO_DADDR(mp, agno, aend);
		ldaddr_start = XFS_DADDR_UP_TO_GRAN(ldaddr_start, gran_bbs);
		ldaddr_end = XFS_AGB_TO_DADDR(mp, agno, dend);
		ldaddr_end = XFS_DADDR_DOWN_TO_GRAN(ldaddr_end, gran_bbs);
		ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, "a[%u:%u:%u] d[%u:%u:%d] left-overlap dl[%llu:%llu]",
			agno, abno, aend - abno, agno, dbno, dend - dbno,
			ldaddr_start, ldaddr_end - ldaddr_start);
		goto out;
	 }

	 /*
	  * last case - alloc-extent overlaps from right
	  *
	  *          |aaaaaaaaaa|
	  * |ddddddddddddddddddd|
	  *
	  *          |aaaaaaaaaaaaaa|
	  * |ddddddddddddddddddd|
	  */
	 if (abno < dend && aend >= dend) {
	 	ldaddr_start = XFS_AGB_TO_DADDR(mp, agno, dbno);
		ldaddr_start = XFS_DADDR_UP_TO_GRAN(ldaddr_start, gran_bbs);
		ldaddr_end = XFS_AGB_TO_DADDR(mp, agno, abno);
		ldaddr_end = XFS_DADDR_DOWN_TO_GRAN(ldaddr_end, gran_bbs);
		ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, "a[%u:%u:%u] d[%u:%u:%u] right-overlap dl[%llu:%llu]",
			agno, abno, aend - abno, agno, dbno, dend - dbno,
			ldaddr_start, ldaddr_end - ldaddr_start);
		goto out;
	 }

	 ZXFS_WARN(1, "XFS(%s): a[%u:%u-%u] d[%u:%u-%u] unhandled case???",
	 	mp->m_fsname, agno, abno, aend, agno, dbno, dend);

out:
	/* set the output fields */
	if (ldaddr_start != NULLDADDR && ldaddr_end != NULLDADDR &&
		ldaddr_start < ldaddr_end) {
		*ldaddr = ldaddr_start;
		*lbbs = ldaddr_end - ldaddr_start;
	} else {
		*ldaddr = NULLDADDR;
		*lbbs = 0;
	}
	if (rdaddr_start != NULLDADDR && rdaddr_end != NULLDADDR &&
		rdaddr_start < rdaddr_end) {
		*rdaddr = rdaddr_start;
		*rbbs = rdaddr_end - rdaddr_start;
	} else {
		*rdaddr = NULLDADDR;
		*rbbs = 0;
	}
}

/*
 * Called when XFS wants to allocate [bno:len] in AG=agno.
 * We need to ensure that no discard-range overlaps the allocation.
 */
void
zxfs_discard_range_prevent(
	xfs_mount_t *mp, 
	xfs_agnumber_t agno, 
	xfs_agblock_t bno, 
	xfs_extlen_t len)
{
	xfs_perag_t *pag = NULL;
	struct rb_node *rbp = NULL;
	u32 num_err = 0, num_err_discard = 0, num_overl_discard = 0;
	u32 num_split = 0, num_l = 0, num_r = 0, num_del = 0;

	ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT,
		"alloc[%u:%u:%u] prevent discard", agno, bno, len);

	if (ZXFS_WARN_ON(len == 0))
		return;

	pag = xfs_perag_get(mp, agno);
	spin_lock(&pag->pagb_lock);

again_locked:
	rbp = pag->pagb_zdr_tree.rb_node;
	while (rbp) {
		int error = 0;
		struct zxfs_discard_range *dr = rb_entry(rbp, struct zxfs_discard_range, dr_tree_node);
		xfs_agnumber_t dagno = NULLAGNUMBER;
		xfs_agblock_t dagbno = NULLAGBLOCK;
		xfs_extlen_t dlen = 0;

		error = __zxfs_discard_range_to_ag(mp, pag, dr,
					&dagno, &dagbno, &dlen);
		if (unlikely(error)) {
			/* we need to get rid of this bad discard-range */
			if (dr->flags & XFS_EXTENT_BUSY_DISCARDED) {
				ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
					"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] error - WAIT FOR DISCARD",
					agno, bno, len, dr->discard_daddr, dr->discard_bbs, 
					dagno, dagbno, dlen);
				++num_err_discard;
				break;
			}

			ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
				"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] error - get rid of",
				agno, bno, len, dr->discard_daddr, dr->discard_bbs, 
				dagno, dagbno, dlen);
			/*
			 * if this discard-range is still in the tree,
			 * and not marked for discard, then it's ok
			 * for us to delete it. remember, we are under
			 * pagb_lock.
			 */
			list_del_init(&dr->link); /* delete from owner's list */
			__zxfs_discard_range_deregister(mp, pag, dr);
			zxfs_discard_range_free(dr);
			++num_err;
			goto again_locked;
		}

		if (bno + len <= dagbno) {
			rbp = rbp->rb_left;
			continue;
		}
		if (dagbno + dlen <= bno) {
			rbp = rbp->rb_right;
			continue;
		}

		if (dr->flags & XFS_EXTENT_BUSY_DISCARDED) {
			ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, 
				"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] overlap - WAIT FOR DISCARD",
				agno, bno, len, dr->discard_daddr, dr->discard_bbs, 
				dagno, dagbno, dlen);
			++num_overl_discard;
			break;
		}

		/* adjust the discard-range */
		{
			xfs_daddr_t ldaddr = NULLDADDR;
			xfs_extlen_t lbbs = 0;
			xfs_daddr_t rdaddr = NULLDADDR;
			xfs_extlen_t rbbs = 0;

			__zxfs_discard_range_adjust_overlap(mp, agno,
				bno/*abno*/, bno + len/*aend*/,
				dagbno/*dbno*/, dagbno + dlen/*dend*/,
				&ldaddr, &lbbs, &rdaddr, &rbbs);
			if (ldaddr != NULLDADDR && lbbs != 0 && rdaddr != NULLDADDR && rbbs != 0) {
				struct zxfs_discard_range *rdr = NULL;

				ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, 
					"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] split dl[%llu:%u] dr[%llu:%u]",
					agno, bno, len, dr->discard_daddr, dr->discard_bbs, 
					dagno, dagbno, dlen,
					ldaddr, lbbs, rdaddr, rbbs);
				++num_split;

				/* adjust our existing discard-range */
				dr->discard_daddr = ldaddr;
				dr->discard_bbs = lbbs;

				/* alloc a new discard-range; KM_NOSLEEP - we are under spinlock! */
				rdr = zxfs_discard_range_alloc(rdaddr, rbbs, KM_NOSLEEP);
				if (rdr == NULL) {
					ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
						"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] split dl[%llu:%u] dr[%llu:%u] - dr alloc fail!",
						agno, bno, len, dr->discard_daddr, dr->discard_bbs, 
						dagno, dagbno, dlen,
						ldaddr, lbbs, rdaddr, rbbs);
				} else {
					error = __zxfs_discard_range_register(mp, pag, rdr);
					if (error) {
						ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
							"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] split dl[%llu:%u] dr[%llu:%u] - dr register fail!",
							agno, bno, len, dr->discard_daddr, dr->discard_bbs, 
							dagno, dagbno, dlen,
							ldaddr, lbbs, rdaddr, rbbs);
						zxfs_discard_range_free(rdr);
					} else {
						/* add AFTER our original range */
						list_add(&rdr->link, &dr->link);
					}
				}
			} else if (ldaddr != NULLDADDR && lbbs != 0) {
				ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT,
					"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] overlap-l dl[%llu:%u]",
					agno, bno, len, dr->discard_daddr, dr->discard_bbs,
					dagno, dagbno, dlen,
					ldaddr, lbbs);
				++num_l;
				dr->discard_daddr = ldaddr;
				dr->discard_bbs = lbbs;
			} else if (rdaddr != NULLDADDR && rbbs != 0) {
				ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT,
					"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] overlap-r dr[%llu:%u]",
					agno, bno, len, dr->discard_daddr, dr->discard_bbs,
					dagno, dagbno, dlen,
					rdaddr, rbbs);
				++num_r;
				dr->discard_daddr = rdaddr;
				dr->discard_bbs = rbbs;
			} else {
				ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT,
					"alloc[%u:%u:%u] drange[%llu:%u] b[%u:%u:%u] DELETE!",
					agno, bno, len, dr->discard_daddr, dr->discard_bbs,
					dagno, dagbno, dlen);
				++num_del;
				list_del_init(&dr->link); /* delete from owner's list */
				__zxfs_discard_range_deregister(mp, pag, dr);
				zxfs_discard_range_free(dr);
			}
			/* we have handled the overlap, we need to re-search */
			goto again_locked;
		}
		BUG(); /* we should not get here */
	}

	/*
	 * either we did not find an overlap,
	 * or we need to sleep for a while
	 * and retry.
	 */
	if (rbp) {
		spin_unlock(&pag->pagb_lock);
		delay(1);
		spin_lock(&pag->pagb_lock);
		goto again_locked;
	}

	spin_unlock(&pag->pagb_lock);
	xfs_perag_put(pag);

	if (zklog_will_print_tag(Z_KDEB1, ZKLOG_TAG_BUSY_EXT)) {
		enum zklog_level_t level = 
			(num_err || num_err_discard || num_overl_discard ||
			 num_split || num_l || num_r || num_del) ? 
			 Z_KDEB1 : Z_KDEB2;
		ZXFSLOG_TAG(mp, level, ZKLOG_TAG_BUSY_EXT,
			"alloc[%u:%u:%u] err=%u err_disc=%u overl_disc=%u split=%u l=%u r=%u del=%u",
			agno, bno, len,
			num_err, num_err_discard, num_overl_discard,
			num_split, num_l, num_r, num_del);
	}
}

/*
 * A helper function to check if there is a busy
 * extent, which overlaps the specified discard range.
 * If yes, the discard range is attached to that busy
 * extent. If no, the discard range is marked with
 * XFS_EXTENT_BUSY_DISCARDED and added to "out_list".
 * @dagbno AG-relative block number of the discard range
 * @dlen length of the discard range in blocks
 * Note: must be called under pagb_lock locked
 */
STATIC
void
__zxfs_discard_range_busy_overl(
	xfs_mount_t *mp,
	xfs_perag_t *pag,
	struct zxfs_discard_range *dr,
	xfs_agblock_t dagbno,
	xfs_extlen_t dlen,
	struct list_head *out_list)
{
	struct rb_node *rbp = NULL;

	assert_spin_locked(&pag->pagb_lock);

	rbp = pag->pagb_tree.rb_node;
	while (rbp) {
		struct xfs_extent_busy *busyp = rb_entry(rbp, struct xfs_extent_busy, rb_node);
		if (dagbno + dlen <= busyp->bno) {
			rbp = rbp->rb_left;
			continue;
		}
		if (busyp->bno + busyp->length <= dagbno) {
			rbp = rbp->rb_right;
			continue;
		}

		ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, 
			"dr[%llu:%u]=>b[%u:%u:%u] overlaps busy[%u:%u:%u]",
			dr->discard_daddr, dr->discard_bbs, pag->pag_agno, dagbno, dlen,
			busyp->agno, busyp->bno, busyp->length);
		list_add_tail(&dr->link, &busyp->discard_ranges);
		break;
	}
	if (rbp == NULL) {
		ZXFSLOG_TAG(mp, Z_KDEB1, ZKLOG_TAG_BUSY_EXT, 
			"dr[%llu:%u]=>b[%u:%u:%u] can discard!",
			dr->discard_daddr, dr->discard_bbs, pag->pag_agno, dagbno, dlen);
		/* we are now discarding it! */
		dr->flags |= XFS_EXTENT_BUSY_DISCARDED;
		list_add_tail(&dr->link, out_list);
	}
}

/*
 * Check all discard-ranges in dr_list.
 * If there is a busy extent that prevents a discard-range from
 * being discarded, attach this discard-range to the busy extent.
 * Otherwise, the discard-range still remains in the discard tree,
 * but is marked with XFS_EXTENT_BUSY_DISCARDED, and is also added
 * to "out_dr_list".
 */
STATIC void
zxfs_discard_ranges_check(
	xfs_mount_t *mp,
	xfs_perag_t *pag,
	xfs_agblock_t busy_bno,		/* not really used, only for prints */
	xfs_extlen_t busy_len,		/* not really used, only for prints */
	struct list_head *dr_list,
	struct list_head *out_list)
{
	int error = 0;
	struct zxfs_discard_range *dr = NULL, *dr_tmp = NULL;

	assert_spin_locked(&pag->pagb_lock);

	list_for_each_entry_safe(dr, dr_tmp, dr_list, link) {
		xfs_agnumber_t dagno = NULLAGNUMBER;
		xfs_agblock_t dagbno = NULLAGBLOCK;
		xfs_extlen_t dlen = 0;

		list_del_init(&dr->link); /*anyways */

		error = __zxfs_discard_range_to_ag(mp, pag, dr,
					&dagno, &dagbno, &dlen);
		if (unlikely(error)) {
			__zxfs_discard_range_deregister(mp, pag, dr);
			zxfs_discard_range_free(dr);
			continue;
		}

		/* ok, we can search for overlapping busy extent now */
		__zxfs_discard_range_busy_overl(mp, pag, dr, dagbno, dlen, out_list);
	}
}

/*
 * A special case when extent is freed, but busy extent is
 * not added (it has been already added).
 * We need to check if the merged range qualifies for discard. If yes, 
 * we need to check if there is some busy extent overlapping
 * the discard range. If yes, we attach the discard-range to that
 * busy extent, otherwise we can discard right away.
 */
void
zxfs_discard_range_insert_nobusy(
	xfs_mount_t *mp,
	xfs_perag_t *pag,
	xfs_agblock_t bno,
	xfs_extlen_t len,
	xfs_agblock_t merged_bno,
	xfs_extlen_t merged_len)
{
	int error = 0;
	struct zxfs_discard_range *dr = NULL;
	xfs_agnumber_t dagno = NULLAGNUMBER;
	xfs_agblock_t dagbno = NULLAGBLOCK;
	xfs_extlen_t dlen = 0;
	LIST_HEAD(dr_list);

	dr = zxfs_extent_busy_merged_to_discard_range(
			mp,
			pag->pag_agno,
			bno, len,
			merged_bno, merged_len);
	if (dr == NULL)
		goto out;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, 
		"f[%u:%u:%u] m[%u:%u] disc[%lld:%u] (%u chunks)",
		pag->pag_agno, bno, len, merged_bno, merged_len,
		dr->discard_daddr, dr->discard_bbs,
		dr->discard_bbs / mp->m_zxfs.discard_gran_bbs);

	error = __zxfs_discard_range_to_ag(mp, pag, dr,
				&dagno, &dagbno, &dlen);
	if (WARN_ON(error))
		goto out; /* free the dr */

	/* check if the discard range overlaps some busy ext */

	spin_lock(&pag->pagb_lock);
	/*
	 * we need to register the discard-range 
	 * only in case it overlaps anybody. otherwise
	 * we can discard right away and not worry that
	 * somebody will allocate, because AGF is locked
	 * right now.
	 * however, for extra safety, let's register in any case.
	 */
	error = __zxfs_discard_range_register(mp, pag, dr);
	if (error == 0)
		__zxfs_discard_range_busy_overl(mp, pag, dr, dagbno, dlen, &dr_list);
	spin_unlock(&pag->pagb_lock);

	if (error)
		goto out; /* free the dr */
	if (list_empty(&dr_list)) {
		/* discard-range was added to some busy extent */
		dr = NULL; /* avoid freeing it */
	} else {
		/*
		 * this discard-range does not overlap anybody.
		 * discard it right away. it is already marked with
		 * XFS_EXTENT_BUSY_DISCARDED
		 */
		ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, 
			"f[%u:%u:%u] m[%u:%u] disc[%lld:%u] (%u chunks) DISCARD NOW!",
			pag->pag_agno, bno, len, merged_bno, merged_len,
			dr->discard_daddr, dr->discard_bbs,
			dr->discard_bbs / mp->m_zxfs.discard_gran_bbs);

		zxfs_discard_ranges(mp, &dr_list);
		zxfs_discard_ranges_clear(mp, &dr_list);
		dr = NULL; /* already has been freed */
	}

out:
	if (dr)
		zxfs_discard_range_free(dr);
}

/*
 * Remove all the discard-ranges in the list from
 * the discard-range tree. All these extents
 * should already be detached from busy extents and
 * marked for discard.
 */
void
zxfs_discard_ranges_clear(xfs_mount_t *mp, 
	struct list_head *discard_ranges)
{
	struct zxfs_discard_range *dr = NULL, *dr_tmp = NULL;
	xfs_perag_t *pag = NULL;
	xfs_agnumber_t agno = NULLAGNUMBER;

	/*
	 * since all the discard-ranges are marked for discard,
	 * it's OK to touch their "link" fields without spinlock.
	 */
	list_for_each_entry_safe(dr, dr_tmp, discard_ranges, link) {
		xfs_agnumber_t dr_agno = xfs_daddr_to_agno(mp, dr->discard_daddr);

		ZXFSLOG_TAG(mp, Z_KDEB2, ZKLOG_TAG_BUSY_EXT, "AG[%u]: release drange[%llu:%u]",
			dr_agno, dr->discard_daddr, dr->discard_bbs);

		ZXFS_WARN_ON(!(dr->flags & XFS_EXTENT_BUSY_DISCARDED));
		list_del_init(&dr->link);

		if (dr_agno != agno) {
			if (pag) {
				spin_unlock(&pag->pagb_lock);
				xfs_perag_put(pag);
			}
			agno = dr_agno;
			pag = xfs_perag_get(mp, agno);
			spin_lock(&pag->pagb_lock);
		}

		__zxfs_discard_range_deregister(mp, pag, dr);
		zxfs_discard_range_free(dr);
	}

	if (pag) {
		spin_unlock(&pag->pagb_lock);
		xfs_perag_put(pag);
	}
}

/********* sysfs support *****************/
ssize_t
zxfs_extent_busy_dump(
	xfs_mount_t *mp, 
	struct xfs_perag *pag, 
	char *buf,
	ssize_t buf_size,
	enum zklog_level_t level)
{
	ssize_t size = 0;
	struct rb_node *rbp = NULL;
	xfs_agblock_t prev_bbno = NULLAGBLOCK;
	xfs_extlen_t prev_blen = 0;

	size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, level, ZKLOG_TAG_BUSY_EXT, 
				"AG[%u]: busy-extents:", pag->pag_agno);

	spin_lock(&pag->pagb_lock);

	for (rbp = rb_first(&pag->pagb_tree);
		 rbp != NULL;
		 rbp = rb_next(rbp)) {
		struct xfs_extent_busy *busyp = rb_entry(rbp, struct xfs_extent_busy, rb_node);
		struct zxfs_discard_range *dr = NULL;

		size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, level, ZKLOG_TAG_BUSY_EXT, 
					"busy[%u:%u:%u] fl=0x%x",
					busyp->agno, busyp->bno, busyp->length, busyp->flags);
		list_for_each_entry(dr, &busyp->discard_ranges, link) {
			size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, level, ZKLOG_TAG_BUSY_EXT,
				"=> dr[%llu:%u] b[%u:%u:%u] fl=0x%x\n",
				dr->discard_daddr, dr->discard_bbs,
				xfs_daddr_to_agno(mp, dr->discard_daddr),
				xfs_daddr_to_agbno(mp, dr->discard_daddr),
				XFS_BB_TO_FSBT(mp, dr->discard_bbs),
				dr->flags);
		}

		if (prev_bbno != NULLAGBLOCK &&
			prev_bbno + prev_blen > busyp->bno) {
			size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, Z_KERR, ZKLOG_TAG_BUSY_EXT,
				"prev_busy[%u:%u:%u] overlaps busy[%u:%u:%u]",
				pag->pag_agno, prev_bbno, prev_blen,
				busyp->agno, busyp->bno, busyp->length);
		}

		prev_bbno = busyp->bno;
		prev_blen = busyp->length;
	}

	spin_unlock(&pag->pagb_lock);
	
	return size;
}

ssize_t
zxfs_discard_range_dump(
	xfs_mount_t *mp, 
	xfs_perag_t *pag, 
	char *buf,
	ssize_t buf_size, 
	enum zklog_level_t level)
{
	ssize_t size = 0;
	struct rb_node *rbp = NULL;
	xfs_daddr_t prev_daddr = NULLDADDR;
	xfs_extlen_t prev_bbs = 0;

	size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, level, ZKLOG_TAG_BUSY_EXT, 
				"AG[%u]: discard-ranges:", pag->pag_agno);

	spin_lock(&pag->pagb_lock);

	for (rbp = rb_first(&pag->pagb_zdr_tree);
	     rbp != NULL;
		 rbp = rb_next(rbp)) {
		struct zxfs_discard_range *dr = rb_entry(rbp, struct zxfs_discard_range, dr_tree_node);
		xfs_agnumber_t dagno = xfs_daddr_to_agno(mp, dr->discard_daddr);
		xfs_agblock_t dbno = xfs_daddr_to_agbno(mp, dr->discard_daddr);
		xfs_extlen_t dlen = XFS_BB_TO_FSBT(mp, dr->discard_bbs);
		
		size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, level, ZKLOG_TAG_BUSY_EXT,
			"dr[%llu:%u] b[%u:%u:%u] fl=0x%x attch=%u\n",
			dr->discard_daddr, dr->discard_bbs,
			dagno, dbno, dlen, dr->flags,
			list_empty(&dr->link) ? 0 : 1);

		if (pag->pag_agno != dagno) {
			size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, Z_KERR, ZKLOG_TAG_BUSY_EXT,
				"dr[%llu:%u] b[%u:%u:%u] dagno(%u)!=pag->agno(%u)",
				dr->discard_daddr, dr->discard_bbs,
				dagno, dbno, dlen,
				dagno, pag->pag_agno);
		}
		if (prev_daddr != NULLDADDR &&
			prev_daddr + prev_bbs > dr->discard_daddr) {
			size += ZXFS_SYSFS_PRINT(mp, buf + size, buf_size - size, Z_KERR, ZKLOG_TAG_BUSY_EXT,
				"prev_dr[%llu:%u] overlaps dr[%llu:%u]",
				prev_daddr, prev_bbs, dr->discard_daddr, dr->discard_bbs);
		}

		prev_daddr = dr->discard_daddr;
		prev_bbs = dr->discard_bbs;
	}

	spin_unlock(&pag->pagb_lock);

	return size;
}

