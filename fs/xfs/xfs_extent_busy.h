/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * Copyright (c) 2010 David Chinner.
 * Copyright (c) 2011 Christoph Hellwig.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __XFS_EXTENT_BUSY_H__
#define	__XFS_EXTENT_BUSY_H__

/*
 * Busy block/extent entry.  Indexed by a rbtree in perag to mark blocks that
 * have been freed but whose transactions aren't committed to disk yet.
 *
 * Note that we use the transaction ID to record the transaction, not the
 * transaction structure itself. See xfs_extent_busy_insert() for details.
 */
struct xfs_extent_busy {
	struct rb_node	rb_node;	/* ag by-bno indexed search tree */
	struct list_head list;		/* transaction busy extent list */
	xfs_agnumber_t	agno;
	xfs_agblock_t	bno;
	xfs_extlen_t	length;
	unsigned int	flags;
#define XFS_EXTENT_BUSY_DISCARDED	0x01	/* undergoing a discard op. */
#define XFS_EXTENT_BUSY_SKIP_DISCARD	0x02	/* do not discard */
#ifdef CONFIG_XFS_ZADARA
	/* 
	 * list of "zxfs_discard_range"s;
	 * it must be manipulated only under pag->pagb_lock!!!
	 */
	struct list_head discard_ranges;
#endif /*CONFIG_XFS_ZADARA*/
};

void
xfs_extent_busy_insert(struct xfs_trans *tp, xfs_agnumber_t agno,
#ifndef CONFIG_XFS_ZADARA
	xfs_agblock_t bno, xfs_extlen_t len, unsigned int flags);
#else /*CONFIG_XFS_ZADARA*/
	xfs_agblock_t bno, xfs_extlen_t len, unsigned int flags,
	xfs_agblock_t merged_bno, xfs_extlen_t merged_len);
#endif /*CONFIG_XFS_ZADARA*/

void
xfs_extent_busy_clear(struct xfs_mount *mp, struct list_head *list,
#ifdef CONFIG_XFS_ZADARA
	struct list_head *out_dr_list,
#endif /*CONFIG_XFS_ZADARA*/
	bool do_discard);

int
xfs_extent_busy_search(struct xfs_mount *mp, xfs_agnumber_t agno,
	xfs_agblock_t bno, xfs_extlen_t len);

void
xfs_extent_busy_reuse(struct xfs_mount *mp, xfs_agnumber_t agno,
	xfs_agblock_t fbno, xfs_extlen_t flen, bool userdata);

void
xfs_extent_busy_trim(struct xfs_alloc_arg *args, xfs_agblock_t bno,
	xfs_extlen_t len, xfs_agblock_t *rbno, xfs_extlen_t *rlen);

int
xfs_extent_busy_ag_cmp(void *priv, struct list_head *a, struct list_head *b);

static inline void xfs_extent_busy_sort(struct list_head *list)
{
	list_sort(NULL, list, xfs_extent_busy_ag_cmp);
}

#ifdef CONFIG_XFS_ZADARA

struct zxfs_discard_range {
	/* 
	 * link in xfs_extent_busy.discard_ranges list;
	 * must be manipulated only under pagb_lock!!!
	 */
	struct list_head link;          
	struct rb_node dr_tree_node;    /* rb_node in pag->pagb_zdr_tree */
	xfs_daddr_t	discard_daddr;		/* absolute sector on the block device, properly aligned by discard-gran, or NULLDADDR */
	xfs_extlen_t discard_bbs;    	/* discard length in sectors, properly aligned by discard-gran or 0 */
	u8 flags;                       /* XFS_EXTENT_BUSY_DISCARDED */
};

void
zxfs_discard_range_insert_nobusy(
	xfs_mount_t *mp,
	struct xfs_perag *pag,
	xfs_agblock_t bno,
	xfs_extlen_t len,
	xfs_agblock_t merged_bno,
	xfs_extlen_t merged_len);

/* 
 * this function should be static, but we want
 * to call it from our unit tests.
 */
struct zxfs_discard_range*
zxfs_extent_busy_merged_to_discard_range(
	xfs_mount_t *mp,
	xfs_agnumber_t agno, 
	xfs_agblock_t bno, xfs_extlen_t len,
	xfs_agblock_t merged_bno, xfs_extlen_t merged_len);

/* 
 * this function should be static, but we want
 * to call it from our unit tests.
 */
void
zxfs_discard_range_free(	
	struct zxfs_discard_range *dr);

/* 
 * this function should be static, but we want
 * to call it from our unit tests.
 */
int
__zxfs_discard_range_to_ag(
	xfs_mount_t *mp,
	struct xfs_perag *pag,
	struct zxfs_discard_range *dr,
	xfs_agnumber_t *dagno,
	xfs_agblock_t *dagbno,
	xfs_extlen_t *dlen
	);

void 
zxfs_discard_range_prevent(
	xfs_mount_t *mp, 
	xfs_agnumber_t agno, 
	xfs_agblock_t bno, 
	xfs_extlen_t len);

void
zxfs_discard_ranges_clear(
	xfs_mount_t *mp, 
	struct list_head *discard_ranges);

/* zsysfs support */
ssize_t
zxfs_extent_busy_dump(
	xfs_mount_t *mp, 
	struct xfs_perag *pag, 
	char *buf,
	ssize_t buf_size,
	enum zklog_level_t level);
ssize_t
zxfs_discard_range_dump(
	xfs_mount_t *mp, 
	struct xfs_perag *pag, 
	char *buf,
	ssize_t buf_size, 
	enum zklog_level_t level);

#endif /*CONFIG_XFS_ZADARA*/

#endif /* __XFS_EXTENT_BUSY_H__ */
