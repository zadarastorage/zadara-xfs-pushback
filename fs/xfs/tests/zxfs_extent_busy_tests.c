#ifdef CONFIG_XFS_ZADARA
#include "xfs.h"
#include "xfs_sb.h"
#include "xfs_ag.h"
#include "xfs_trans_resv.h"
#include "xfs_alloc.h"
#include "xfs_log_format.h"
#include "xfs_log.h"
#include "xfs_mount.h"
#include "xfs_extent_busy.h"
#include "xfs_trans.h"
#include "xfs_shared.h"
#include "zxfs_tests.h"

/*********** helpers ***********************************/
#define CALL_SHOULD_SUCCEED(error, name)                                         \
({                                                                               \
	if (ZXFS_WARN(error, "Call: %s should succeed, but error=%d", #name, error)) \
		goto out;                                                                \
})

#define CALL_SHOULD_FAIL(error, name)                                              \
({																	               \
	if (ZXFS_WARN(error==0, "Call: %s should fail, but error=%d", #name, error)) { \
		error = -ECANCELED;                                                        \
		goto out;													               \
	}                                                                              \
	error = 0;                                                                     \
})

#define VALUE_SHOULD_BE(val, correct_val, name)                                    \
({                                                                                 \
	if (ZXFS_WARN((val) != (correct_val), "Value: %s is %llu but should be %llu",  \
		     #name, (u64)val, (u64)correct_val)) {                                 \
		error = -ECANCELED;                                                        \
		goto out;                                                                  \
	}                                                                              \
	error = 0;                                                                     \
})

#define COND_SHOULD_HOLD(cond, name)                            \
({ 															    \
	if (WARN(!(cond), "Condition: %s does not hold",  #name)) { \
		error = -ECANCELED;										\
		goto out;												\
	}															\
})

STATIC void free_mp(xfs_mount_t *mp)
{
	if (mp) {
		if (mp->m_super)
			kmem_free(mp->m_super);
		if (mp->m_ddev_targp) {
			struct block_device *bdev = mp->m_ddev_targp->bt_bdev;
			xfs_free_buftarg(mp, mp->m_ddev_targp);
			if (bdev)
				blkdev_put(bdev, FMODE_READ);
		}
		kmem_free(mp);
	}
}

STATIC int alloc_mp(unsigned int discard_gran_bytes, xfs_mount_t **out_mp)
{
	static char *s_fs_name = "TEST";
	static uuid_t s_uuid = {
		.__u_bits = {0x00, 0x01, 0x02, 0x03,
			         0x04, 0x05, 0x06, 0x07,
			         0x08, 0x09, 0x0a, 0x0b,
			         0x0c, 0x0d, 0x0e, 0x0f}};

	int error = 0;
	struct block_device *bdev = NULL;
	struct super_block *sb = NULL;
	xfs_mount_t *mp = NULL;
	xfs_buftarg_t *ddev_targp = NULL;
	xfs_sb_t *xfs_sb = NULL;
	struct zxfs_mount *zmp = NULL;

	/* bdev */
	bdev = blkdev_get_by_path("/dev/ram0", FMODE_READ, THIS_MODULE/*holder*/);
	if (IS_ERR(bdev)) {
		error = PTR_ERR(bdev);
		bdev = NULL;
	}
	CALL_SHOULD_SUCCEED(error, blkdev_get_by_path);

	/* sb */
	sb = kmem_zalloc(sizeof(struct super_block), 0/*flags*/);
	error = sb ? 0 : -ENOMEM;
	CALL_SHOULD_SUCCEED(error, kmem_zalloc);

	snprintf(sb->s_id, sizeof(sb->s_id), "%s", s_fs_name);

	/* mp */
	mp = kmem_zalloc(sizeof(xfs_mount_t), 0/*flags*/);
	error = mp ? 0 : -ENOMEM;
	CALL_SHOULD_SUCCEED(error , kmem_zalloc);

	mp->m_super = sb;
	mp->m_fsname = s_fs_name;
	mp->m_fsname_len = strlen(mp->m_fsname) + 1;
	mp->m_flags |= XFS_MOUNT_DISCARD;

	spin_lock_init(&mp->m_perag_lock);
	INIT_RADIX_TREE(&mp->m_perag_tree, GFP_ATOMIC);

	/* ddev_targp */
	ddev_targp = xfs_alloc_buftarg(mp, bdev);
	error = ddev_targp ? 0 : -ENOMEM;
	CALL_SHOULD_SUCCEED(error , xfs_alloc_buftarg);
	mp->m_ddev_targp = ddev_targp;

	xfs_sb = &mp->m_sb;
	xfs_sb->sb_magicnum = XFS_SB_MAGIC;
	xfs_sb->sb_blocksize = 4096;
	xfs_sb->sb_blocklog = 12;
	xfs_sb->sb_dblocks = 34865152; /* 133 GB */
	memcpy(&xfs_sb->sb_uuid, &s_uuid, sizeof(uuid_t));
	xfs_sb->sb_sectsize = 512;
	xfs_sb->sb_sectlog = 9;
	xfs_sb->sb_inodesize = 256;

	xfs_sb->sb_agblocks = 8716288;
	xfs_sb->sb_agblklog = 24;
	xfs_sb->sb_agcount = 4;

	xfs_sb->sb_logstart = 33554436; /* AG #2 */
	xfs_sb->sb_logblocks = 17024;

	xfs_sb->sb_inprogress = 0;
	
	mp->m_maxagi = xfs_sb->sb_agcount;
	mp->m_blkbb_log = xfs_sb->sb_blocklog - BBSHIFT;
	mp->m_sectbb_log = xfs_sb->sb_sectlog - BBSHIFT;
	mp->m_blockmask = xfs_sb->sb_blocksize - 1;
	mp->m_bsize = XFS_FSB_TO_BB(mp, 1);

	zmp = &mp->m_zxfs;
	atomic64_set(&zmp->shutdown_flags, 0);
	atomic_set(&zmp->corruption_detected, 0);
	zmp->discard_gran_bbs = BTOBBT(discard_gran_bytes);
	atomic_set(&zmp->total_discard_ranges, 0);
	zmp->online_discard = 1;

	*out_mp = mp;

out:
	if (error) {
		if (sb)
			kmem_free(sb);
		if (mp) {
			if (ddev_targp)
				xfs_free_buftarg(mp, ddev_targp);
			kmem_free(mp);
		}
		if (bdev)
			blkdev_put(bdev, FMODE_READ);
	}
	return error;
}

STATIC void free_perag(xfs_perag_t *pag)
{
	if (pag) {
		spin_lock(&pag->pag_mount->m_perag_lock);
		radix_tree_delete(&pag->pag_mount->m_perag_tree, pag->pag_agno);
		spin_unlock(&pag->pag_mount->m_perag_lock);
		ZXFS_WARN_ON(!RB_EMPTY_ROOT(&pag->pagb_tree));
		ZXFS_WARN_ON(!RB_EMPTY_ROOT(&pag->pagb_zdr_tree));
		kmem_free(pag);
	}
}

STATIC int alloc_perag(xfs_mount_t *mp, xfs_agnumber_t agno, xfs_perag_t **out_pag)
{
	int error = 0;
	xfs_perag_t *pag = NULL;

	pag = kmem_zalloc(sizeof(xfs_perag_t), 0/*flags*/);
	error = pag ? 0 : -ENOMEM;
	CALL_SHOULD_SUCCEED(error, kmem_zalloc);

	pag->pag_mount = mp;
	pag->pag_agno = agno;
	atomic_set(&pag->pag_ref, 1);
	pag->pagf_init = 1;
	pag->pagi_init = 1;
	pag->pagf_metadata = 0;
	pag->pagi_inodeok = 1;
	spin_lock_init(&pag->pagb_lock);
	pag->pagb_tree = RB_ROOT;
	pag->pagb_zdr_tree = RB_ROOT;
	pag->pagb_count = 0; /* leftover, that is not used nowdays */

	spin_lock(&mp->m_perag_lock);
	error = radix_tree_insert(&mp->m_perag_tree, agno, pag);
	CALL_SHOULD_SUCCEED(error, radix_tree_insert);

	spin_unlock(&mp->m_perag_lock);

	*out_pag = pag;
out:
	if (error)
		free_perag(pag);
	return error;
}

/*********** tests ***********************************/

/* --------------------------------------------------*/
STATIC int
test_merged_to_discard(void)
{
	int error = 0;
	xfs_mount_t *mp = NULL;
	xfs_agnumber_t agno = NULLAGNUMBER;
	xfs_agblock_t bno = NULLAGBLOCK, merged_bno = NULLAGBLOCK;
	xfs_extlen_t len = 0, merged_len = 0;
	unsigned int fsbs_per_dchunk = 0;
	struct zxfs_discard_range *dr = NULL;

	error = alloc_mp(1024*1024/*discard_gran_bytes*/, &mp);
	CALL_SHOULD_SUCCEED(error , alloc_mp);

	/* we have 256 4KB blocks per 1MB discard chunk */
	fsbs_per_dchunk = BBTOB(mp->m_zxfs.discard_gran_bbs) / mp->m_sb.sb_blocksize;
	VALUE_SHOULD_BE(fsbs_per_dchunk, 256, fsbs_per_dchunk);

	agno = 3;

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed and merged within single discard chunk #7 of AG#3 ===");
	/* freed and merged are one block, cannot discard */
	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = bno;
	merged_len = len;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	/* freed and merged are 10 blocks, cannot discard */
	bno = 7*fsbs_per_dchunk + 100;
	len = 10;
	merged_bno = bno;
	merged_len = len;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	/* freed is 10 blocks, merged almost one chunk, cannot discard */
	bno = 7*fsbs_per_dchunk + 100;
	len = 10;
	merged_bno = 7*fsbs_per_dchunk + 1;
	merged_len = 8*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	/* freed is 10 blocks, merged starts on chunk, ends before chunk, cannot discard */
	bno = 7*fsbs_per_dchunk + 100;
	len = 10;
	merged_bno = 7*fsbs_per_dchunk;
	merged_len = fsbs_per_dchunk - 1;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	/* freed is 10 blocks, merged starts after chunk, ends on chunk, cannot discard */
	bno = 7*fsbs_per_dchunk + 100;
	len = 10;
	merged_bno = 7*fsbs_per_dchunk + 1;
	merged_len = fsbs_per_dchunk - 1;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);
	
	/* freed is 10 blocks, merged is one chunk, discard one chunk */
	bno = 7*fsbs_per_dchunk + 100;
	len = 10;
	merged_bno = 7*fsbs_per_dchunk;
	merged_len = fsbs_per_dchunk;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,merged_bno), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/* freed starts on chunk, ends before chunk, merged is one chunk, discard one chunk */
	bno = 7*fsbs_per_dchunk;
	len = 10;
	merged_bno = 7*fsbs_per_dchunk;
	merged_len = fsbs_per_dchunk;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,merged_bno), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);
	
	/* freed starts after chunk, ends on chunk, merged is one chunk, discard one chunk */
	bno = 7*fsbs_per_dchunk + 1;
	len = fsbs_per_dchunk - 1;
	merged_bno = 7*fsbs_per_dchunk;
	merged_len = fsbs_per_dchunk;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,merged_bno), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/* freed and merged are one chunk */
	bno = 7*fsbs_per_dchunk;
	len = fsbs_per_dchunk;
	merged_bno = 7*fsbs_per_dchunk;
	merged_len = fsbs_per_dchunk;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,merged_bno), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed within single discard chunk #7 of AG#3, merged outside that chunk ===");
	/* freed one block, merged ends before chunk, cannot discard */
	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 7*fsbs_per_dchunk - 1;
	merged_len = 8*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 7*fsbs_per_dchunk - 100;
	merged_len = 8*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 6*fsbs_per_dchunk;
	merged_len = 8*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 3*fsbs_per_dchunk + 100;
	merged_len = bno + len - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 3*fsbs_per_dchunk + 100;
	merged_len = 8*fsbs_per_dchunk - 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	/* freed one block, merged starts after chunk, cannot discard */
	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 7*fsbs_per_dchunk + 1;
	merged_len = fsbs_per_dchunk;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = bno;
	merged_len = 8*fsbs_per_dchunk + 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 7*fsbs_per_dchunk + 10;
	merged_len = 9*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 1;
	merged_bno = 7*fsbs_per_dchunk + 1;
	merged_len = 9*fsbs_per_dchunk + 200 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed within single discard chunk #7 of AG#3, merged covers much more ===");
	/* check that we can discard only one chunk */
	bno = 7*fsbs_per_dchunk + 100;
	len = 15;
	merged_bno = 7*fsbs_per_dchunk - 1;
	merged_len = 8*fsbs_per_dchunk + 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 15;
	merged_bno = 6*fsbs_per_dchunk;
	merged_len = 9*fsbs_per_dchunk + 100 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 15;
	merged_bno = 6*fsbs_per_dchunk - 50;
	merged_len = 10*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 7*fsbs_per_dchunk + 100;
	len = 15;
	merged_bno = 5*fsbs_per_dchunk;
	merged_len = 10*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers two discard-chunk #6-7 in AG#3, we can discard both (merged is much more) ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk;
	merged_len = 8*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 5*fsbs_per_dchunk - 40;
	merged_len = 9*fsbs_per_dchunk +30 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk;
	merged_len = 9*fsbs_per_dchunk +35 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk + 50;
	merged_len = 9*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk + 50;
	merged_len = 9*fsbs_per_dchunk + 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - bno;
	merged_bno = 4*fsbs_per_dchunk + 50;
	merged_len = 9*fsbs_per_dchunk + 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk;
	len = 8*fsbs_per_dchunk - bno;
	merged_bno = 4*fsbs_per_dchunk + 50;
	merged_len = 9*fsbs_per_dchunk + 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno, 6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers two discard-chunk #6-7 in AG#3, we can discard none ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 1;
	merged_len = 8*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = bno;
	merged_len = len;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = bno - 2;
	merged_len = len + 3;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr, NULL, dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers two discard-chunk #6-7 in AG#3, we can discard left ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk;
	merged_len = 8*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk - 100;
	merged_len = bno + len -  merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk + 100;
	merged_len = 8*fsbs_per_dchunk - 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk;
	merged_len = 8*fsbs_per_dchunk - 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk;
	merged_len = 8*fsbs_per_dchunk - 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers two discard-chunk #6-7 in AG#3, we can discard right ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = bno;
	merged_len = 8*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 99;
	merged_len = 8*fsbs_per_dchunk +200 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 1;
	merged_len = 9*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 1;
	merged_len = 10*fsbs_per_dchunk + 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 8*fsbs_per_dchunk - bno;
	merged_bno = 6*fsbs_per_dchunk + 1;
	merged_len = 10*fsbs_per_dchunk + 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers three discard-chunk #6-7-8 in AG#3, we can discard middle ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = bno;
	merged_len = len;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 1;
	merged_len = 9*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = bno;
	merged_len = 9*fsbs_per_dchunk - 1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);
	
	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 20;
	merged_len = bno + len - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers three discard-chunk #6-7-8 in AG#3, we can discard all ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk;
	merged_len = 9*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 3*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk - 100;
	merged_len = 9*fsbs_per_dchunk + 50 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 3*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 5*fsbs_per_dchunk;
	merged_len = 9*fsbs_per_dchunk + 50 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 3*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk + 20;
	merged_len = 11*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 3*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk - 100;
	merged_len = 9*fsbs_per_dchunk + 50 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 3*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - bno;
	merged_bno = 4*fsbs_per_dchunk - 100;
	merged_len = 11*fsbs_per_dchunk + 50 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 3*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk;
	len = 9*fsbs_per_dchunk - bno;
	merged_bno = 5*fsbs_per_dchunk - 100;
	merged_len = 10*fsbs_per_dchunk + 50 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 3*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers three discard-chunk #6-7-8 in AG#3, we can discard first two ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk;
	merged_len = 9*fsbs_per_dchunk -1 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 5*fsbs_per_dchunk + 100;
	merged_len = 9*fsbs_per_dchunk - 50 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk;
	merged_len = 9*fsbs_per_dchunk - 30 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 4*fsbs_per_dchunk;
	merged_len = 9*fsbs_per_dchunk - 30 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,6*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	/**************************************************************************/
	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== freed covers three discard-chunk #6-7-8 in AG#3, we can discard second two ===");
	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 1;
	merged_len = 9*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = bno;
	merged_len = 9*fsbs_per_dchunk + 20 - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - 50 - bno;
	merged_bno = 6*fsbs_per_dchunk + 15;
	merged_len = 11*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

	bno = 6*fsbs_per_dchunk + 100;
	len = 9*fsbs_per_dchunk - bno;
	merged_bno = 6*fsbs_per_dchunk + 15;
	merged_len = 11*fsbs_per_dchunk - merged_bno;
	dr = zxfs_extent_busy_merged_to_discard_range(mp, agno, bno, len, merged_bno, merged_len);
	VALUE_SHOULD_BE(dr->discard_daddr, XFS_AGB_TO_DADDR(mp,agno,7*fsbs_per_dchunk), disc_daddr);
	VALUE_SHOULD_BE(dr->discard_bbs, XFS_FSB_TO_BB(mp, 2*fsbs_per_dchunk), disc_dlen);
	zxfs_discard_range_free(dr);

out:
	free_mp(mp);

	return error;
}

/* --------------------------------------------------*/
struct zxfs_test_xfs_extent_busy {
	xfs_agnumber_t	agno;
	xfs_agblock_t	bno;
	xfs_extlen_t	length;

	bool in_busy_tree;
	bool should_be_in_busy_tree;
};

struct zxfs_test_discard_range {
	xfs_agblock_t dbno;
	xfs_extlen_t dlen;
	xfs_daddr_t	discard_daddr;
	xfs_extlen_t discard_bbs;
	
	bool in_dr_tree;
	bool should_be_in_dr_tree;
	
	bool attached_to_busy;
	bool should_be_attached_to_busy;

	u8 flags_should_be;
};

STATIC struct zxfs_test_xfs_extent_busy*
__find_tbusyp(
	xfs_mount_t *mp,
	struct zxfs_test_xfs_extent_busy tbusy[],
	unsigned int num_tbusy,
	struct xfs_extent_busy *busyp)
{
	unsigned int idx = 0;
	for (idx = 0; idx < num_tbusy; ++idx) {
		if (tbusy[idx].agno == busyp->agno &&
			tbusy[idx].bno == busyp->bno &&
			tbusy[idx].length == busyp->length)
			return &tbusy[idx];
	}

	ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
		"busy[%u:%u:%u] not found!", 
		busyp->agno, busyp->bno, busyp->length);
	return NULL;
}

STATIC struct zxfs_test_discard_range*
__find_tdr(
	xfs_mount_t *mp,
	struct zxfs_test_discard_range tdrs[],
	unsigned int num_tdrs,
	struct zxfs_discard_range *dr)
{
	unsigned int idx = 0;
	for (idx = 0; idx < num_tdrs; ++idx) {
		if (tdrs[idx].discard_daddr == dr->discard_daddr &&
			tdrs[idx].discard_bbs == dr->discard_bbs)
			return &tdrs[idx];
	}

	ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
		"dr[%llu:%u] not found!", 
		dr->discard_daddr, dr->discard_bbs);
	return NULL;
}

STATIC int
__verify_busy_and_discard_trees(
	xfs_mount_t *mp,
	xfs_perag_t *pag,
	struct zxfs_test_xfs_extent_busy tbusy[],
	unsigned int num_tbusy,
	struct zxfs_test_discard_range tdrs[],
	unsigned int num_tdrs)
{
	int error = 0;
	unsigned int idx = 0;
	struct rb_node *rbp = NULL;

	for (idx = 0; idx < num_tbusy; ++idx) {
		tbusy[idx].in_busy_tree = false;
	}
	for (idx = 0; idx < num_tdrs; ++idx) {
		tdrs[idx].in_dr_tree = false;
		tdrs[idx].attached_to_busy = false;
	}

	spin_lock(&pag->pagb_lock);

	/* check the dr-tree first */
	rbp = rb_first(&pag->pagb_zdr_tree);
	while (rbp) {
		struct zxfs_discard_range *dr = rb_entry(rbp, struct zxfs_discard_range, dr_tree_node);
		struct zxfs_test_discard_range *tdr = __find_tdr(mp, tdrs, num_tdrs, dr);
		xfs_agnumber_t dagno = NULLAGNUMBER;
		xfs_agblock_t dagbno = NULLAGBLOCK;
		xfs_extlen_t dlen = 0;

		/* check the discard-range */
		COND_SHOULD_HOLD(tdr != NULL, tdr != NULL);
		error = __zxfs_discard_range_to_ag(mp, pag, dr,
					&dagno, &dagbno, &dlen);
		CALL_SHOULD_SUCCEED(error, __zxfs_discard_range_to_ag);
		VALUE_SHOULD_BE(dagno, pag->pag_agno, dagno);

		VALUE_SHOULD_BE(dr->flags, tdr->flags_should_be, dr->flags);

		/* found in dr-tree */
		VALUE_SHOULD_BE(tdr->in_dr_tree, false, in_dr_tree);
		tdr->in_dr_tree = true;
		rbp = rb_next(rbp);
	}

	/* now the busy extents tree */
	rbp = rb_first(&pag->pagb_tree);
	while (rbp) {
		struct xfs_extent_busy *busyp = rb_entry(rbp, struct xfs_extent_busy, rb_node);
		struct zxfs_test_xfs_extent_busy *tbusyp = __find_tbusyp(mp, tbusy, num_tbusy, busyp);
		struct zxfs_discard_range *dr = NULL;

		COND_SHOULD_HOLD(tbusyp != NULL, tbusyp != NULL);
		VALUE_SHOULD_BE(busyp->agno, pag->pag_agno, busyp->agno);
		VALUE_SHOULD_BE(busyp->flags, 0, busyp->flags);

		/* found in busy tree */
		VALUE_SHOULD_BE(tbusyp->in_busy_tree, false, in_busy_tree);
		tbusyp->in_busy_tree = true;
		
		/* check attached extents */
		list_for_each_entry(dr, &busyp->discard_ranges, link) {
			struct zxfs_test_discard_range *tdr = __find_tdr(mp, tdrs, num_tdrs, dr);

			COND_SHOULD_HOLD(tdr != NULL, tdr != NULL);

			/* if we are attached, we shouldn't have XFS_EXTENT_BUSY_DISCARDED set */
			if (dr->flags & XFS_EXTENT_BUSY_DISCARDED) {
				ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
					"dr[%llu:%u] XFS_EXTENT_BUSY_DISCARDED attached attached to busy",
					dr->discard_daddr, dr->discard_bbs);
				error = -EFSCORRUPTED;
				goto out;
			}

			/* attached */
			VALUE_SHOULD_BE(tdr->attached_to_busy, false, tdr->attached_to_busy);
			tdr->attached_to_busy = true;

			/* attached discard-range should be in dr-tree */
			VALUE_SHOULD_BE(tdr->in_dr_tree, true, in_dr_tree);
		}

		rbp = rb_next(rbp);
	}

	/* now check */
	for (idx = 0; idx < num_tbusy; ++idx) {
		if (tbusy[idx].agno == NULLAGNUMBER ||
			tbusy[idx].bno == NULLAGBLOCK ||
			tbusy[idx].length == 0) {
			/* not in use for the test */
			VALUE_SHOULD_BE(tbusy[idx].in_busy_tree, false, in_busy_tree);
			continue; 
		}

		if (tbusy[idx].in_busy_tree != tbusy[idx].should_be_in_busy_tree) {
			ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT,
				"busy[%u:%u:%u] in_busy_tree(%u)!=should_be_in_busy_tree(%u)",
				tbusy[idx].agno, tbusy[idx].bno, tbusy[idx].length,
				tbusy[idx].in_busy_tree, tbusy[idx].should_be_in_busy_tree);
			error = -EFSCORRUPTED;
			goto out;
		}
	}
	for (idx = 0; idx < num_tdrs; ++idx) {
		if (tdrs[idx].discard_daddr == NULLDADDR ||
			tdrs[idx].discard_bbs == 0) {
			/* not in use for the test */
			VALUE_SHOULD_BE(tdrs[idx].in_dr_tree, false, in_dr_tree);
			VALUE_SHOULD_BE(tdrs[idx].attached_to_busy, false, attached_to_busy);
			continue;
		}

		if (tdrs[idx].in_dr_tree != tdrs[idx].should_be_in_dr_tree) {
			ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
				"dr[%llu:%u] in_dr_tree(%u)!=should_be_in_dr_tree(%u)",
				tdrs[idx].discard_daddr, tdrs[idx].discard_bbs,
				tdrs[idx].in_dr_tree, tdrs[idx].should_be_in_dr_tree);
			error = -EFSCORRUPTED;
			goto out;
		}
		if (tdrs[idx].attached_to_busy != tdrs[idx].should_be_attached_to_busy) {
			ZXFSLOG_TAG(mp, Z_KERR, ZKLOG_TAG_BUSY_EXT, 
				"dr[%llu:%u] attached_to_busy(%u)!=should_be_attached_to_busy(%u)",
				tdrs[idx].discard_daddr, tdrs[idx].discard_bbs,
				tdrs[idx].attached_to_busy, tdrs[idx].should_be_attached_to_busy);
			error = -EFSCORRUPTED;
			goto out;
		}
	}

out:
	spin_unlock(&pag->pagb_lock);
	return error;
}

#define TBUSY(idx, bbno, blen, should_be_in_busy)            \
({                                                           \
	tbusy[idx].agno = agno;                                  \
	tbusy[idx].bno = bbno;                                   \
	tbusy[idx].length = blen;                                \
	tbusy[idx].should_be_in_busy_tree = should_be_in_busy;   \
})

#define TBUSY_CLEAR(idx)                                     \
({                                                           \
	tbusy[idx].agno = NULLAGNUMBER;                          \
	tbusy[idx].bno = NULLAGBLOCK;                            \
	tbusy[idx].length = 0;                                   \
	tbusy[idx].should_be_in_busy_tree = false;               \
})

#define TDR(idx, mp, d_bno, d_len, should_be_in_dr, should_be_attached, flags)				\
({																							\
	tdrs[idx].dbno = d_bno;																	\
	tdrs[idx].dlen = d_len;																	\
	tdrs[idx].discard_daddr = XFS_AGB_TO_DADDR(mp, agno, (d_bno));							\
	tdrs[idx].discard_bbs = XFS_FSB_TO_BB(mp, (d_len));										\
	tdrs[idx].should_be_in_dr_tree = should_be_in_dr;										\
	tdrs[idx].should_be_attached_to_busy = should_be_attached;								\
	tdrs[idx].flags_should_be = flags;														\
})

#define TDR_UPDATE(idx, should_be_in_dr, should_be_attached, flags)							\
({																							\
	tdrs[idx].should_be_in_dr_tree = should_be_in_dr;										\
	tdrs[idx].should_be_attached_to_busy = should_be_attached;								\
	tdrs[idx].flags_should_be = flags;														\
})

#define TDR_UPDATE_RANGE(idx, d_bno, d_len)						\
({																\
	tdrs[idx].discard_daddr = XFS_AGB_TO_DADDR(mp, agno, d_bno);\
	tdrs[idx].discard_bbs = XFS_FSB_TO_BB(mp, (d_len));      	\
})

#define TDR_CLEAR(idx)                                          \
({                                                              \
	tdrs[idx].discard_daddr = NULLDADDR;                        \
	tdrs[idx].discard_bbs = 0;                                  \
	tdrs[idx].should_be_in_dr_tree = false;                		\
	tdrs[idx].should_be_attached_to_busy = false;            	\
	tdrs[idx].flags_should_be = 0;                          	\
})

/* --------------------------------------------------*/
STATIC int
test_discard_ranges_register(void)
{
	int error = 0;
	xfs_mount_t *mp = NULL;
	xfs_agnumber_t agno = 3;
	xfs_perag_t *pag = NULL;
	xfs_trans_t* tps[10] = {NULL};
	struct zxfs_test_xfs_extent_busy tbusy[10] = {{0}};
	struct zxfs_test_discard_range tdrs[10] = {{0}};
	LIST_HEAD(dr_list);
	unsigned int idx = 0;
	unsigned int fsbs_per_dchunk = 0;

	for (idx = 0; idx < ARRAY_SIZE(tbusy); ++idx) {
		TBUSY_CLEAR(idx);
	}
	for (idx = 0; idx < ARRAY_SIZE(tdrs); ++idx) {
		TDR_CLEAR(idx);
	}

	error = alloc_mp(1024*1024/*discard_gran_bytes*/, &mp);
	CALL_SHOULD_SUCCEED(error , alloc_mp);
	error = alloc_perag(mp, agno, &pag);
	CALL_SHOULD_SUCCEED(error , alloc_perag);

	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		tps[idx] = _xfs_trans_alloc(mp, XFS_TRANS_CREATE, 0/*memflags*/);
		COND_SHOULD_HOLD(tps[idx] != NULL, tps[idx] != NULL);
	}

	COND_SHOULD_HOLD(ZXFS_ONLINE_DISCARD_ENABLED(mp), ZXFS_ONLINE_DISCARD_ENABLED);

	/* we have 256 4KB blocks per 1MB discard chunk */
	fsbs_per_dchunk = BBTOB(mp->m_zxfs.discard_gran_bbs) / mp->m_sb.sb_blocksize;
	VALUE_SHOULD_BE(fsbs_per_dchunk, 256, fsbs_per_dchunk);

	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== register some discard extents");
	TBUSY(0, 15*fsbs_per_dchunk + 20, 20, true);
	TDR(0, mp, 15*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, /*attached*/true, 0);
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0/*flags*/, tdrs[0].dbno/*merged_bno*/, tdrs[0].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(1, 18*fsbs_per_dchunk - 30, 50, true);
	TDR(1, mp, 17*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, /*attached*/true, 0);
	xfs_extent_busy_insert(tps[1], agno, tbusy[1].bno, tbusy[1].length, 0/*flags*/, tdrs[1].dbno/*merged_bno*/, tdrs[1].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(2, 19*fsbs_per_dchunk, 40, true);
	TDR(2, mp, 19*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, /*attached*/true, 0);
	xfs_extent_busy_insert(tps[2], agno, tbusy[2].bno, tbusy[2].length, 0/*flags*/, tdrs[2].dbno/*merged_bno*/, tdrs[2].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(3, 23*fsbs_per_dchunk - 100, 100, true);
	TDR(3, mp, 22*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, /*attached*/true, 0);
	xfs_extent_busy_insert(tps[3], agno, tbusy[3].bno, tbusy[3].length, 0/*flags*/, tdrs[3].dbno/*merged_bno*/, tdrs[3].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(4, 30*fsbs_per_dchunk, 3*fsbs_per_dchunk, true);
	TDR(4, mp, 30*fsbs_per_dchunk, 3*fsbs_per_dchunk, true/*in_dr*/, /*attached*/true, 0);
	xfs_extent_busy_insert(tps[4], agno, tbusy[4].bno, tbusy[4].length, 0/*flags*/, tdrs[4].dbno/*merged_bno*/, tdrs[4].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== new discard-range starts before existing and overlaps"); 
	TBUSY(5, 17*fsbs_per_dchunk - 5, 10, true);
	TDR(5, mp, 16*fsbs_per_dchunk, 2*fsbs_per_dchunk, false/*in_dr*/, false/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(5, 22*fsbs_per_dchunk - 5, 10, true);
	TDR(5, mp, 21*fsbs_per_dchunk, 2*fsbs_per_dchunk, false/*in_dr*/, false/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/*
	 * this is not strictly correct, we are adding a busy extent,
	 * which overlaps existing busy extent. but original XFS code
	 * only does ASSERT on this when compiled normally.
	 */
	TBUSY(5, 21*fsbs_per_dchunk, 3*fsbs_per_dchunk, true);
	TDR(5, mp, 21*fsbs_per_dchunk, 3*fsbs_per_dchunk, false/*in_dr*/, false/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== new discard-range starts at the same daddr as existing");
	TBUSY(5, 17*fsbs_per_dchunk, 10,  true);
	TDR(5, mp, 17*fsbs_per_dchunk, fsbs_per_dchunk, false/*in_dr*/, false/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== new discard range starts within existing");
	TBUSY(5, 18*fsbs_per_dchunk + 100, 10,  true);
	TDR(5, mp, 18*fsbs_per_dchunk, fsbs_per_dchunk, false/*in_dr*/, false/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(5, 31*fsbs_per_dchunk + 100, 10,  true);
	TDR(5, mp, 31*fsbs_per_dchunk, fsbs_per_dchunk, false/*in_dr*/, false/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(5, 19*fsbs_per_dchunk - 100, 105,  true);
	TDR(5, mp, 18*fsbs_per_dchunk, 2*fsbs_per_dchunk, false/*in_dr*/, false/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== check that non-overlapping discard ranges are possible to insert");
	TBUSY(5, 16*fsbs_per_dchunk + 100, 10,  true);
	TDR(5, mp, 16*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(6, 21*fsbs_per_dchunk - 15, 30, true);
	TDR(6, mp, 20*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	xfs_extent_busy_insert(tps[6], agno, tbusy[6].bno, tbusy[6].length, 0/*flags*/, tdrs[6].dbno/*merged_bno*/, tdrs[6].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(7, 14*fsbs_per_dchunk + 15, 30, true);
	TDR(7, mp, 14*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	xfs_extent_busy_insert(tps[7], agno, tbusy[7].bno, tbusy[7].length, 0/*flags*/, tdrs[7].dbno/*merged_bno*/, tdrs[6].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(8, 23*fsbs_per_dchunk, 30, true);
	TDR(8, mp, 23*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	xfs_extent_busy_insert(tps[8], agno, tbusy[8].bno, tbusy[8].length, 0/*flags*/, tdrs[8].dbno/*merged_bno*/, tdrs[8].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== clear all the busy extents and discard ranges as if we aborted");
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[1]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(1);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[3]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(3);
	TDR_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[0]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(0);
	TDR_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[7]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(7);
	TDR_CLEAR(7);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[8]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(8);
	TDR_CLEAR(8);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[4]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(4);
	TDR_CLEAR(4);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[6]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(6);
	TDR_CLEAR(6);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[2]->t_busy, &dr_list, false/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(2);
	TDR_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(pag->&pagb_zdr_tree));

out:
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		if (tps[idx])
			zxfs_trans_free(tps[idx]);
	}

	free_perag(pag);
	free_mp(mp);

	return error;
}

/* --------------------------------------------------*/
STATIC int
test_discard_ranges_check(void)
{
	int error = 0;
	xfs_mount_t *mp = NULL;
	xfs_agnumber_t agno = 3;
	xfs_perag_t *pag = NULL;
	xfs_trans_t* tps[10] = {NULL};
	LIST_HEAD(dr_list);
	struct zxfs_test_xfs_extent_busy tbusy[10] = {{0}};
	struct zxfs_test_discard_range tdrs[10] = {{0}};
	unsigned int idx = 0;
	unsigned int fsbs_per_dchunk = 0;

	for (idx = 0; idx < ARRAY_SIZE(tbusy); ++idx) {
		TBUSY_CLEAR(idx);
	}
	for (idx = 0; idx < ARRAY_SIZE(tdrs); ++idx) {
		TDR_CLEAR(idx);
	}

	error = alloc_mp(1024*1024/*discard_gran_bytes*/, &mp);
	CALL_SHOULD_SUCCEED(error , alloc_mp);
	error = alloc_perag(mp, agno, &pag);
	CALL_SHOULD_SUCCEED(error , alloc_perag);
	
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		tps[idx] = _xfs_trans_alloc(mp, XFS_TRANS_CREATE, 0/*memflags*/);
		COND_SHOULD_HOLD(tps[idx] != NULL, tps[idx] != NULL);
	}

	COND_SHOULD_HOLD(ZXFS_ONLINE_DISCARD_ENABLED(mp), ZXFS_ONLINE_DISCARD_ENABLED);

	/* we have 256 4KB blocks per 1MB discard chunk */
	fsbs_per_dchunk = BBTOB(mp->m_zxfs.discard_gran_bbs) / mp->m_sb.sb_blocksize;
	VALUE_SHOULD_BE(fsbs_per_dchunk, 256, fsbs_per_dchunk);

	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== insert some busy extents without discard-ranges, and clear them");
	TBUSY(0, 1000, 10, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(1, 1100, 20, true);
	xfs_extent_busy_insert(tps[1], agno, tbusy[1].bno, tbusy[1].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(2, 1200, 15, true);
	xfs_extent_busy_insert(tps[2], agno, tbusy[2].bno, tbusy[2].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* commit */
	xfs_extent_busy_clear(mp, &tps[0]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[1]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	xfs_extent_busy_clear(mp, &tps[2]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== discard ranges that do not overlap any busy extents");
	TBUSY(0, 11*fsbs_per_dchunk - 20, 20, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(1, 13*fsbs_per_dchunk, 30, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[1].bno, tbusy[1].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(2, 15*fsbs_per_dchunk + 50, 50, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[2].bno, tbusy[2].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(3, 11*fsbs_per_dchunk + 50, 20, true);
	TDR(3, mp, 11*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, /*attached*/true, 0); /* adjacent to busy[0] from left */
	xfs_extent_busy_insert(tps[3], agno, tbusy[3].bno, tbusy[3].length, 0/*flags*/, tdrs[3].dbno/*merged_bno*/, tdrs[3].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(4, 12*fsbs_per_dchunk + 50, 20, true);
	TDR(4, mp, 12*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0); /* adjacent to busy[0] from right */
	xfs_extent_busy_insert(tps[4], agno, tbusy[4].bno, tbusy[4].length, 0/*flags*/, tdrs[4].dbno/*merged_bno*/, tdrs[4].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* commit */
	xfs_extent_busy_clear(mp, &tps[3]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(3);
	TDR_UPDATE(3, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[4]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(4);
	TDR_UPDATE(4, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	zxfs_discard_ranges_clear(mp, &dr_list);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TDR_CLEAR(3);
	TDR_CLEAR(4);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[0]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(0);
	TBUSY_CLEAR(1);
	TBUSY_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== discard range overlaps one other busy extent");	
	TBUSY(0, 11*fsbs_per_dchunk - 20, 20, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(1, 13*fsbs_per_dchunk + 30, 30, true);
	xfs_extent_busy_insert(tps[1], agno, tbusy[1].bno, tbusy[1].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(2, 13*fsbs_per_dchunk - 15, 45, true);
	TDR(2, mp, 12*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0); /* overlaps busy[1] */
	xfs_extent_busy_insert(tps[2], agno, tbusy[2].bno, tbusy[2].length, 0/*flags*/, tdrs[2].dbno/*merged_bno*/, tdrs[2].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(3, 15*fsbs_per_dchunk + 100, 100, true);
	xfs_extent_busy_insert(tps[3], agno, tbusy[3].bno, tbusy[3].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(4, 15*fsbs_per_dchunk + 200, 10, true);
	TDR(4, mp, 15*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0); /* overlaps busy[3] */
	xfs_extent_busy_insert(tps[4], agno, tbusy[4].bno, tbusy[4].length, 0/*flags*/, tdrs[4].dbno/*merged_bno*/, tdrs[4].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(5, 10*fsbs_per_dchunk, 10, true);
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(6, 11*fsbs_per_dchunk - 1, 1, true);
	TDR(6, mp, 10*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0); /* overlaps busy[5] */
	xfs_extent_busy_insert(tps[6], agno, tbusy[6].bno, tbusy[6].length, 0/*flags*/, tdrs[6].dbno/*merged_bno*/, tdrs[6].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* do commits */
	xfs_extent_busy_clear(mp, &tps[4]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(4);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	xfs_extent_busy_clear(mp, &tps[2]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[3]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(3);
	TDR_UPDATE(4, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	zxfs_discard_ranges_clear(mp, &dr_list);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TDR_CLEAR(4);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[1]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(1);
	TDR_UPDATE(2, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	zxfs_discard_ranges_clear(mp, &dr_list);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TDR_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[0]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[6]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(6);
	TDR_UPDATE(6, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	zxfs_discard_ranges_clear(mp, &dr_list);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TDR_CLEAR(6);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== discard range overlaps several busy extents ");
	TBUSY(0, 18*fsbs_per_dchunk - 20, 30, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	TBUSY(1, 16*fsbs_per_dchunk + 50, 10, true);
	xfs_extent_busy_insert(tps[1], agno, tbusy[1].bno, tbusy[1].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(2, 18*fsbs_per_dchunk - 30, 10, true);
	xfs_extent_busy_insert(tps[2], agno, tbusy[2].bno, tbusy[2].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(3, 17*fsbs_per_dchunk - 5, 20, true);
	TDR(3, mp, 16*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0); /* covers chunks 16 and 17 */
	xfs_extent_busy_insert(tps[3], agno, tbusy[3].bno, tbusy[3].length, 0/*flags*/, tdrs[3].dbno/*merged_bno*/, tdrs[3].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* commits */
	xfs_extent_busy_clear(mp, &tps[3]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[2]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[0]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	xfs_extent_busy_clear(mp, &tps[1]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(1);
	TDR_UPDATE(3, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	zxfs_discard_ranges_clear(mp, &dr_list);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TDR_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(pag->&pagb_zdr_tree));

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== more complex discard-range movearounds");
	TBUSY(0, 22*fsbs_per_dchunk + 120, 20, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(1, 21*fsbs_per_dchunk - 5, 5 + fsbs_per_dchunk + 5, true);
	TDR(1, mp, 21*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	/*
	 * note: here we want the discard-range to be inside the busy extent.
	 * but the merged-extent cannot be inside the busy extent; so we make
	 * the merged extent to be identical to the busy extent.
	 */
	xfs_extent_busy_insert(tps[1], agno, tbusy[1].bno, tbusy[1].length, 0/*flags*/, tdrs[1].dbno - 5/*merged_bno*/, 5 + tdrs[1].dlen + 5/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(2, 20*fsbs_per_dchunk + 50, 50, true);
	xfs_extent_busy_insert(tps[2], agno, tbusy[2].bno, tbusy[2].length, 0/*flags*/, NULLAGBLOCK/*merged_bno*/, 0/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(3, 20*fsbs_per_dchunk - 50, 100, true);
	TDR(3, mp, 19*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	xfs_extent_busy_insert(tps[3], agno, tbusy[3].bno, tbusy[3].length, 0/*flags*/, tdrs[3].dbno/*merged_bno*/, tdrs[3].dlen/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(4, 23*fsbs_per_dchunk - 10, 20, true);
	TDR(4, mp, 22*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	/* similar issue here with the merged range */
	xfs_extent_busy_insert(tps[4], agno, tbusy[4].bno, tbusy[4].length, 0/*flags*/, tdrs[4].dbno/*merged_bno*/, tdrs[4].dlen + 10/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(5, 24*fsbs_per_dchunk - 10, 20, true);
	TDR(5, mp, 23*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);
	/* similar issue here with the merged range */
	xfs_extent_busy_insert(tps[5], agno, tbusy[5].bno, tbusy[5].length, 0/*flags*/, tdrs[5].dbno/*merged_bno*/, tdrs[5].dlen + 10/*merged_len*/);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* commits */
	xfs_extent_busy_clear(mp, &tps[5]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[4]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(4);
	TDR_UPDATE(5, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[0]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	zxfs_discard_ranges_clear(mp, &dr_list);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TDR_CLEAR(5);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[3]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[2]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	xfs_extent_busy_clear(mp, &tps[1]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(1);
	TDR_UPDATE(1, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	TDR_UPDATE(3, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	TDR_UPDATE(4, true/*should_be_in_dr*/, false/*should_be_attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	zxfs_discard_ranges_clear(mp, &dr_list);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TDR_CLEAR(1);
	TDR_CLEAR(3);
	TDR_CLEAR(4);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tbusy));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

out:
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		if (tps[idx])
			zxfs_trans_free(tps[idx]);
	}

	free_perag(pag);
	free_mp(mp);

	return error;
}

/* --------------------------------------------------*/
#define CLEANUP_AND_REPOPULATE																					\
({																												\
	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== cleanup and repopulate");									\
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {																\
		if (tps[idx]) {																							\
			LIST_HEAD(dr_list);																					\
			xfs_extent_busy_clear(mp, &tps[idx]->t_busy, &dr_list, false/*do_discard*/);						\
			COND_SHOULD_HOLD(list_empty(&dr_list),list_empty(&dr_list));										\
		}																										\
	}																											\
																												\
	for (idx = 0; idx < ARRAY_SIZE(tbusy); ++idx) {																\
		TBUSY_CLEAR(idx);																						\
	}																											\
	for (idx = 0; idx < ARRAY_SIZE(tdrs); ++idx) {																\
		TDR_CLEAR(idx);																							\
	}																											\
																												\
	TBUSY(0, 11*fsbs_per_dchunk - 5, 10, true);																	\
	TDR(0, mp, 10*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);						\
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0, tdrs[0].dbno, tdrs[0].dlen);			\
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));			\
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);												\
																												\
	TBUSY(1, 13*fsbs_per_dchunk, 10, true);																		\
	TDR(1, mp, 13*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);						\
	xfs_extent_busy_insert(tps[1], agno, tbusy[1].bno, tbusy[1].length, 0, tdrs[1].dbno, tdrs[1].dlen);			\
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));			\
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);												\
																												\
	TBUSY(2, 16*fsbs_per_dchunk - 5, 5 + 2*fsbs_per_dchunk + 5, true);											\
	TDR(2, mp, 15*fsbs_per_dchunk, 4*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);						\
	xfs_extent_busy_insert(tps[2], agno, tbusy[2].bno, tbusy[2].length, 0, tdrs[2].dbno, tdrs[2].dlen);			\
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));			\
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);												\
																												\
	TBUSY(3, 20*fsbs_per_dchunk - 5, 5 + fsbs_per_dchunk + 5, true);											\
	TDR(3, mp, 19*fsbs_per_dchunk, 3*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0);						\
	xfs_extent_busy_insert(tps[3], agno, tbusy[3].bno, tbusy[3].length, 0, tdrs[3].dbno, tdrs[3].dlen);			\
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));			\
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);												\
																												\
	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== cleanup and repopulate DONE");							\
})

STATIC int
test_discard_ranges_prevent(void)
{
	int error = 0;
	xfs_mount_t *mp = NULL;
	xfs_agnumber_t agno = 3;
	xfs_perag_t *pag = NULL;
	xfs_trans_t* tps[10] = {NULL};
	struct zxfs_test_xfs_extent_busy tbusy[10] = {{0}};
	struct zxfs_test_discard_range tdrs[10] = {{0}};
	unsigned int idx = 0;
	unsigned int fsbs_per_dchunk = 0;

	for (idx = 0; idx < ARRAY_SIZE(tbusy); ++idx) {
		TBUSY_CLEAR(idx);
	}
	for (idx = 0; idx < ARRAY_SIZE(tdrs); ++idx) {
		TDR_CLEAR(idx);
	}

	error = alloc_mp(1024*1024/*discard_gran_bytes*/, &mp);
	CALL_SHOULD_SUCCEED(error , alloc_mp);
	error = alloc_perag(mp, agno, &pag);
	CALL_SHOULD_SUCCEED(error , alloc_perag);
	
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		tps[idx] = _xfs_trans_alloc(mp, XFS_TRANS_CREATE, 0/*memflags*/);
		COND_SHOULD_HOLD(tps[idx] != NULL, tps[idx] != NULL);
	}

	COND_SHOULD_HOLD(ZXFS_ONLINE_DISCARD_ENABLED(mp), ZXFS_ONLINE_DISCARD_ENABLED);

	/* we have 256 4KB blocks per 1MB discard chunk */
	fsbs_per_dchunk = BBTOB(mp->m_zxfs.discard_gran_bbs) / mp->m_sb.sb_blocksize;
	VALUE_SHOULD_BE(fsbs_per_dchunk, 256, fsbs_per_dchunk);

	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== overlap from left(1)");
	/*
	 * |aaaaaaaaaa|
	 *     |dddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 10*fsbs_per_dchunk - 50, 50 + 10);
	TDR_UPDATE_RANGE(0, 11*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 15*fsbs_per_dchunk - 50, 50 + 3*fsbs_per_dchunk + 1);
	TDR_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== overlap from left(2)");
	/*
	 * |aaaaaaaaaaaaaaaaaaa|
	 *    |dddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 15*fsbs_per_dchunk - 1, 1 + 4*fsbs_per_dchunk);
	TDR_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 13*fsbs_per_dchunk - 100, 100 + fsbs_per_dchunk);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== fully overlap");
	/*
	 * |aaaaaaaaaaaaaaaaaaaaaaa|
	 *	  |dddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 13*fsbs_per_dchunk - 1, 1 + fsbs_per_dchunk + 1);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 15*fsbs_per_dchunk - 1, 1 + (4+3)*fsbs_per_dchunk + 1);
	TDR_CLEAR(2);
	TDR_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== alloc-extent starts on same daddr as discard-range (1)");
	/*
	 *    |aaaaaaaaaaaaaa|
	 *	  |dddddddddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 19*fsbs_per_dchunk, fsbs_per_dchunk + 255);
	TDR_UPDATE_RANGE(3, 21*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 13*fsbs_per_dchunk, 1);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 15*fsbs_per_dchunk, 1);
	TDR_UPDATE_RANGE(2, 16*fsbs_per_dchunk, 3*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 10*fsbs_per_dchunk, fsbs_per_dchunk + 1);
	TDR_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== alloc-extent is exactly the same as discard-range");
	/*
	 *    |aaaaaaaaaaaaaaaaaaaaaa|
	 *	  |dddddddddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 15*fsbs_per_dchunk, 4*fsbs_per_dchunk);
	TDR_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 13*fsbs_per_dchunk, fsbs_per_dchunk);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 19*fsbs_per_dchunk, 3*fsbs_per_dchunk);
	TDR_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 10*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	TDR_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== alloc-extent starts on same daddr as discard-range (2)");
	/*
	 *	  |aaaaaaaaaaaaaaaaaaaaaaa|
	 *	  |ddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 13*fsbs_per_dchunk, fsbs_per_dchunk + 1);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 19*fsbs_per_dchunk, 3*fsbs_per_dchunk + 10);
	TDR_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 10*fsbs_per_dchunk, 2*fsbs_per_dchunk + 5);
	TDR_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 15*fsbs_per_dchunk, 4*fsbs_per_dchunk + 5);
	TDR_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== alloc-extent starts within discard-range (1)");
	/*
	 *	  |aaaaaaaa|
	 * |ddddddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 13*fsbs_per_dchunk + 50, 50);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 17*fsbs_per_dchunk + 50, 50);
	TDR_UPDATE_RANGE(2, 15*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	TDR(4, mp, 18*fsbs_per_dchunk, fsbs_per_dchunk,true/*in_dr*/,true/*attached*/, 0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 21*fsbs_per_dchunk - 50, 50 + 1);
	TDR_UPDATE_RANGE(3, 19*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 10*fsbs_per_dchunk + 50, 50);
	TDR_UPDATE_RANGE(0, 11*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== alloc-extent starts within discard-range (2)");
	/*
	 *	          |aaaaaaaa|
	 * |ddddddddddddddddddd|
	 */

	zxfs_discard_range_prevent(mp, agno, 18*fsbs_per_dchunk - 50, 50 + fsbs_per_dchunk);
	TDR_UPDATE_RANGE(2, 15*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 20*fsbs_per_dchunk - 1, 1 + 2*fsbs_per_dchunk);
	TDR_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 12*fsbs_per_dchunk - 10, 10);
	TDR_UPDATE_RANGE(0, 10*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 14*fsbs_per_dchunk - 100, 100);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== alloc-extent starts within discard-range (3)");
	/*
	 *			  |aaaaaaaaaaaa|
	 * |ddddddddddddddddddd|
	 */
	zxfs_discard_range_prevent(mp, agno, 12*fsbs_per_dchunk - 100, 100 + 15);
	TDR_UPDATE_RANGE(0, 10*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 20*fsbs_per_dchunk - 1, 1 + 2*fsbs_per_dchunk + 15);
	TDR_CLEAR(3);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 19*fsbs_per_dchunk - 1, 2);
	TDR_UPDATE_RANGE(2, 15*fsbs_per_dchunk, 3*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_range_prevent(mp, agno, 14*fsbs_per_dchunk - 50, 50 + 10);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== more complex overlaps (1)");
	zxfs_discard_range_prevent(mp, agno, 12*fsbs_per_dchunk - 100, 100 + fsbs_per_dchunk + 1);
	TDR_UPDATE_RANGE(0, 10*fsbs_per_dchunk, fsbs_per_dchunk);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== more complex overlaps (2)");
	zxfs_discard_range_prevent(mp, agno, 11*fsbs_per_dchunk - 1, 1 + 5*fsbs_per_dchunk + 1);
	TDR_CLEAR(0);
	TDR_CLEAR(1);
	TDR_UPDATE_RANGE(2, 17*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== more complex overlaps (3)");
	zxfs_discard_range_prevent(mp, agno, 14*fsbs_per_dchunk - 10, 10 + 6*fsbs_per_dchunk + 15);
	TDR_CLEAR(1);
	TDR_CLEAR(2);
	TDR_UPDATE_RANGE(3, 21*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	CLEANUP_AND_REPOPULATE;

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== more complex overlaps (4)");
	zxfs_discard_range_prevent(mp, agno, 19*fsbs_per_dchunk - 15, 15 + 15);
	TDR_UPDATE_RANGE(2, 15*fsbs_per_dchunk, 3*fsbs_per_dchunk);
	TDR_UPDATE_RANGE(3, 20*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

out:
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		if (tps[idx])
			zxfs_trans_free(tps[idx]);
	}

	free_perag(pag);
	free_mp(mp);

	return error;
}

STATIC int
test_discard_range_nobusy(void)
{
	int error = 0;
	xfs_mount_t *mp = NULL;
	xfs_agnumber_t agno = 3;
	xfs_perag_t *pag = NULL;
	xfs_trans_t* tps[10] = {NULL};
	struct zxfs_test_xfs_extent_busy tbusy[10] = {{0}};
	struct zxfs_test_discard_range tdrs[10] = {{0}};
	LIST_HEAD(dr_list);
	unsigned int idx = 0;
	unsigned int fsbs_per_dchunk = 0;

	for (idx = 0; idx < ARRAY_SIZE(tbusy); ++idx) {
		TBUSY_CLEAR(idx);
	}
	for (idx = 0; idx < ARRAY_SIZE(tdrs); ++idx) {
		TDR_CLEAR(idx);
	}

	error = alloc_mp(1024*1024/*discard_gran_bytes*/, &mp);
	CALL_SHOULD_SUCCEED(error , alloc_mp);
	error = alloc_perag(mp, agno, &pag);
	CALL_SHOULD_SUCCEED(error , alloc_perag);
	
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		tps[idx] = _xfs_trans_alloc(mp, XFS_TRANS_CREATE, 0/*memflags*/);
		COND_SHOULD_HOLD(tps[idx] != NULL, tps[idx] != NULL);
	}

	COND_SHOULD_HOLD(ZXFS_ONLINE_DISCARD_ENABLED(mp), ZXFS_ONLINE_DISCARD_ENABLED);

	/* we have 256 4KB blocks per 1MB discard chunk */
	fsbs_per_dchunk = BBTOB(mp->m_zxfs.discard_gran_bbs) / mp->m_sb.sb_blocksize;
	VALUE_SHOULD_BE(fsbs_per_dchunk, 256, fsbs_per_dchunk);

	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== populate with busy extents");
	TBUSY(0, 11*fsbs_per_dchunk + 50, 10, true);
	xfs_extent_busy_insert(tps[0], agno, tbusy[0].bno, tbusy[0].length, 0, NULLAGBLOCK, 0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	TBUSY(1, 12*fsbs_per_dchunk, 10, true);
	xfs_extent_busy_insert(tps[1], agno, tbusy[1].bno, tbusy[1].length, 0, NULLAGBLOCK, 0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	TBUSY(2, 15*fsbs_per_dchunk + 200, 15, true);
	xfs_extent_busy_insert(tps[2], agno, tbusy[2].bno, tbusy[2].length, 0, NULLAGBLOCK, 0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	TBUSY(3, 16*fsbs_per_dchunk - 5, 5, true);
	xfs_extent_busy_insert(tps[3], agno, tbusy[3].bno, tbusy[3].length, 0, NULLAGBLOCK, 0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	ZXFSLOG_TAG(mp, Z_KINFO, ZKLOG_TAG_BUSY_EXT, "=== directly insert discard ranges at different spots");

	/* can discard */
	zxfs_discard_range_insert_nobusy(mp, pag, 13*fsbs_per_dchunk,1, 13*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	
	/* can discard */
	zxfs_discard_range_insert_nobusy(mp, pag, 14*fsbs_per_dchunk - 1, 2, 13*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* can discard */
	zxfs_discard_range_insert_nobusy(mp, pag, 11*fsbs_per_dchunk - 1, 2, 10*fsbs_per_dchunk, fsbs_per_dchunk + 1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* can discard */
	zxfs_discard_range_insert_nobusy(mp, pag, 16*fsbs_per_dchunk + 100, 10, 16*fsbs_per_dchunk, fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* cannot discard */
	TDR(0, mp, 12*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0/*flags*/);
	zxfs_discard_range_insert_nobusy(mp, pag, 13*fsbs_per_dchunk - 1, 2, 12*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* cannot discard */
	TDR(1, mp, 14*fsbs_per_dchunk, 2*fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0/*flags*/);
	zxfs_discard_range_insert_nobusy(mp, pag, 15*fsbs_per_dchunk - 5, 10, 14*fsbs_per_dchunk, 2*fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* cannot discard */
	TDR(2, mp, 11*fsbs_per_dchunk, fsbs_per_dchunk, true/*in_dr*/, true/*attached*/, 0/*flags*/);
	zxfs_discard_range_insert_nobusy(mp, pag, 11*fsbs_per_dchunk - 5, 5 + 5, 11*fsbs_per_dchunk - 5, 5 + fsbs_per_dchunk);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* busy[2] commits, still cannot discard */
	xfs_extent_busy_clear(mp, &tps[2]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(list_empty(&dr_list), list_empty(&dr_list));
	TBUSY_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* busy[0] commits, can discard */
	xfs_extent_busy_clear(mp, &tps[0]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(0);
	TDR_UPDATE(2, true/*in_dr*/, false/*attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_ranges_clear(mp, &dr_list);
	TDR_CLEAR(2);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* busy[3] commits, can discard */
	xfs_extent_busy_clear(mp, &tps[3]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(3);
	TDR_UPDATE(1, true/*in_dr*/, false/*attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_ranges_clear(mp, &dr_list);
	TDR_CLEAR(1);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	/* busy[1] commits, can discard */
	xfs_extent_busy_clear(mp, &tps[1]->t_busy, &dr_list, true/*do_discard*/);
	COND_SHOULD_HOLD(!list_empty(&dr_list), !list_empty(&dr_list));
	TBUSY_CLEAR(1);
	TDR_UPDATE(0, true/*in_dr*/, false/*attached*/, XFS_EXTENT_BUSY_DISCARDED);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);
	zxfs_discard_ranges_clear(mp, &dr_list);
	TDR_CLEAR(0);
	error = __verify_busy_and_discard_trees(mp, pag, tbusy, ARRAY_SIZE(tbusy), tdrs, ARRAY_SIZE(tdrs));
	CALL_SHOULD_SUCCEED(error , __verify_busy_and_discard_trees);

	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_tree), RB_EMPTY_ROOT(&pag->pagb_tree));
	COND_SHOULD_HOLD(RB_EMPTY_ROOT(&pag->pagb_zdr_tree), RB_EMPTY_ROOT(&pag->pagb_zdr_tree));

out:
	for (idx = 0; idx < ARRAY_SIZE(tps); ++idx) {
		if (tps[idx])
			zxfs_trans_free(tps[idx]);
	}

	free_perag(pag);
	free_mp(mp);

	return error;
}
	
/* --------------------------------------------------*/
int zxfs_test_busy_extents(void)
{
	int error = 0;

	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "Running test_merged_to_discard...");
	error = test_merged_to_discard();
	CALL_SHOULD_SUCCEED(error, test_merged_to_discard);

	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "Running test_discard_ranges_register...");
	error = test_discard_ranges_register();
	CALL_SHOULD_SUCCEED(error, test_discard_ranges_register);

	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "Running test_discard_ranges_check...");
	error = test_discard_ranges_check();
	CALL_SHOULD_SUCCEED(error, test_discard_ranges_check);

	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "Running test_discard_ranges_prevent...");
	error = test_discard_ranges_prevent();
	CALL_SHOULD_SUCCEED(error, test_discard_ranges_prevent);

	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "Running test_discard_range_nobusy...");
	error = test_discard_range_nobusy();
	CALL_SHOULD_SUCCEED(error, test_discard_range_nobusy);

	zklog_tag(Z_KINFO, ZKLOG_TAG_BUSY_EXT, "All tests passed.");

out:
	return error;
}

#endif /*CONFIG_XFS_ZADARA*/

