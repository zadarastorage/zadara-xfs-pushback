#include <linux/version.h>
#include <linux/blkdev.h>

#include "zbio.h"
#include "zklog.h"

/*
 * Miscallaneous wrappers and utility functions, related
 * to bio handling.
 */

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0))

static int __zbio_add_page(struct request_queue *q, struct bio *bio, struct page *page,
			  unsigned int len, unsigned int offset)
{
	int retried_segments = 0;
	struct bio_vec *bvec;
	char buf[BDEVNAME_SIZE];

	/*
	 * cloned bio must not modify vec list
	 */
	if (unlikely(bio_flagged(bio, BIO_CLONED))) {
		zklog_ratelimited(Z_KERR, "bdev(%s): BIO_CLONED", bdevname(bio->bi_bdev, buf));
		return 0;
	}

	/*
	 * Do not honour max_sectors of the block device.
	 * So the block device should be able to handle larger bios.
	 */
#if 0
	if (((bio->bi_iter.bi_size + len) >> 9) > max_sectors) {
		zklog_ratelimited(Z_KERR, "bdev(%s): (bio->bi_iter.bi_size + len) >> 9(%u) > max_sectors(%u)", bdevname(bio->bi_bdev, buf), (bio->bi_iter.bi_size + len) >> 9, max_sectors);
		return 0;
	}
#endif	

	/*
	 * For filesystems with a blocksize smaller than the pagesize
	 * we will often be called with the same page as last time and
	 * a consecutive offset.  Optimize this special case. 
	 * ZADARA - should not enter this if 
	 */
	if (bio->bi_vcnt > 0) {
		struct bio_vec *prev = &bio->bi_io_vec[bio->bi_vcnt - 1];

		if (page == prev->bv_page &&
		    offset == prev->bv_offset + prev->bv_len) {
			zklog_ratelimited(Z_KERR, "bdev(%s): page %p[off=%u len=%u] prev[off=%u len=%u] not added again to bio %p", 
				              bdevname(bio->bi_bdev, buf), page, offset, len, prev->bv_offset, prev->bv_len, bio);
			return 0;
		}

		/*
		 * If the queue doesn't support SG gaps and adding this
		 * offset would create a gap, disallow it.
		 */
		if (q->queue_flags & (1 << QUEUE_FLAG_SG_GAPS) &&
			bvec_gap_to_prev(prev, offset)) {
			zklog_ratelimited(Z_KERR, "bdev(%s): QUEUE_FLAG_SG_GAPS is set and gap page %p[off=%u len=%u] prev[off=%u len=%u] bio %p",
				              bdevname(bio->bi_bdev, buf), page, offset, len, prev->bv_offset, prev->bv_len, bio);
			return 0;
		}
	}

	if (bio->bi_vcnt >= bio->bi_max_vecs) {
		zklog_ratelimited(Z_KERR, "bdev(%s): bio->bi_vcnt(%u) >= bio->bi_max_vecs(%u)", bdevname(bio->bi_bdev, buf), bio->bi_vcnt, bio->bi_max_vecs);
		return 0;
	}

	/*
	 * Zadara: do not agree to work with bios that have more than BIO_MAX_PAGES.
	 * Such bios are not splittable by Device-Mapper, see alloc_tio().
	 */
	if (unlikely(bio->bi_max_vecs > BIO_MAX_PAGES)) {
		zklog_ratelimited(Z_KERR, "bdev(%s): bio->bi_max_vecs(%u) > BIO_MAX_PAGES(%u)", bdevname(bio->bi_bdev, buf), bio->bi_max_vecs, BIO_MAX_PAGES);
		return 0;
	}

	/*
	 * we might lose a segment or two here, but rather that than
	 * make this too complex.
	 */

	while (bio->bi_phys_segments >= queue_max_segments(q)) {

		if (retried_segments) {
			zklog_ratelimited(Z_KERR, "bdev(%s): bio->bi_phys_segments(%u) >= queue_max_segments(q)(%u)", bdevname(bio->bi_bdev, buf), bio->bi_phys_segments, queue_max_segments(q));
			return 0;
		}

		retried_segments = 1;
		blk_recount_segments(q, bio);
	}

	/*
	 * setup the new entry, we might clear it again later if we
	 * cannot add the page
	 */
	bvec = &bio->bi_io_vec[bio->bi_vcnt];
	bvec->bv_page = page;
	bvec->bv_len = len;
	bvec->bv_offset = offset;

	/* If we may be able to merge these biovecs, force a recount */
	if (bio->bi_vcnt && (BIOVEC_PHYS_MERGEABLE(bvec-1, bvec)))
		bio->bi_flags &= ~(1 << BIO_SEG_VALID);

	bio->bi_vcnt++;
	bio->bi_phys_segments++;

	bio_size(bio) += len;
	return len;
}

int zbio_add_page(struct bio *bio, struct page *page, unsigned int len,
		 unsigned int offset)
{
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	return __zbio_add_page(q, bio, page, len, offset);
}
EXPORT_SYMBOL(zbio_add_page);

#if 0
/*
 * This is a simplified version of __bio_map_user_iov, with
 * following differences from the original:
 * - it assumes a single buffer to be mapped (not an IOV of buffers)
 * - it calls __zbio_add_page() to make sure that any bdev restrictions on
 *   max bio length are not honoured
 * - it does not return partial mapping, while __bio_map_user_iov can return a partial
 *   mapping in case bio_add_pc_page() fails to add a page.
 * - it does not create bios that have more than BIO_MAX_PAGES entries (in that
 *   case the function *will* create a partial mapping.
 */
static struct bio *__zbio_map_user(struct request_queue *q,
				      struct block_device *bdev,
				      unsigned long uaddr, unsigned long len,
				      int write_to_vm, gfp_t gfp_mask)
{
	unsigned int i = 0;
	unsigned int nr_pages = 0;
	struct page **pages = NULL;
	struct bio *bio = NULL;
	int ret = 0;
	char bname[BDEVNAME_SIZE] = "";

	{
		unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		unsigned long start = uaddr >> PAGE_SHIFT;

		/*
		 * Overflow, abort
		 */
		if (end < start) {
			zklog(Z_KERR, "bdev(%s): uaddr=%lu, len=%lu, %s: end=%lu < start=%lu, ret=%d",
				  bdevname(bdev, bname), uaddr, len, write_to_vm ? "RD" : "WR", end, start, -EINVAL);
			return ERR_PTR(-EINVAL);
		}

		nr_pages = end - start;

		/*
		 * buffer must be aligned to at least hardsector size for now
		 */
		if (uaddr & queue_dma_alignment(q)) {
			zklog(Z_KERR, "bdev(%s): uaddr=%#lx, len=%lu, %s: queue_dma_alignment=%d, uaddr&align=%#lx, ret=%d",
				  bdevname(bdev, bname), uaddr, len, write_to_vm ? "RD" : "WR", queue_dma_alignment(q), uaddr & queue_dma_alignment(q), -EINVAL);
			return ERR_PTR(-EINVAL);
		}
	}

	if (!nr_pages) {
		zklog(Z_KERR, "bdev(%s): uaddr=%lu, len=%lu, %s: nr_pages=%u, ret=%d",
			  bdevname(bdev, bname), uaddr, len, write_to_vm ? "RD" : "WR", nr_pages, -EINVAL);
		return ERR_PTR(-EINVAL);
	}

	/* 
	 * Zadara: do not map more than BIO_MAX_PAGES.
	 * Note that the caller is responsible to check
	 * the returned bio - it might not map the whole user
	 * buffer.
	 */
	if (nr_pages > BIO_MAX_PAGES)
		nr_pages = BIO_MAX_PAGES;

	bio = bio_kmalloc(gfp_mask, nr_pages);
	if (!bio) {
		zklog(Z_KERR, "bdev(%s): uaddr=%lu, len=%lu, %s: bio=%p, ret=%d",
			  bdevname(bdev, bname), uaddr, len, write_to_vm ? "RD" : "WR", bio, -ENOMEM);
		return ERR_PTR(-ENOMEM);
	}

	ret = -ENOMEM;
	pages = kcalloc(nr_pages, sizeof(struct page *), gfp_mask);
	if (!pages) {
		zklog(Z_KERR, "bdev(%s): uaddr=%lu, len=%lu, %s: pages=%p, ret=%d",
			  bdevname(bdev, bname), uaddr, len, write_to_vm ? "RD" : "WR", pages, -ENOMEM);
		goto out;
	}

	/* __zbio_add_page needs to have a valid bdev on the bio */
	bio->bi_bdev = bdev;

	{
		int offset;

		ret = get_user_pages_fast(uaddr, nr_pages,
				write_to_vm, &pages[0]);
		if (ret < nr_pages) {
			zklog(Z_KERR, "bdev(%s): uaddr=%lu, len=%lu, %s: get_user_pages_fast=%d < nr_pages=%u, ret=%d",
				  bdevname(bdev, bname), uaddr, len, write_to_vm ? "RD" : "WR", ret, nr_pages, -EFAULT);
			ret = -EFAULT;
			goto out_unmap;
		}

		offset = uaddr & ~PAGE_MASK;
		for (i = 0; i < nr_pages; i++) {
			unsigned int bytes = PAGE_SIZE - offset;

			if (len <= 0)
				break;

			if (bytes > len)
				bytes = len;

			if (__zbio_add_page(q, bio, pages[i], bytes, offset) < bytes) {
				zklog(Z_KERR, "bdev(%s): uaddr=%lu, len=%lu, %s: __zbio_add_page() failed, ret=%d",
					  bdevname(bdev, bname), uaddr, len, write_to_vm ? "RD" : "WR", -ECANCELED);
				ret = -ECANCELED;
				goto out_unmap;
			}

			len -= bytes;
			offset = 0;
		}
	}

	kfree(pages);

	/*
	 * set data direction, and check if mapped pages need bouncing
	 */
	if (!write_to_vm)
		bio->bi_rw |= REQ_WRITE;

	bio->bi_flags |= (1 << BIO_USER_MAPPED);
	return bio;

 out_unmap:
	for (i = 0; i < nr_pages; i++) {
		if(!pages[i])
			break;
		page_cache_release(pages[i]);
	}
 out:
	kfree(pages);
	bio_put(bio);
	return ERR_PTR(ret);
}
#endif

/*
 * This is a simplified version of __bio_map_user_iov, with
 * following differences from the original:
 * - it calls __zbio_add_page() to make sure that any bdev restrictions on
 *   max bio length are not honoured
 * - it does not return partial mapping, while __bio_map_user_iov can return a partial
 *   mapping in case bio_add_pc_page() fails to add a page.
 * - it does not create bios larger that have more than BIO_MAX_PAGES entries (in that
 *   case the function *will* create a partial mapping).
 * Note: all buffers in the IOV are assumed to be of the same size - iov_len_bytes.
 */
static struct bio *__zbio_map_user_iov(struct request_queue *q,
				      struct block_device *bdev,
				      unsigned long *iov, unsigned int iov_count, unsigned int iov_len_bytes,
				      int write_to_vm, gfp_t gfp_mask)
{
	int i = 0, j = 0;
	int nr_pages = 0;
	struct page **pages = NULL;
	struct bio *bio = NULL;
	int cur_page = 0;
	int ret = 0;
	char bname[BDEVNAME_SIZE] = {'\0'};

	for (i = 0; i < iov_count; i++) {
		unsigned long uaddr = iov[i];
		unsigned long len = iov_len_bytes;
		unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		unsigned long start = uaddr >> PAGE_SHIFT;

		/*
		 * Overflow, abort
		 */
		if (end < start) {
			zklog(Z_KERR, "bdev(%s): iov=#%d uaddr=%#lx len=%lu, %s: end=%lu < start=%lu, ret=%d",
				  bdevname(bdev, bname), i, uaddr, len, write_to_vm ? "RD" : "WR", end, start, -EINVAL);
			return ERR_PTR(-EINVAL);
		}

		nr_pages += end - start;
		/*
		 * buffer must be aligned to at least hardsector size for now
		 */
		if (uaddr & queue_dma_alignment(q)) {
			zklog(Z_KERR, "bdev(%s): iov=#%d uaddr=%#lx len=%lu, %s: queue_dma_alignment=%d, uaddr&align=%#lx, ret=%d",
				  bdevname(bdev, bname), i, uaddr, len, write_to_vm ? "RD" : "WR", 
				  queue_dma_alignment(q), uaddr & queue_dma_alignment(q), -EINVAL);
			return ERR_PTR(-EINVAL);
		}
	}

	if (!nr_pages) {
		zklog(Z_KERR, "bdev(%s): iov_count=%u iov_len_bytes=%u, %s: nr_pages=%d, ret=%d",
			  bdevname(bdev, bname), iov_count, iov_len_bytes, write_to_vm ? "RD" : "WR", nr_pages, -EINVAL);
		return ERR_PTR(-EINVAL);
	}

	/* 
	 * Zadara: do not map more than BIO_MAX_PAGES.
	 * Note that the caller is responsible to check
	 * the returned bio - it might not map the whole user
	 * buffer.
	 */
	if (nr_pages > BIO_MAX_PAGES)
		nr_pages = BIO_MAX_PAGES;

	bio = bio_kmalloc(gfp_mask, nr_pages);
	if (!bio) {
		zklog(Z_KERR, "bdev(%s): nr_pages=%d bio_kmalloc() failed, ret=%d",
			  bdevname(bdev, bname), nr_pages, -ENOMEM);
		return ERR_PTR(-ENOMEM);
	}

	ret = -ENOMEM;
	pages = kcalloc(nr_pages, sizeof(struct page *), gfp_mask);
	if (!pages) {
		zklog(Z_KERR, "bdev(%s): nr_pages=%d kcalloc(nr_pages/page*) failed, ret=%d",
			  bdevname(bdev, bname), nr_pages, -ENOMEM);
		goto out;
	}

	/* __zbio_add_page needs to have a valid bdev on the bio */
	bio->bi_bdev = bdev;

	for (i = 0; i < iov_count; i++) {
		int offset = 0;
		unsigned long uaddr = iov[i];
		unsigned long len = iov_len_bytes;
		unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		unsigned long start = uaddr >> PAGE_SHIFT;
		int local_nr_pages = end - start;
		int page_limit = 0;
		/* 
		 * we need to check that we do not attempt to map more than nr_pages.
		 * note that we might have limited nr_pages due to BIO_MAX_PAGES.
		 */
		if (cur_page + local_nr_pages > nr_pages)
			local_nr_pages = nr_pages - cur_page;
		if (local_nr_pages == 0)
			break;
		page_limit = cur_page + local_nr_pages;

		ret = get_user_pages_fast(uaddr, local_nr_pages,
				write_to_vm, &pages[cur_page]);
		if (ret < local_nr_pages) {
			zklog(Z_KERR, "bdev(%s): iov=#%d uaddr=%#lx len=%lu, %s: get_user_pages_fast=%d < local_nr_pages=%u, ret=%d",
				  bdevname(bdev, bname), i, uaddr, len, write_to_vm ? "RD" : "WR", ret, local_nr_pages, -EFAULT);
			ret = -EFAULT;
			goto out_unmap;
		}

		offset = uaddr & ~PAGE_MASK;
		for (j = cur_page; j < page_limit; j++) {
			unsigned int bytes = PAGE_SIZE - offset;

			if (len <= 0)
				break;
			
			if (bytes > len)
				bytes = len;

			if (__zbio_add_page(q, bio, pages[j], bytes, offset) < bytes) {
				zklog(Z_KERR, "bdev(%s): iov=#%d %s: __zbio_add_page(page=#%d,len=%u,offset=%d) failed, ret=%d",
					  bdevname(bdev, bname), i, write_to_vm ? "RD" : "WR", j, bytes, offset, -ECANCELED);
				ret = -ECANCELED;
				goto out_unmap;
			}

			len -= bytes;
			offset = 0;
		}

		/* we should have added all needed pages */
		if (WARN_ON(j != page_limit)) {
			ret = -ECANCELED;
			goto out_unmap;
		}

		cur_page = page_limit;
		BUG_ON(cur_page > nr_pages);
	}

	kfree(pages);

	/*
	 * set data direction, and check if mapped pages need bouncing
	 */
	if (!write_to_vm)
		bio->bi_rw |= REQ_WRITE;

	bio->bi_flags |= (1 << BIO_USER_MAPPED);
	return bio;

 out_unmap:
	for (i = 0; i < nr_pages; i++) {
		if(!pages[i])
			break;
		page_cache_release(pages[i]);
	}
 out:
	kfree(pages);
	bio_put(bio);
	return ERR_PTR(ret);
}

struct bio *zbio_map_user(struct request_queue *q, struct block_device *bdev,
			 unsigned long uaddr, unsigned int len, int write_to_vm,
			 gfp_t gfp_mask)
{
	unsigned long iov[1] = {uaddr};
	struct bio *bio = NULL;

	bio = __zbio_map_user_iov(q, bdev, iov, 1/*iov_count*/, len, write_to_vm, gfp_mask);
	if (IS_ERR(bio))
		return bio;

	/*
	 * subtle -- if __bio_map_user() ended up bouncing a bio,
	 * it would normally disappear when its bi_end_io is run.
	 * however, we need it for the unmap, so grab an extra
	 * reference to it
	 */
	/*
	 * AlexL/Zadara: I am not sure this is needed, but since bio will
	 * be released by bio_unmap_user (which we don't override), we need
	 * this to match it.
	 */
	bio_get(bio);

	return bio;
}
EXPORT_SYMBOL(zbio_map_user);

struct bio *zbio_map_user_iov(struct request_queue *q, struct block_device *bdev,
			     unsigned long *iov, unsigned int iov_count, unsigned int iov_len_bytes,
			     int write_to_vm, gfp_t gfp_mask)
{
	struct bio *bio = NULL;

	bio = __zbio_map_user_iov(q, bdev, iov, iov_count, iov_len_bytes, write_to_vm, gfp_mask);
	if (IS_ERR(bio))
		return bio;

	/*
	 * subtle -- if __bio_map_user() ended up bouncing a bio,
	 * it would normally disappear when its bi_end_io is run.
	 * however, we need it for the unmap, so grab an extra
	 * reference to it
	 */
	/*
	 * AlexL/Zadara: I am not sure this is needed, but since bio will
	 * be released by bio_unmap_user (which we don't override), we need
	 * this to match it.
	 */
	bio_get(bio);

	return bio;
}
EXPORT_SYMBOL(zbio_map_user_iov);

struct zread_write_ubuff_sync_compl_ctx {
	int error;
	struct block_device *bdev;

	struct completion compl;
	atomic_t in_flight_bios;

	struct bio_list *completed_bios;
	spinlock_t completed_bios_lock;
};

static void __zread_write_ubuff_sync_compl_ctx_init(struct zread_write_ubuff_sync_compl_ctx *ctx, struct block_device *bdev, struct bio_list *completed_bios, int nbios)
{
	ctx->error = 0;
	ctx->bdev = bdev;

	init_completion(&ctx->compl);
	atomic_set(&ctx->in_flight_bios, nbios);

	ctx->completed_bios = completed_bios;
	spin_lock_init(&ctx->completed_bios_lock);
}

static void __zread_write_ubuff_sync_end_io(struct bio *bio, int error)
{
	struct zread_write_ubuff_sync_compl_ctx *ctx = bio->bi_private;

	if (WARN_ON(error > 0))
		error = -EIO;

	/* this is a bit racy, but ok */
	if (unlikely(error)) {
		char bname[BDEVNAME_SIZE];

		zklog_ratelimited(Z_KERR, "bdev(%s): bio(%p) sect=%lu rw=0x%lx ret=%d", 
			              bdevname(ctx->bdev, bname), 
			              bio, bio_start_sector(bio), bio->bi_rw,
			              error);
		ctx->error = error;
	}

	/* this bio completed */
	spin_lock(&ctx->completed_bios_lock);
	bio_list_add(ctx->completed_bios, bio);
	spin_unlock(&ctx->completed_bios_lock);

	if (atomic_dec_return(&ctx->in_flight_bios) == 0)
		complete(&ctx->compl);
}

/*
 * @param out_bio_list supposed to be initialized by the caller;
 *                     upon return, will hold completed bios,
 *                     which the caller must release
 */
static int __zread_write_ubuff_sync(struct block_device *bdev,
	               sector_t start_sector,
	               u8 __user *ubuff, u32 nbytes,
	               bool bwrite, gfp_t gfp_mask,
	               struct bio_list *out_bio_list)
{
	int ret = 0;
	struct bio *bio = NULL;
	struct bio_list bios_to_spawn;
	struct zread_write_ubuff_sync_compl_ctx compl_ctx;

	ret = zbio_map_user_list(&bios_to_spawn, bdev, start_sector, ubuff, nbytes, bwrite, __zread_write_ubuff_sync_end_io, &compl_ctx, gfp_mask);
	if (unlikely(ret != 0))
		return ret;

	if (unlikely(nbytes == 0))
		return 0;

	__zread_write_ubuff_sync_compl_ctx_init(&compl_ctx, bdev, out_bio_list, bio_list_size(&bios_to_spawn));

	/* make sure we submit bios that are not on the list */
	while ((bio = bio_list_pop(&bios_to_spawn)) != NULL) {
		submit_bio(bio->bi_rw, bio);
	}

	/* wait until all bios complete */
	wait_for_completion(&compl_ctx.compl);

	ret = compl_ctx.error;

	/* completed bios are on the out_bio_list; caller is responsible to release them */

	return ret;
}

int zread_write_ubuff_sync(struct block_device *bdev,
						   sector_t start_sector,
						   u8 __user *ubuff, u32 nbytes,
						   bool bwrite, gfp_t gfp_mask)
{
	int ret = 0;
	struct bio_list completed_bios;

	bio_list_init(&completed_bios);

	ret = __zread_write_ubuff_sync(bdev, start_sector, ubuff, nbytes, bwrite, gfp_mask, &completed_bios);
	/* in any case */
	zread_write_ubuff_release_mapped_bios(&completed_bios);

	return ret;
}
EXPORT_SYMBOL(zread_write_ubuff_sync);

int zread_write_ubuff_sync_no_unmap(struct block_device *bdev,
						   sector_t start_sector,
						   u8 __user *ubuff, u32 nbytes,
						   bool bwrite, gfp_t gfp_mask,
						   struct bio_list *out_bio_list)
{
	int ret = 0;

	/* caller should not have anything there */
	bio_list_init(out_bio_list);

	ret = __zread_write_ubuff_sync(bdev, start_sector, ubuff, nbytes, bwrite, gfp_mask, out_bio_list);

	return ret;
}
EXPORT_SYMBOL(zread_write_ubuff_sync_no_unmap);

void zread_write_ubuff_release_mapped_bios(struct bio_list *bio_list)
{
	struct bio *bio = NULL;

	while ((bio = bio_list_pop(bio_list)) != NULL) {
		bio_unmap_user(bio);
	}
}
EXPORT_SYMBOL(zread_write_ubuff_release_mapped_bios);

int zbio_map_user_list(struct bio_list *bio_list,
					   struct block_device *bdev, sector_t start_sector, u8 __user *ubuff, u32 nbytes,
					   bool bwrite, bio_end_io_t bi_end_io, void *bi_private,
					   gfp_t gfp_mask)
{
	char bname[BDEVNAME_SIZE] = "";
	unsigned long uaddr = (uintptr_t)ubuff;
	struct bio *bio = NULL;
	int ret = 0;

	bio_list_init(bio_list);

	if (unlikely(!BYTES_ALIGNED_TO_BLK(uaddr) || !BYTES_ALIGNED_TO_BLK(nbytes))) {
		zklog_ratelimited(Z_KERR, "bdev(%s): uaddr=%p nbytes=%u - not aligned", bdevname(bdev, bname), ubuff, nbytes);
		return -EINVAL;
	}

	if (unlikely(nbytes == 0))
		return 0;

	/*
	 * zbio_map_user might refuse to map the specified range to a single bio due
	 * to BIO_MAX_PAGES restriction.
	 */
	while (nbytes > 0) {
		bio = zbio_map_user(bdev_get_queue(bdev), bdev, uaddr, nbytes, !bwrite/*write_to_vm*/, gfp_mask);
		if (unlikely(IS_ERR(bio))) {
			ret = PTR_ERR(bio);
			bio = NULL;
			goto end;
		}

		if (unlikely(bio_size(bio) > nbytes || !BYTES_ALIGNED_TO_BLK(bio_size(bio)))) {
			zklog(Z_KERR, "bdev(%s): bi_size=%u, nbytes=%u", bdevname(bdev, bname), bio_size(bio), nbytes);
			ret = -EINVAL;
			bio_unmap_user(bio);
			bio = NULL;
			goto end;
		}

		bio_start_sector(bio) = start_sector;
		bio->bi_end_io = bi_end_io;
		bio->bi_private = bi_private;

		/* adds bio to tail */
		bio_list_add(bio_list, bio); 

		/* for the next bio */
		uaddr += bio_size(bio);
		nbytes -= bio_size(bio);
		start_sector += BYTES_TO_BLK(bio_size(bio));
	}

end:
	if (unlikely(ret != 0)) {
		while ((bio = bio_list_pop(bio_list)) != NULL)
			bio_unmap_user(bio);
	}

	return ret;
}
EXPORT_SYMBOL(zbio_map_user_list);


/**
 * zblkdev_issue_zeroout - generate number of zero filed write bios. Based on __blkdev_issue_zeroout
 * @bdev:	blockdev to issue
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 *
 * Description:
 *  Generate and issue number of bios with zerofiled pages.
 */

struct zbio_batch {
	atomic_t		done;
	unsigned long		flags;
	struct completion	*wait;
};

static void zbio_batch_end_io(struct bio *bio, int err)
{
	struct zbio_batch *bb = bio->bi_private;

	if (err && (err != -EOPNOTSUPP))
		clear_bit(BIO_UPTODATE, &bb->flags);
	if (atomic_dec_and_test(&bb->done))
		complete(bb->wait);
	bio_put(bio);
}

int zblkdev_issue_zeroout(struct block_device *bdev, sector_t sector, sector_t nr_sects, gfp_t gfp_mask)
{
	int ret;
	struct bio *bio;
	struct zbio_batch bb;
	unsigned int sz;
	DECLARE_COMPLETION_ONSTACK(wait);

	atomic_set(&bb.done, 1);
	bb.flags = 1 << BIO_UPTODATE;
	bb.wait = &wait;

	ret = 0;
	while (nr_sects != 0) {
		bio = bio_alloc(gfp_mask,
				min(nr_sects, (sector_t)BIO_MAX_PAGES));
		if (!bio) {
			ret = -ENOMEM;
			break;
		}

		bio->bi_iter.bi_sector = sector;
		bio->bi_bdev   = bdev;
		bio->bi_end_io = zbio_batch_end_io;
		bio->bi_private = &bb;

		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE >> 9 , nr_sects);
			ret = bio_add_page(bio, ZERO_PAGE(0), sz << 9, 0);
			nr_sects -= ret >> 9;
			sector += ret >> 9;
			if (ret < (sz << 9))
				break;
		}
		ret = 0;
		atomic_inc(&bb.done);
		submit_bio(WRITE, bio);
	}

	/* Wait for bios in-flight */
	if (!atomic_dec_and_test(&bb.done))
		wait_for_completion_io(&wait);

	if (!test_bit(BIO_UPTODATE, &bb.flags))
		/* One of bios in the batch was completed with error.*/
		ret = -EIO;

	return ret;
}
EXPORT_SYMBOL(zblkdev_issue_zeroout);

#endif // (LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0))
	 

