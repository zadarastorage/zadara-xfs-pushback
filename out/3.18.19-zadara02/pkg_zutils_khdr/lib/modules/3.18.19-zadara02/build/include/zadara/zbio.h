#ifndef __ZUTILS_BIO_HDR__
#define __ZUTILS_BIO_HDR__

#include <linux/blk_types.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
	#define bio_start_sector(bio)	( (bio)->bi_iter.bi_sector )
	#define bio_size(bio)			( (bio)->bi_iter.bi_size )
#else
	#define bio_start_sector(bio)	( (bio)->bi_sector )
	#define bio_size(bio)			( (bio)->bi_size )
#endif 

#define ONE_BLK					(512)
#define BLK_TO_BYTES(blk)		((u64)(blk) << 9)
#define BYTES_TO_BLK(b)			( (b) >> 9)
#define BYTES_ALIGNED_TO_BLK(b) ((b) % ONE_BLK == 0) 

/**
 *	zbio_add_page	-	attempt to add page to bio
 *	@bio: destination bio
 *	@page: page to add
 *	@len: vec entry length
 *	@offset: vec entry offset
 *
 *	Attempt to add a page to the bio_vec maplist. This can fail for a
 *	number of reasons, such as the bio being full or target block device
 *	limitations. The target block device must allow bio's up to PAGE_SIZE,
 *	so it is always possible to add a single page to an empty bio.
 *
 *  Zadara:
 *  Similar to bio_add_page, but does not honour various bio->bi_bdev 
 *  restrictions on max bio size.
 *  As a result, bio->bi_bdev should be able to handle arbitrary large
 *  bios.
 *  However, note that bio must not have more BIO_MAX_PAGES entries.
 */
extern int zbio_add_page(struct bio *bio, struct page *page, unsigned int len,
		unsigned int offset);

/**
 *	zbio_map_user	-	map user address into bio
 *	@q: the struct request_queue for the bio
 *	@bdev: destination block device
 *	@uaddr: start of user address
 *	@len: length in bytes
 *	@write_to_vm: bool indicating writing to pages or not
 *	@gfp_mask: memory allocation flags
 *
 *	Map the user space address into a bio suitable for io to a block
 *	device. Returns an error pointer in case of error.
 *
 *  Zadara:
 *  Similar to bio_map_user, but does not honour various bio->bi_bdev 
 *  restrictions on max bio size.
 *  If the user-specified buffer needs more than BIO_MAX_PAGES entries in the bio,
 *  then a bio having BIO_MAX_PAGES entries is created, which maps the user buffer
 *  only partially. Caller must check bio->bi_size, and call this function again
 *  if needed, to create another bio.
 */
extern struct bio *zbio_map_user(struct request_queue *q, struct block_device *bdev,
		unsigned long uaddr, unsigned int len, int write_to_vm,
		gfp_t gfp_mask);

/**
 *	zbio_map_user_iov - map user scatter-gather buffer into bio
 *	@q: the struct request_queue for the bio
 *	@bdev: destination block device
 *	@iov:  array of pointers to user-space addresses
 *	@iov_count: number of elements in "iov"
 *  @iov_len_bytes: size of each user-space buffer (all buffers are considered equal)
 *	@write_to_vm: bool indicating writing to pages or not
 *	@gfp_mask: memory allocation flags
 *
 *	Map the user space address into a bio suitable for io to a block
 *	device. Returns an error pointer in case of error.
 *
 *  Zadara:
 *  Similar to bio_map_user_iov, but does not honour various bio->bi_bdev 
 *  restrictions on max bio size.
 *  If the user-specified buffer needs more than BIO_MAX_PAGES entries in the bio,
 *  then a bio having BIO_MAX_PAGES entries is created, which maps the user buffer
 *  only partially. Caller must check bio->bi_size, and call this function again
 *  if needed, to create another bio.
 */
extern struct bio *zbio_map_user_iov(struct request_queue *q, struct block_device *bdev,
			     unsigned long *iov, unsigned int iov_count, unsigned int iov_len_bytes,
			     int write_to_vm, gfp_t gfp_mask);

/**
 * Synchronously read or write data from/to the specified bdev,
 * to/from the specified user-buffer.
 *
 * @bdev: block device to read/write from/to
 * @start_sector: position in the block device
 * @ubuff: user buffer to read/write to/from
 * @nbytes: number of bytes to read/write
 * @bwrite: if true, then WRITE, otherwise READ
 * @gfp_mask: for allocations
 */
int zread_write_ubuff_sync(struct block_device *bdev,
						   sector_t start_sector,
						   u8 __user *ubuff, u32 nbytes,
						   bool bwrite, gfp_t gfp_mask);

/**
 * Synchronously read or write data from/to the specified bdev,
 * to/from the specified user-buffer.
 * After the IO is complete, the completed BIOs are returned
 * in "out_bio_list", and the caller is responsible to
 * call zread_write_ubuff_release_mapped_bios() with this list.
 * Until this call is made, the "ubuff" pages are pinned in the
 * kernel, and the caller can access "ubuff".
 *
 * @bdev: block device to read/write from/to
 * @start_sector: position in the block device
 * @ubuff: user buffer to read/write to/from
 * @nbytes: number of bytes to read/write
 * @bwrite: if true, then WRITE, otherwise READ
 * @gfp_mask: for allocations
 * @out_bio_list: upon success, will host BIOs to be released
 *                by the called via zread_write_ubuff_release_mapped_bios()
 */
int zread_write_ubuff_sync_no_unmap(struct block_device *bdev,
						   sector_t start_sector,
						   u8 __user *ubuff, u32 nbytes,
						   bool bwrite, gfp_t gfp_mask,
						   struct bio_list *out_bio_list);

/**
 * Release the BIOs returned by zread_write_ubuff_sync_no_unmap().
 */
void zread_write_ubuff_release_mapped_bios(struct bio_list *bio_list);


/**
 * map user buffer into bio_list 
 * @bdev: block device to read/write from/to
 * @start_sector: position in the block device
 * @ubuff: user buffer to read/write to/from
 * @nbytes: number of bytes to read/write
 * @bwrite: if true, then WRITE, otherwise READ 
 * @bi_end_io: callback to be set in bio->bi_end_io
 * @bi_private: value to be set in bio->bi_private
 * @gfp_mask: for allocations
 */
extern int zbio_map_user_list(struct bio_list *bio_list,
							  struct block_device *bdev, sector_t start_sector, u8 __user *ubuff, u32 nbytes,
							  bool bwrite, bio_end_io_t bi_end_io, void *bi_private,
							  gfp_t gfp_mask);

#endif /*__ZUTILS_BIO_HDR__*/
