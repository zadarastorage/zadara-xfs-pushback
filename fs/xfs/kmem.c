/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
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
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include "time.h"
#include "kmem.h"
#include "xfs_message.h"

/*
 * Greedy allocation.  May fail and may return vmalloced memory.
 *
 * Must be freed using kmem_free_large.
 */
void *
kmem_zalloc_greedy(size_t *size, size_t minsize, size_t maxsize)
{
	void		*ptr;
	size_t		kmsize = maxsize;

	while (!(ptr = kmem_zalloc_large(kmsize))) {
		if ((kmsize >>= 1) <= minsize)
			kmsize = minsize;
	}
	if (ptr)
		*size = kmsize;
	return ptr;
}

#ifndef CONFIG_XFS_ZADARA
void *
kmem_alloc(size_t size, xfs_km_flags_t flags)
{
	int	retries = 0;
	gfp_t	lflags = kmem_flags_convert(flags);
	void	*ptr;

	do {
		ptr = kmalloc(size, lflags);
		if (ptr || (flags & (KM_MAYFAIL|KM_NOSLEEP)))
			return ptr;
		if (!(++retries % 100))
			xfs_err(NULL,
		"possible memory allocation deadlock in %s (mode:0x%x)",
					__func__, lflags);
		congestion_wait(BLK_RW_ASYNC, HZ/50);
	} while (1);
}
#else /*CONFIG_XFS_ZADARA*/
void *
kmem_alloc(size_t size, xfs_km_flags_t flags)
{
	unsigned int retries = 0;
	gfp_t	lflags = kmem_flags_convert(flags);
	void	*ptr;

	do {
		ptr = kmalloc(size, lflags);
		if (ptr || (flags & (KM_MAYFAIL|KM_NOSLEEP))) {
			if (retries > 0 && ptr)
				xfs_info(NULL, "[%d] kmem_alloc success after %u retries size=%lu flags=0x%x lflags=0x%x", current->pid, retries, size, flags, lflags);
			return ptr;
		}
		if (retries == 0) {
			xfs_err(NULL, "[%d] kmem_alloc failure size=%lu flags=0x%x lflags=0x%x", current->pid, size, flags, lflags);
			dump_stack();
		}
		if (!(++retries % 100))
			xfs_err(NULL, "[%d] kmem_alloc failure size=%lu flags=0x%x lflags=0x%x retries=%u SLEEP", current->pid, size, flags, lflags, retries);
		congestion_wait(BLK_RW_ASYNC, HZ/50);
	} while (1);
}
#endif /*CONFIG_XFS_ZADARA*/

void *
kmem_zalloc(size_t size, xfs_km_flags_t flags)
{
	void	*ptr;

	ptr = kmem_alloc(size, flags);
	if (ptr)
		memset((char *)ptr, 0, (int)size);
	return ptr;
}

void
kmem_free(const void *ptr)
{
	if (!is_vmalloc_addr(ptr)) {
		kfree(ptr);
	} else {
		vfree(ptr);
	}
}

void *
kmem_realloc(const void *ptr, size_t newsize, size_t oldsize,
	     xfs_km_flags_t flags)
{
	void	*new;

	new = kmem_alloc(newsize, flags);
	if (ptr) {
		if (new)
			memcpy(new, ptr,
				((oldsize < newsize) ? oldsize : newsize));
		kmem_free(ptr);
	}
	return new;
}

#ifdef CONFIG_XFS_ZADARA
#include "xfs.h"
#include "xfs_bmap_btree.h"
#include "xfs_inode.h"
STATIC void
__ino_from_ifp(xfs_ifork_t *ifp, xfs_ino_t *inum)
{
	struct page *page = NULL;
	struct kmem_cache *cachep = NULL;
	xfs_inode_t *inode = NULL;

	/* if this is an attribute fork, it is allocated from kmem_cache */
	page = virt_to_head_page(ifp);
	cachep = page->slab_cache;
	if (cachep == xfs_ifork_zone)
		return;

	/* otherwise, it is embedded within xfs_inode */
	inode = container_of(ifp, xfs_inode_t, i_df);

	*inum = inode->i_ino;
}

STATIC void *
kmem_alloc_xfs_iext_realloc_indirect(size_t size, xfs_km_flags_t flags, xfs_ifork_t *ifp)
{
	unsigned int retries = 0;
	gfp_t	lflags = kmem_flags_convert(flags);
	void	*ptr;
	xfs_ino_t inum = ULLONG_MAX;

	__ino_from_ifp(ifp, &inum);

	do {
		ptr = kmalloc(size, lflags);
		if (ptr || (flags & (KM_MAYFAIL|KM_NOSLEEP))) {
			if (retries > 0 && ptr)
				xfs_info(NULL, "[%d] kmem_alloc success after %u retries inum=%llu size=%lu flags=0x%x lflags=0x%x", current->pid, retries, inum, size, flags, lflags);
			return ptr;
		}
		if (retries == 0) {
			xfs_err(NULL, "[%d] kmem_alloc failure inum=%llu size=%lu flags=0x%x lflags=0x%x", current->pid, inum, size, flags, lflags);
			dump_stack();
		}
		if (!(++retries % 100))
			xfs_err(NULL, "[%d] kmem_alloc failure inum=%llu size=%lu flags=0x%x lflags=0x%x retries=%u SLEEP", current->pid, inum, size, flags, lflags, retries);
		congestion_wait(BLK_RW_ASYNC, HZ/50);
	} while (1);
}

void *
kmem_realloc_xfs_iext_realloc_indirect(const void *ptr, size_t newsize, size_t oldsize, xfs_km_flags_t flags, struct xfs_ifork *ifp)
{
	void	*new;

	new = kmem_alloc_xfs_iext_realloc_indirect(newsize, flags, ifp);
	if (ptr) {
		if (new)
			memcpy(new, ptr,
				((oldsize < newsize) ? oldsize : newsize));
		kmem_free(ptr);
	}
	return new;
}
#endif /*CONFIG_XFS_ZADARA*/

void *
kmem_zone_alloc(kmem_zone_t *zone, xfs_km_flags_t flags)
{
	int	retries = 0;
	gfp_t	lflags = kmem_flags_convert(flags);
	void	*ptr;

	do {
		ptr = kmem_cache_alloc(zone, lflags);
		if (ptr || (flags & (KM_MAYFAIL|KM_NOSLEEP)))
			return ptr;
		if (!(++retries % 100))
			xfs_err(NULL,
		"possible memory allocation deadlock in %s (mode:0x%x)",
					__func__, lflags);
		congestion_wait(BLK_RW_ASYNC, HZ/50);
	} while (1);
}

void *
kmem_zone_zalloc(kmem_zone_t *zone, xfs_km_flags_t flags)
{
	void	*ptr;

	ptr = kmem_zone_alloc(zone, flags);
	if (ptr)
		memset((char *)ptr, 0, kmem_cache_size(zone));
	return ptr;
}
