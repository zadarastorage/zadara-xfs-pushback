/*
 * Copyright (c) 2001-2005 Silicon Graphics, Inc.
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
#ifndef __XFS_ACL_H__
#define __XFS_ACL_H__

struct inode;
struct posix_acl;
struct xfs_inode;

#define XFS_ACL_NOT_PRESENT (-1)

/* On-disk XFS access control list structure */
struct xfs_acl_entry {
	__be32	ae_tag;
	__be32	ae_id;
	__be16	ae_perm;
	__be16	ae_pad;		/* fill the implicit hole in the structure */
};

struct xfs_acl {
	__be32			acl_cnt;
	struct xfs_acl_entry	acl_entry[0];
};

/*
 * The number of ACL entries allowed is defined by the on-disk format.
 * For v4 superblocks, that is limited to 25 entries. For v5 superblocks, it is
 * limited only by the maximum size of the xattr that stores the information.
 */
#ifndef CONFIG_XFS_ZADARA
#define XFS_ACL_MAX_ENTRIES(mp)	\
		(xfs_sb_version_hascrc(&mp->m_sb) \
			?  (XATTR_SIZE_MAX - sizeof(struct xfs_acl)) / \
							sizeof(struct xfs_acl_entry) \
		: 25)
#else /*CONFIG_XFS_ZADARA*/
#define XFS_ACL_MAX_ENTRIES(mp)	\
		(xfs_sb_version_hascrc(&mp->m_sb) \
			?  (XATTR_SIZE_MAX - sizeof(struct xfs_acl)) / \
							sizeof(struct xfs_acl_entry) \
		: 2048)
#endif /*CONFIG_XFS_ZADARA*/

#define XFS_ACL_MAX_SIZE(mp) \
	(sizeof(struct xfs_acl) + \
		sizeof(struct xfs_acl_entry) * XFS_ACL_MAX_ENTRIES((mp)))

/* On-disk XFS extended attribute names */
#define SGI_ACL_FILE		(unsigned char *)"SGI_ACL_FILE"
#define SGI_ACL_DEFAULT		(unsigned char *)"SGI_ACL_DEFAULT"
#define SGI_ACL_FILE_SIZE	(sizeof(SGI_ACL_FILE)-1)
#define SGI_ACL_DEFAULT_SIZE	(sizeof(SGI_ACL_DEFAULT)-1)

#ifdef CONFIG_XFS_POSIX_ACL
extern struct posix_acl *xfs_get_acl(struct inode *inode, int type);
extern int xfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int posix_acl_access_exists(struct inode *inode);
extern int posix_acl_default_exists(struct inode *inode);
#else
static inline struct posix_acl *xfs_get_acl(struct inode *inode, int type)
{
	return NULL;
}
# define xfs_set_acl					NULL
# define posix_acl_access_exists(inode)			0
# define posix_acl_default_exists(inode)		0
#endif /* CONFIG_XFS_POSIX_ACL */
#endif	/* __XFS_ACL_H__ */
