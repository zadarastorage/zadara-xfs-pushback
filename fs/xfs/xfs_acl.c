/*
 * Copyright (c) 2008, Christoph Hellwig
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
#include "xfs.h"
#ifdef CONFIG_XFS_ZADARA
#include "xfs_sb.h"
#include "xfs_mount.h"
#endif /*CONFIG_XFS_ZADARA*/
#include "xfs_acl.h"
#include "xfs_attr.h"
#include "xfs_bmap_btree.h"
#include "xfs_inode.h"
#include "xfs_vnodeops.h"
#include "xfs_trace.h"
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>


/*
 * Locking scheme:
 *  - all ACL updates are protected by inode->i_mutex, which is taken before
 *    calling into this file.
 */

STATIC struct posix_acl *
xfs_acl_from_disk(struct xfs_acl *aclp)
{
	struct posix_acl_entry *acl_e;
	struct posix_acl *acl;
	struct xfs_acl_entry *ace;
	unsigned int count, i;

	count = be32_to_cpu(aclp->acl_cnt);
	if (count > XFS_ACL_MAX_ENTRIES)
		return ERR_PTR(-EFSCORRUPTED);

	acl = posix_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < count; i++) {
		acl_e = &acl->a_entries[i];
		ace = &aclp->acl_entry[i];

		/*
		 * The tag is 32 bits on disk and 16 bits in core.
		 *
		 * Because every access to it goes through the core
		 * format first this is not a problem.
		 */
		acl_e->e_tag = be32_to_cpu(ace->ae_tag);
		acl_e->e_perm = be16_to_cpu(ace->ae_perm);

		switch (acl_e->e_tag) {
		case ACL_USER:
		case ACL_GROUP:
			acl_e->e_id = be32_to_cpu(ace->ae_id);
			break;
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			acl_e->e_id = ACL_UNDEFINED_ID;
			break;
		default:
			goto fail;
		}
	}
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

STATIC void
xfs_acl_to_disk(struct xfs_acl *aclp, const struct posix_acl *acl)
{
	const struct posix_acl_entry *acl_e;
	struct xfs_acl_entry *ace;
	int i;

	aclp->acl_cnt = cpu_to_be32(acl->a_count);
	for (i = 0; i < acl->a_count; i++) {
		ace = &aclp->acl_entry[i];
		acl_e = &acl->a_entries[i];

		ace->ae_tag = cpu_to_be32(acl_e->e_tag);
		ace->ae_id = cpu_to_be32(acl_e->e_id);
		ace->ae_perm = cpu_to_be16(acl_e->e_perm);
	}
}

struct posix_acl *
xfs_get_acl(struct inode *inode, int type)
{
	struct xfs_inode *ip = XFS_I(inode);
	struct posix_acl *acl;
	struct xfs_acl *xfs_acl;
	int len = sizeof(struct xfs_acl);
	unsigned char *ea_name;
	int error;

	acl = get_cached_acl(inode, type);
	if (acl != ACL_NOT_CACHED)
		return acl;

	trace_xfs_get_acl(ip);

	switch (type) {
	case ACL_TYPE_ACCESS:
		ea_name = SGI_ACL_FILE;
		break;
	case ACL_TYPE_DEFAULT:
		ea_name = SGI_ACL_DEFAULT;
		break;
	default:
		BUG();
	}

	/*
	 * If we have a cached ACLs value just return it, not need to
	 * go out to the disk.
	 */

#ifdef CONFIG_XFS_ZADARA
	xfs_acl = vzalloc(sizeof(struct xfs_acl));
	if (!xfs_acl) {
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu vzalloc(sizeof(struct xfs_acl)(%lu)) failed", ip->i_ino, sizeof(struct xfs_acl));
		return ERR_PTR(-ENOMEM);
	}
#else /*CONFIG_XFS_ZADARA*/	
	xfs_acl = kzalloc(sizeof(struct xfs_acl), GFP_KERNEL);
	if (!xfs_acl)
		return ERR_PTR(-ENOMEM);
#endif /*CONFIG_XFS_ZADARA*/

	error = -xfs_attr_get(ip, ea_name, (unsigned char *)xfs_acl,
							&len, ATTR_ROOT);
	if (error) {
		/*
		 * If the attribute doesn't exist make sure we have a negative
		 * cache entry, for any other error assume it is transient and
		 * leave the cache entry as ACL_NOT_CACHED.
		 */
		if (error == -ENOATTR) {
			acl = NULL;
			goto out_update_cache;
		}
		goto out;
	}

	acl = xfs_acl_from_disk(xfs_acl);
	if (IS_ERR(acl))
		goto out;

 out_update_cache:
	set_cached_acl(inode, type, acl);
 out:
#ifdef CONFIG_XFS_ZADARA
	vfree(xfs_acl);
#else /*CONFIG_XFS_ZADARA*/
	kfree(xfs_acl);
#endif /*CONFIG_XFS_ZADARA*/
	return acl;
}

STATIC int
xfs_set_acl(struct inode *inode, int type, struct posix_acl *acl)
{
	struct xfs_inode *ip = XFS_I(inode);
	unsigned char *ea_name;
	int error;

#ifdef CONFIG_XFS_ZADARA
	ZXFSLOG_TAG(ip->i_mount, Z_KDEB1, ZKLOG_TAG_XATTR, "ino=%llu type=0x%x acl=%p", ip->i_ino, type, acl);
	if (S_ISLNK(inode->i_mode)) {
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu S_ISLNK => EOPNOTSUPP", ip->i_ino);
		return -EOPNOTSUPP;
	}
#else /*CONFIG_XFS_ZADARA*/	
	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
#endif /*CONFIG_XFS_ZADARA*/

	switch (type) {
	case ACL_TYPE_ACCESS:
		ea_name = SGI_ACL_FILE;
		break;
	case ACL_TYPE_DEFAULT:
#ifdef CONFIG_XFS_ZADARA
		if (!S_ISDIR(inode->i_mode)) {
			ZXFSLOG_TAG(ip->i_mount, Z_KWARN, ZKLOG_TAG_XATTR,"ino=%llu ACL_TYPE_DEFAULT !S_ISDIR ret=%d", ip->i_ino, acl ? -EACCES : 0);
			return acl ? -EACCES : 0;
		}
#else /*CONFIG_XFS_ZADARA*/
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
#endif /*CONFIG_XFS_ZADARA*/
		ea_name = SGI_ACL_DEFAULT;
		break;
	default:
#ifdef CONFIG_XFS_ZADARA		
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu unknown type=0x%x => EINVAL", ip->i_ino, type);
#endif /*CONFIG_XFS_ZADARA*/
		return -EINVAL;
	}

	if (acl) {
		struct xfs_acl *xfs_acl;
		int len;

#ifdef CONFIG_XFS_ZADARA
		xfs_acl = vzalloc(sizeof(struct xfs_acl));
		if (!xfs_acl) {
			ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu vzalloc(struct xfs_acl(%lu)) ENOMEM", ip->i_ino, sizeof(struct xfs_acl));
			return -ENOMEM;
		}
#else /*CONFIG_XFS_ZADARA*/
		xfs_acl = kzalloc(sizeof(struct xfs_acl), GFP_KERNEL);
		if (!xfs_acl)
			return -ENOMEM;
#endif /*CONFIG_XFS_ZADARA*/

		xfs_acl_to_disk(xfs_acl, acl);
		len = sizeof(struct xfs_acl) -
			(sizeof(struct xfs_acl_entry) *
			 (XFS_ACL_MAX_ENTRIES - acl->a_count));

		error = -xfs_attr_set(ip, ea_name, (unsigned char *)xfs_acl,
				len, ATTR_ROOT);

#ifdef CONFIG_XFS_ZADARA		
		ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_attr_set(ea_name=%s, len=%d) ret=%d", ip->i_ino, ea_name, len, error);
		vfree(xfs_acl);
#else /*CONFIG_XFS_ZADARA*/
		kfree(xfs_acl);
#endif /*CONFIG_XFS_ZADARA*/
	} else {
		/*
		 * A NULL ACL argument means we want to remove the ACL.
		 */
		error = -xfs_attr_remove(ip, ea_name, ATTR_ROOT);
#ifdef CONFIG_XFS_ZADARA
		ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_attr_remove(ea_name=%s) ret=%d", ip->i_ino, ea_name, error);
#endif /*CONFIG_XFS_ZADARA*/

		/*
		 * If the attribute didn't exist to start with that's fine.
		 */
		if (error == -ENOATTR)
			error = 0;
	}

	if (!error)
		set_cached_acl(inode, type, acl);
	return error;
}

static int
xfs_set_mode(struct inode *inode, umode_t mode)
{
	int error = 0;

	if (mode != inode->i_mode) {
		struct iattr iattr;

		iattr.ia_valid = ATTR_MODE | ATTR_CTIME;
		iattr.ia_mode = mode;
		iattr.ia_ctime = current_fs_time(inode->i_sb);

		error = -xfs_setattr_nonsize(XFS_I(inode), &iattr, XFS_ATTR_NOACL);
#ifdef CONFIG_XFS_ZADARA
		ZXFSLOG_TAG(XFS_I(inode)->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_setattr_nonsize(mode=0%o) ret=%d", XFS_I(inode)->i_ino, mode, error);
#endif /*CONFIG_XFS_ZADARA*/
	}

	return error;
}

static int
xfs_acl_exists(struct inode *inode, unsigned char *name)
{
	int len = sizeof(struct xfs_acl);

	return (xfs_attr_get(XFS_I(inode), name, NULL, &len,
			    ATTR_ROOT|ATTR_KERNOVAL) == 0);
}

int
posix_acl_access_exists(struct inode *inode)
{
	return xfs_acl_exists(inode, SGI_ACL_FILE);
}

int
posix_acl_default_exists(struct inode *inode)
{
	if (!S_ISDIR(inode->i_mode))
		return 0;
	return xfs_acl_exists(inode, SGI_ACL_DEFAULT);
}

/*
 * No need for i_mutex because the inode is not yet exposed to the VFS.
 */
int
xfs_inherit_acl(struct inode *inode, struct posix_acl *acl)
{
	umode_t mode = inode->i_mode;
	int error = 0, inherit = 0;
#ifdef CONFIG_XFS_ZADARA
	struct xfs_inode *ip = XFS_I(inode);
	ZXFSLOG_TAG(ip->i_mount, Z_KDEB1, ZKLOG_TAG_XATTR, "ino=%llu mode=0%o", ip->i_ino, inode->i_mode);
#endif /*CONFIG_XFS_ZADARA*/	

	if (S_ISDIR(inode->i_mode)) {
		error = xfs_set_acl(inode, ACL_TYPE_DEFAULT, acl);
#ifdef CONFIG_XFS_ZADARA		
		ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_set_acl(ACL_TYPE_DEFAULT) ret=%d", ip->i_ino, error);
#endif /*CONFIG_XFS_ZADARA*/
		if (error)
			goto out;
	}

	error = posix_acl_create(&acl, GFP_KERNEL, &mode);
#ifdef CONFIG_XFS_ZADARA
	ZXFSLOG_TAG(ip->i_mount, error >= 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu posix_acl_create() mode=0%o ret=%d", ip->i_ino, mode, error);
#endif /*CONFIG_XFS_ZADARA*/
	if (error < 0)
		return error;

	/*
	 * If posix_acl_create returns a positive value we need to
	 * inherit a permission that can't be represented using the Unix
	 * mode bits and we actually need to set an ACL.
	 */
	if (error > 0)
		inherit = 1;

	error = xfs_set_mode(inode, mode);
#ifdef CONFIG_XFS_ZADARA
	ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_set_mode(mode=0%o) ret=%d", ip->i_ino, mode, error);
#endif /*CONFIG_XFS_ZADARA*/
	if (error)
		goto out;

	if (inherit)
		error = xfs_set_acl(inode, ACL_TYPE_ACCESS, acl);
#ifdef CONFIG_XFS_ZADARA
	if (inherit)
		ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_set_acl(ACL_TYPE_ACCESS) ret=%d", ip->i_ino, error);
#endif /*CONFIG_XFS_ZADARA*/

out:
	posix_acl_release(acl);
	return error;
}

int
xfs_acl_chmod(struct inode *inode)
{
	struct posix_acl *acl;
	int error;

#ifdef CONFIG_XFS_ZADARA
	struct xfs_inode *ip = XFS_I(inode);
	if (S_ISLNK(inode->i_mode)) {
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu S_ISLNK(inode->i_mode=0%o) EOPNOTSUPP", ip->i_ino, inode->i_mode);
		return -EOPNOTSUPP;
	}
#else /*CONFIG_XFS_ZADARA*/
	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
#endif /*CONFIG_XFS_ZADARA*/

	acl = xfs_get_acl(inode, ACL_TYPE_ACCESS);
	if (IS_ERR(acl) || !acl)
		return PTR_ERR(acl);

	error = posix_acl_chmod(&acl, GFP_KERNEL, inode->i_mode);
#ifdef CONFIG_XFS_ZADARA
	ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu posix_acl_chmod(inode->i_mode=0%o) ret=%d", ip->i_ino, inode->i_mode, error);
#endif /*CONFIG_XFS_ZADARA*/
	if (error)
		return error;

	error = xfs_set_acl(inode, ACL_TYPE_ACCESS, acl);
#ifdef CONFIG_XFS_ZADARA
	ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_set_acl(ACL_TYPE_ACCESS) ret=%d", ip->i_ino, error);
#endif /*CONFIG_XFS_ZADARA*/
	posix_acl_release(acl);
	return error;
}

static int
xfs_xattr_acl_get(struct dentry *dentry, const char *name,
		void *value, size_t size, int type)
{
	struct posix_acl *acl;
	int error;

	acl = xfs_get_acl(dentry->d_inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;

	error = posix_acl_to_xattr(&init_user_ns, acl, value, size);
	posix_acl_release(acl);

	return error;
}

static int
xfs_xattr_acl_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	struct inode *inode = dentry->d_inode;
	struct posix_acl *acl = NULL;
	int error = 0;

#ifdef CONFIG_XFS_ZADARA	
	struct xfs_inode *ip = XFS_I(inode);
	ZXFSLOG_TAG(ip->i_mount, Z_KDEB1, ZKLOG_TAG_XATTR, "ino=%llu name=[%s] flags=0x%x type=0x%x val=[%.*s]", ip->i_ino, name, flags, type, min_t(int, size, 16), (const char*)(value ? value : "NULL"));
	if (flags & XATTR_CREATE) {
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu name=[%s] flags & XATTR_CREATE => -EINVAL", ip->i_ino, name);
		return -EINVAL;
	}
	if (type == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode)) {
		ZXFSLOG_TAG(ip->i_mount, Z_KWARN, ZKLOG_TAG_XATTR, "ino=%llu ACL_TYPE_DEFAULT !S_ISDIR ret=%d", ip->i_ino, value ? -EACCES : 0);
		return value ? -EACCES : 0;
	}
	if ((current_fsuid() != inode->i_uid) && !capable(CAP_FOWNER)) {
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu current_fsuid(%u)!=inode->i_uid(%u) && !capable(CAP_FOWNER) => -EPERM", ip->i_ino, current_fsuid(), inode->i_uid);
		return -EPERM;
	}
#else /*CONFIG_XFS_ZADARA*/
	if (flags & XATTR_CREATE)
		return -EINVAL;
	if (type == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode))
		return value ? -EACCES : 0;
	if ((current_fsuid() != inode->i_uid) && !capable(CAP_FOWNER))
		return -EPERM;
#endif /*CONFIG_XFS_ZADARA*/

	if (!value)
		goto set_acl;

	acl = posix_acl_from_xattr(&init_user_ns, value, size);
	if (!acl) {
		/*
		 * acl_set_file(3) may request that we set default ACLs with
		 * zero length -- defend (gracefully) against that here.
		 */
#ifdef CONFIG_XFS_ZADARA
		ZXFSLOG_TAG(ip->i_mount, Z_KWARN, ZKLOG_TAG_XATTR, "ino=%llu posix_acl_from_xattr() ret=NULL", ip->i_ino);
#endif /*CONFIG_XFS_ZADARA*/
		goto out;
	}
	if (IS_ERR(acl)) {
		error = PTR_ERR(acl);
#ifdef CONFIG_XFS_ZADARA
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu posix_acl_from_xattr() ret=%d", ip->i_ino, error);
#endif /*CONFIG_XFS_ZADARA*/
		goto out;
	}

	error = posix_acl_valid(acl);
#ifdef CONFIG_XFS_ZADARA
	if (error) {
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu posix_acl_valid() ret=%d", ip->i_ino, error);
		goto out_release;
	}
#else /*CONFIG_XFS_ZADARA*/
	if (error)
		goto out_release;
#endif /*CONFIG_XFS_ZADARA*/

	error = -EINVAL;
#ifdef CONFIG_XFS_ZADARA
	if (acl->a_count > XFS_ACL_MAX_ENTRIES) {
		ZXFSLOG_TAG(ip->i_mount, Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu acl->a_count(%u) > XFS_ACL_MAX_ENTRIES(%u)", ip->i_ino, acl->a_count, XFS_ACL_MAX_ENTRIES);
		goto out_release;
	}
#else /*CONFIG_XFS_ZADARA*/
	if (acl->a_count > XFS_ACL_MAX_ENTRIES)
		goto out_release;
#endif /*CONFIG_XFS_ZADARA*/

	if (type == ACL_TYPE_ACCESS) {
		umode_t mode = inode->i_mode;
		error = posix_acl_equiv_mode(acl, &mode);

		if (error <= 0) {
			posix_acl_release(acl);
#ifdef CONFIG_XFS_ZADARA			
			ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu posix_acl_equiv_mode() mode=0%o ret=%d", ip->i_ino, mode, error);
#endif /*CONFIG_XFS_ZADARA*/
			acl = NULL;

			if (error < 0)
				return error;
		}

		error = xfs_set_mode(inode, mode);
#ifdef CONFIG_XFS_ZADARA
		ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_set_mode(mode=0%o) ret=%d", ip->i_ino, mode, error);
#endif /*CONFIG_XFS_ZADARA*/
		if (error)
			goto out_release;
	}

 set_acl:
	error = xfs_set_acl(inode, type, acl);
#ifdef CONFIG_XFS_ZADARA
	ZXFSLOG_TAG(ip->i_mount, error == 0 ? Z_KDEB1 : Z_KERR, ZKLOG_TAG_XATTR, "ino=%llu xfs_set_acl(type=0x%x) ret=%d", ip->i_ino, type, error);
#endif /*CONFIG_XFS_ZADARA*/
 out_release:
	posix_acl_release(acl);
 out:
	return error;
}

const struct xattr_handler xfs_xattr_acl_access_handler = {
	.prefix	= POSIX_ACL_XATTR_ACCESS,
	.flags	= ACL_TYPE_ACCESS,
	.get	= xfs_xattr_acl_get,
	.set	= xfs_xattr_acl_set,
};

const struct xattr_handler xfs_xattr_acl_default_handler = {
	.prefix	= POSIX_ACL_XATTR_DEFAULT,
	.flags	= ACL_TYPE_DEFAULT,
	.get	= xfs_xattr_acl_get,
	.set	= xfs_xattr_acl_set,
};
