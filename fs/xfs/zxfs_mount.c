/*
 * This file is meant to be included directly from fs/xfs/xfs_mount.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

/* See https://bugzilla.kernel.org/show_bug.cgi?id=48651 */
void xfs_uuid_table_free(void)
{
	mutex_lock(&xfs_uuid_table_mutex);
	if (xfs_uuid_table) {
		kmem_free(xfs_uuid_table);
		xfs_uuid_table = NULL;
	}
	mutex_unlock(&xfs_uuid_table_mutex);
}

