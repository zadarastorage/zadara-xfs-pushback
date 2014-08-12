/*
 * This file is meant to be included directly from fs/xfs/xfs_trans.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

void
zxfs_trans_free(struct xfs_trans * tp)
{
	xfs_trans_free(tp);
}

