/*
 * Misc Zadara stuff.
 * This file is meant to be included directly from fs/btrfs/ctree.c
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 * If Zadara changes are ever accepted by the community, the contents of this file
 * will move into ctree.c and this file will disappear.
 */

static /*const*/ struct btrfs_key s_key_tree_end_reached = {
	.objectid = (u64)-1, 
	.type	  = (u8)-1,
	.offset   = (u64)-1
};

/*
 * Checks whether the specified key says "tree end reached".
 */
bool btrfs_compare_trees_key_tree_end_reached(struct btrfs_key *key)
{
	return btrfs_comp_cpu_keys(key, &s_key_tree_end_reached) == 0 ? true : false;
}

/*
 * Generate a tree comparison checkpoint, suitable for being sent over network,
 * written to disk etc.
 * Returns the same 'cp' pointer that was passed.
 */
struct btrfs_compare_trees_checkpoint* 
btrfs_compare_trees_gen_checkpoint(struct btrfs_compare_trees_checkpoint *cp,
							 const struct btrfs_key *left_key, int left_end_reached,
							 const struct btrfs_key *right_key, int right_end_reached)
{
	if (left_end_reached) {
		cp->left_key__objectid = cpu_to_le64(s_key_tree_end_reached.objectid);
		cp->left_key__type     = s_key_tree_end_reached.type;
		cp->left_key__offset   = cpu_to_le64(s_key_tree_end_reached.offset);
	} else {
		cp->left_key__objectid = cpu_to_le64(left_key->objectid);
		cp->left_key__type     = left_key->type;
		cp->left_key__offset   = cpu_to_le64(left_key->offset);
	}

	if (right_end_reached) {
		cp->right_key__objectid = cpu_to_le64(s_key_tree_end_reached.objectid);
		cp->right_key__type	    = s_key_tree_end_reached.type;
		cp->right_key__offset   = cpu_to_le64(s_key_tree_end_reached.offset);
	} else {
		cp->right_key__objectid = cpu_to_le64(right_key->objectid);
		cp->right_key__type	    = right_key->type;
		cp->right_key__offset   = cpu_to_le64(right_key->offset);
	}

	return cp;
}

static int btrfs_compare_trees_rearm_to_tree_end(struct btrfs_root *root,
	/* Output goes here */
	struct btrfs_path *path,
	struct btrfs_key *key, int *level, int *end_reached)
{
	int ret = 0;
	struct btrfs_key search_key = s_key_tree_end_reached;

	ret = btrfs_search_slot(NULL, root, &search_key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret > 0) {
		*key = s_key_tree_end_reached;                  /* doesn't really matter in this case */
		*level = btrfs_header_level(root->commit_root); /* doesn't really matter in this case */
		*end_reached = ADVANCE;
		ret = 0;
	} else {
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_TR_COMP, "Tree[%llu]: btrfs_search_slot(tree_end) failed, ret=%d", root->objectid, ret);
		ret = -EILSEQ;
	}

	return ret;
}

static int btrfs_compare_trees_rearm_to_item(struct btrfs_root *root, struct btrfs_key *rearm_key,
	/* Output goes here */
	struct btrfs_path *path,
	struct btrfs_key *key, int *level, int *end_reached)
{
	int ret = 0;
	struct btrfs_key search_key = *rearm_key;

	ret = btrfs_search_slot(NULL, root, &search_key, path, 0/*ins_len*/, 0/*cow*/);
	if (ret != 0) {
		/* We should be able to find the key */
		ZBTRFSLOG_TAG(root->fs_info, Z_KERR, ZKLOG_TAG_TR_COMP, "Tree[%llu]: btrfs_search_slot(%llu,%s,%llu) failed, ret=%d",
		              root->objectid,
		              rearm_key->objectid, btrfs_fs_key_type_to_str(rearm_key->type), rearm_key->offset,
		              ret);
		ret = -EILSEQ;
	} else {
		*key = *rearm_key;
		*level = 0; /* We found the item, so we're on level 0 */
		*end_reached = 0;
	}

	return ret;
}

/*
 * Rearms the checkpoint for the tree comparison process.
 * Must be called under commit_root_sem read-locked and 
 * paths should be configured as searching through commit roots.
 */
int btrfs_compare_trees_rearm_cp(const struct btrfs_compare_trees_checkpoint *cp,
	struct btrfs_root *left_root, struct btrfs_root *right_root,
	/* Output goes here */
	struct btrfs_path *left_path, struct btrfs_path *right_path,
	struct btrfs_key *left_key, int *left_level, int *left_end_reached,
	struct btrfs_key *right_key, int *right_level, int *right_end_reached)
{
	int ret = 0;
	struct btrfs_key rearm_key;

	if (ZBTRFS_WARN_ON(!rwsem_is_locked(&left_root->fs_info->commit_root_sem)))
		return -ECANCELED;
	if (ZBTRFS_WARN_ON(left_path->search_commit_root == 0))
		return -ECANCELED;
	if (ZBTRFS_WARN_ON(right_path->search_commit_root == 0))
		return -ECANCELED;

	/* rearm left tree */
	rearm_key.objectid = le64_to_cpu(cp->left_key__objectid);
	rearm_key.type     = cp->left_key__type;
	rearm_key.offset   = le64_to_cpu(cp->left_key__offset);
	if (btrfs_comp_cpu_keys(&rearm_key, &s_key_tree_end_reached) == 0) {
		ZBTRFSLOG_TAG(left_root->fs_info, Z_KDEB1, ZKLOG_TAG_TR_COMP, "L[%llu] - rearm to tree end", left_root->objectid);
		ret = btrfs_compare_trees_rearm_to_tree_end(left_root,
				/* output */
				left_path,
				left_key, left_level, left_end_reached);
	} else {
		ZBTRFSLOG_TAG(left_root->fs_info, Z_KDEB1, ZKLOG_TAG_TR_COMP, "L[%llu] - rearm to (%llu,%s,%llu)", left_root->objectid,
			          rearm_key.objectid, btrfs_fs_key_type_to_str(rearm_key.type), rearm_key.offset);
		ret = btrfs_compare_trees_rearm_to_item(left_root, &rearm_key,
				/* output */
				left_path,
				left_key, left_level, left_end_reached);
	}
	if (ret != 0)
		goto out;

	/* rearm right tree */
	rearm_key.objectid = le64_to_cpu(cp->right_key__objectid);
	rearm_key.type	   = cp->right_key__type;
	rearm_key.offset   = le64_to_cpu(cp->right_key__offset);
	if (btrfs_comp_cpu_keys(&rearm_key, &s_key_tree_end_reached) == 0) {
		ZBTRFSLOG_TAG(right_root->fs_info, Z_KDEB1, ZKLOG_TAG_TR_COMP, "R[%llu] - rearm to tree end", right_root->objectid);
		ret = btrfs_compare_trees_rearm_to_tree_end(right_root,
				/* output */
				right_path,
				right_key, right_level, right_end_reached);
	} else {
		ZBTRFSLOG_TAG(right_root->fs_info, Z_KDEB1, ZKLOG_TAG_TR_COMP, "R[%llu] - rearm to (%llu,%s,%llu)", right_root->objectid,
			          rearm_key.objectid, btrfs_fs_key_type_to_str(rearm_key.type), rearm_key.offset);
		ret = btrfs_compare_trees_rearm_to_item(right_root, &rearm_key,
				/* output */
				right_path,
				right_key, right_level, right_end_reached);
	}

out:
	return ret;
}

const char *btrfs_trans_type_to_str(unsigned int type)
{
	const char *res = "???";
	switch (type) {
		case TRANS_USERSPACE:
			res = "USER";
			break;
		case TRANS_START:
			res = "START";
			break;
		case TRANS_ATTACH:
			res = "ATTACH";
			break;
		case TRANS_JOIN:
			res = "JOIN";
			break;
		case TRANS_JOIN_NOLOCK:
			res = "JOIN_NOLOCK";
			break;
		default:
			break;
	}
	return res;
}

