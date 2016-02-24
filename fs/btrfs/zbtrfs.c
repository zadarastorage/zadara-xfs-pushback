#ifdef CONFIG_BTRFS_ZADARA
#include <linux/module.h>
#include <linux/dm-kcopyd.h>
#include <linux/poll.h>
#include <linux/kthread.h>
#include "ctree.h"
#include "volumes.h"
#include "transaction.h"
#include "zjournal.h"

/*********** globals ******************************/
struct zbtrfs_globals_t zbtrfs_globals;

/*********** zklog *******************************/
struct zklog_module_ctx *ZKLOG_THIS_MODULE_CTX = NULL;
zklog_tag_t ZKLOG_TAG_TR_COMP = 0;
zklog_tag_t ZKLOG_TAG_SR = 0;
zklog_tag_t ZKLOG_TAG_CHCKP = 0;
zklog_tag_t ZKLOG_TAG_BLKVIRT = 0;
zklog_tag_t ZKLOG_TAG_SUBVOL_CRE = 0;
zklog_tag_t ZKLOG_TAG_SUBVOL_DEL = 0;
zklog_tag_t ZKLOG_TAG_SPACE_USAGE = 0;
zklog_tag_t ZKLOG_TAG_TXN = 0;
zklog_tag_t ZKLOG_TAG_CHUNK_ALLOC = 0;
zklog_tag_t ZKLOG_TAG_SPACE_CACHING = 0;
zklog_tag_t ZKLOG_TAG_EXTENT_ALLOC = 0;
zklog_tag_t ZKLOG_TAG_FREE_SP_CACHE = 0;
zklog_tag_t ZKLOG_TAG_RESIZE = 0;
zklog_tag_t ZKLOG_TAG_DINODE = 0;
zklog_tag_t ZKLOG_TAG_ZTENANT = 0;
zklog_tag_t ZKLOG_TAG_DREF = 0;
zklog_tag_t ZKLOG_TAG_CH_CHUNKS = 0;

/****** transactions-related stuff **********************/

void zbtrfs_trans_committed(struct btrfs_fs_info *fs_info, struct btrfs_transaction *cur_trans)
{
	u64 corrupted_transid = 0;

	/* maybe we somehow managed to commit on a corrupted tree...*/
	corrupted_transid = atomic64_read(&fs_info->zfs_info.corrupted_tree_transid);
	if (corrupted_transid == cur_trans->transid)
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "corrupted trans[%llu] successfully committed!!!", cur_trans->transid);

	if (fs_info->zfs_info.pool_id != 0) {
		int jrn_rc;
		jrn_rc = zjournal_commit(fs_info->zfs_info.pool_id, cur_trans->transid);
		BUG_ON(jrn_rc!=0);
	}

	zbtrfs_subvol_deletion_committed(fs_info, cur_trans);
}

/* This follows __btrfs_abort_transaction; make sure to keep it in sync */
void __zbtrfs_force_abort_transaction(struct btrfs_trans_handle *trans,
		struct btrfs_root *root, const char *function,
		unsigned int line, int errno)
{
	/* Mark first abort since mount */
	test_and_set_bit(BTRFS_FS_STATE_TRANS_ABORTED, &root->fs_info->fs_state);

	if (trans) {
		ZBTRFSLOG(root->fs_info, Z_KERR, "trans[%llu] force-aborted", trans->transid);
		trans->aborted = errno;
	} else {
		ZBTRFSLOG(root->fs_info, Z_KERR, "no ongoing trans, just mark ERROR");
	}

	if (trans) {
		ACCESS_ONCE(trans->transaction->aborted) = errno;
		/* Wake up anybody who may be waiting on this transaction */
		wake_up(&root->fs_info->transaction_wait);
		wake_up(&root->fs_info->transaction_blocked_wait);
	}

	/* call this in any case */
	__btrfs_std_error(root->fs_info, function, line, errno, NULL);
}

int zbtrfs_assert_no_delayed_refs(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans)
{
	int ret = 0;
	struct btrfs_delayed_ref_root *delayed_refs = &curr_trans->delayed_refs;

	spin_lock(&delayed_refs->lock);
	if (rb_first(&delayed_refs->href_root) != NULL) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_TXN, "txn[%llu]: href_root is not empty [ne=%d nh=%lu nhr=%lu]",
		              curr_trans->transid,
		              atomic_read(&delayed_refs->num_entries), delayed_refs->num_heads, delayed_refs->num_heads_ready);
		ret = -EEXIST;
	} else if (atomic_read(&delayed_refs->num_entries) > 0 || delayed_refs->num_heads > 0 || delayed_refs->num_heads_ready > 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "txn[%llu]: href_root empty but [ne=%d nh=%lu nhr=%lu]",
		              curr_trans->transid,
		              atomic_read(&delayed_refs->num_entries), delayed_refs->num_heads, delayed_refs->num_heads_ready);
	}
	spin_unlock(&delayed_refs->lock);

	return ret;
}

/****** snapshot deletion tracking stuff *******************/

/*
 * Called when a root for deletion is removed from the dead_roots list,
 * still under trans_lock.
 */
void zbtrfs_set_deleting_subvol(struct btrfs_fs_info *fs_info, struct btrfs_root *root)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	
	ZBTRFS_WARN_ON(zfs_info->curr_deleting_subvol_objectid != 0 || zfs_info->curr_deleting_subvol_otransid != 0);
	zfs_info->curr_deleting_subvol_objectid = root->objectid;
	zfs_info->curr_deleting_subvol_otransid = btrfs_root_otransid(&root->root_item);
}

/*
 * Currently-deleting subvolume will be committed as "deleted"
 * in the specified transaction. However, the specified transaction 
 * has not committed yet, and it may also be aborted.
 */
int zbtrfs_subvol_deletion_will_commit(struct btrfs_fs_info *fs_info, struct btrfs_trans_handle* trans)
{
	int ret = 0;
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	struct zbtrfs_deleted_subvol_info *subv_info = NULL;

	if (ZBTRFS_WARN_ON(zfs_info->curr_deleting_subvol_objectid == 0 || zfs_info->curr_deleting_subvol_otransid == 0))
		goto out;

	/* 
	 * if this is a non-block-virt mount, don't bother, because VAC will
	 * not be monitoring us.
	 */
	if (unlikely(!ZBTRFS_IS_FULL_BLKVIRT_MOUNT(fs_info)))
		goto out;

	subv_info = kmem_cache_zalloc(zbtrfs_globals.deleted_subvol_cachep, GFP_NOFS);
	if (unlikely(subv_info == NULL)) {
		ZBTRFSLOG_TAG(fs_info, Z_KERR, ZKLOG_TAG_SUBVOL_DEL, "failed allocating zbtrfs_deleted_subvol_info for root=%llu",
			          zfs_info->curr_deleting_subvol_objectid);
		ret = -ENOMEM;
		goto out;
	}

	subv_info->root_objectid      = zfs_info->curr_deleting_subvol_objectid;
	subv_info->otransid           = zfs_info->curr_deleting_subvol_otransid;
	subv_info->deletion_transid   = trans->transid;
	ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "root(%llu,%llu) deletion will commint in txn[%llu]",
		          subv_info->root_objectid, subv_info->otransid, subv_info->deletion_transid);

	spin_lock(&zfs_info->deleted_subvols_lock);
	/* list is sorted in ascending transid */
	list_add_tail(&subv_info->deleted_subvols_link, &zfs_info->deleted_subvols);
	spin_unlock(&zfs_info->deleted_subvols_lock);

out:
	return ret;
}

void zbtrfs_reset_deleting_subvol(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;

	zfs_info->curr_deleting_subvol_objectid = 0;
	zfs_info->curr_deleting_subvol_otransid = 0;
}

void zbtrfs_subvol_deletion_committed(struct btrfs_fs_info *fs_info, struct btrfs_transaction *cur_trans)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	bool wakeup = false;

	/* check if have some deletions that are now final, and notify VAC */

	spin_lock(&zfs_info->deleted_subvols_lock);
	
	if (!list_empty(&zfs_info->deleted_subvols)) {
		struct zbtrfs_deleted_subvol_info *subv_info = list_first_entry(
						&zfs_info->deleted_subvols, 
						struct zbtrfs_deleted_subvol_info,
						deleted_subvols_link);
		/* list is sorted in ascending transid */
		if (subv_info->deletion_transid <= cur_trans->transid)
			wakeup = true;
	}
	
	spin_unlock(&zfs_info->deleted_subvols_lock);

	if (wakeup)
		zbtrfs_control_poll_wake_up(fs_info, POLLIN);
}

void zbtrfs_subvol_deletion_list_free(struct btrfs_fs_info *fs_info, struct list_head *deleted_subvols)
{
	struct zbtrfs_deleted_subvol_info *subv_info = NULL, *tmp = NULL;
	
	list_for_each_entry_safe(subv_info, tmp, deleted_subvols, deleted_subvols_link) {
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL,
			      "freeing deleted root(%llu,%llu) txn[%llu]",
			      subv_info->root_objectid, subv_info->otransid, subv_info->deletion_transid);
		list_del_init(&subv_info->deleted_subvols_link);
		kmem_cache_free(zbtrfs_globals.deleted_subvol_cachep, subv_info);
	}
}

void zbtrfs_fetch_committed_deleted_subvols(struct btrfs_fs_info *fs_info, u32 max_subvols_to_fetch,
	                 struct list_head *out_list, bool *have_more)
{
	u64 last_transid = fs_info->last_trans_committed;
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	struct zbtrfs_deleted_subvol_info *subv_info = NULL, *tmp = NULL;
	u32 n_fetched = 0;

	*have_more = false;

	spin_lock(&zfs_info->deleted_subvols_lock);

	list_for_each_entry_safe(subv_info, tmp, &zfs_info->deleted_subvols, deleted_subvols_link) {
		/* not committed yet */
		if (subv_info->deletion_transid > last_transid)
			break;

		/* we cannot fetch more, but let's notify VAC to call us again */
		if (n_fetched >= max_subvols_to_fetch) {
			*have_more = true;
			break;
		}

		list_del_init(&subv_info->deleted_subvols_link);
		list_add_tail(&subv_info->deleted_subvols_link, out_list);
		++n_fetched;
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_SUBVOL_DEL, "fetching committed deleted root(%llu,%llu)",
			          subv_info->root_objectid, subv_info->otransid);
	}

	spin_unlock(&zfs_info->deleted_subvols_lock);
}

bool zbtrfs_have_deleted_subvol(struct btrfs_fs_info *fs_info, u64 root_objectid, u64 otransid)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	struct zbtrfs_deleted_subvol_info *subv_info = NULL;
	bool have = false;

	spin_lock(&zfs_info->deleted_subvols_lock);

	list_for_each_entry(subv_info, &zfs_info->deleted_subvols, deleted_subvols_link) {
		if (subv_info->root_objectid == root_objectid &&
			subv_info->otransid == otransid) {
			have = true;
			break;
		}
	}

	spin_unlock(&zfs_info->deleted_subvols_lock);

	return have;
}

/****** misc stuff ****************************************/

void __zbtrfs_tree_corruption(struct btrfs_fs_info *fs_info, const char *file, const char *func, unsigned int line)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	u64 curr_transid = 0;
	u64 prev_corrupted_transid = 0;
	bool had_running_trans = false;

	spin_lock(&fs_info->trans_lock);
	prev_corrupted_transid = atomic64_read(&zfs_info->corrupted_tree_transid);
	if (fs_info->running_transaction) {
		atomic64_set(&zfs_info->corrupted_tree_transid, fs_info->running_transaction->transid);
		curr_transid = fs_info->running_transaction->transid;
		had_running_trans = true;
	} else {
		/* 
		 * there is no running transaction, but we detected a tree corruption.
		 * set a fake transid (1) if we don't already have something larger there.
		 * note that mkfs.btrfs performs several "transactions" while btrfs is still
		 * unmounted, so even on a fresh btrfs, transactions will not start from 1.
		 */
		if (prev_corrupted_transid == 0)
			atomic64_set(&zfs_info->corrupted_tree_transid, 1);
		curr_transid = 1;
	}
	spin_unlock(&fs_info->trans_lock);

	if (had_running_trans) {
		ZBTRFS_WARN(1, "FS[%s]: tree corruption trans[%llu] in %s:%s:%u",
			           fs_info->sb ? fs_info->sb->s_id : "---",
			           curr_transid, file, func, line);
	} else {
		ZBTRFS_WARN(1, "FS[%s]: tree corruption outside of transaction(have=%llu) in %s:%s:%u",
			           fs_info->sb ? fs_info->sb->s_id : "---",
			           (u64)atomic64_read(&fs_info->zfs_info.corrupted_tree_transid),
			           file, func, line);
	}

	/* if this is the first time we detect a corruption since mount, notify VAC */
	if (prev_corrupted_transid == 0)
		zbtrfs_control_poll_wake_up(fs_info, POLLERR);
}

void __zbtrfs_log_io_error(struct btrfs_fs_info *fs_info, struct block_device *bdev, struct bio *bio, int error,
	                       const char *file, const char *func, unsigned int line)
{
	static DEFINE_RATELIMIT_STATE(rs,
				      DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	if (__ratelimit(&rs)) {
		char bdev_name[BDEVNAME_SIZE] = {'\0'};
		const char *bio_kind = NULL;
		u32 bio_len_bytes = 0;
		struct bio_vec *bvec = NULL;
		u32 bvec_idx = 0;

		if ((bio->bi_rw & WRITE_FLUSH) == WRITE_FLUSH)
			bio_kind = "FLUSH";
		else if (bio->bi_rw & WRITE)
			bio_kind = "WRITE";
		else
			bio_kind = "READ";

		bio_for_each_segment_all(bvec, bio, bvec_idx) {
			bio_len_bytes += bvec->bv_len;
		}

		__zklog_print_default_tag(ZKLOG_THIS_MODULE_CTX, Z_KERR, 
			                      file, func, line,
			                      "FS[%s]: bdev(%s) %s[%lu:%u(%u b)] err=%d",
			                      fs_info ? fs_info->sb->s_id : "--",
			                      bdev ? bdevname(bdev, bdev_name) : "???",
			                      bio_kind, bio->bi_iter.bi_sector/*most probably this will not be correct*/, 
			                      BYTES_TO_BLK(bio_len_bytes), bio_len_bytes,
			                      error);
	}
}

void zbtrfs_notify_fs_error(struct btrfs_fs_info *fs_info)
{
	ZBTRFS_WARN(1, "FS[%s] ERROR!!!", fs_info->sb->s_id);
	zbtrfs_control_poll_wake_up(fs_info, POLLERR);
}

/********** per-FS init/exit ************************/

void zbtrfs_wait_for_journal_replay(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	bool thr_should_stop = false;

	/* don't wait if journal is not operational */
	if (zfs_info->pool_id == 0)
		return;

	ZBTRFSLOG(fs_info, Z_KINFO, "%.*s - wait for replay", TASK_COMM_LEN, current->comm);
	while (!(zfs_info->replay_completed ||
		   (thr_should_stop=kthread_should_stop()))) {
		/* 
		 * wait with timeout, to avoid false "hung" warnings, 
		 * when journal replay takes too long 
		 */
		wait_event_timeout(zfs_info->replay_completed_wait, 
			               zfs_info->replay_completed || 
			               (thr_should_stop=kthread_should_stop()),
			               30*HZ);
	}
	if (thr_should_stop)
		ZBTRFSLOG(fs_info, Z_KWARN, "%.*s - thread_should_stop", TASK_COMM_LEN, current->comm);
	else
		ZBTRFSLOG(fs_info, Z_KINFO, "%.*s - replay completed", TASK_COMM_LEN, current->comm);
}

/*
 * Called as soon as struct btrfs_fs_info has been allocated.
 * This function doesn't fail.
 * After this function returns, it is guaranteed that zbtrfs_fs_info_fini()
 * will be called.
 * It can be assumed that fs_info memory is zeroed.
 * @param mount_dev_name device on which btrfs is being mounted - needed only for prints
 */
void zbtrfs_fs_info_init(struct btrfs_fs_info *fs_info, const char *mount_dev_name)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;

	zklog(Z_KINFO, "btrfs_mount[%s] INIT", mount_dev_name);

	zbtrfs_zstats_init(fs_info);

	zbtrfs_sysfs_init(fs_info);

	zbtrfs_control_init(fs_info);

	zfs_info->pool_data_devpath[0] = '\0';
	zfs_info->pool_data_bdev = NULL;
	zfs_info->pool_gran_bytes = 0;
	zfs_info->pool_id = 0;

	atomic64_set(&zfs_info->corrupted_tree_transid, 0);
	init_waitqueue_head(&zfs_info->replay_completed_wait);
	zfs_info->replay_completed = false;
	zfs_info->report_zjournal_corruption = false;

	atomic_set(&zfs_info->data_block_groups_to_warmup, 0);
	atomic_set(&zfs_info->metadata_block_groups_to_warmup, 0);
	atomic_set(&zfs_info->system_block_groups_to_warmup, 0);

	zfs_info->curr_deleting_subvol_objectid = 0;
	zfs_info->curr_deleting_subvol_otransid = 0;
	INIT_LIST_HEAD(&zfs_info->deleted_subvols);
	spin_lock_init(&zfs_info->deleted_subvols_lock);
}

/*
 * Called early enough so that FS is not fully functional yet,
 * but not too early, such that FS knows stuff about itself,
 * like FSID, mount options were parsed etc.
 */
int zbtrfs_fs_info_start1(struct btrfs_fs_info *fs_info, u64 latest_trans_before_mount)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	int ret = 0;

	ZBTRFSLOG(fs_info, Z_KINFO, "START1%s", (fs_info->sb->s_flags & MS_RDONLY) ?  " MS_RDONLY" : "");

	/* FSID must be valid at this point */
	if (btrfs_is_empty_uuid(fs_info->fsid)) {
		ZBTRFSLOG(fs_info, Z_KERR, "FSID is zeros");
		return -EINVAL;
	}

	/* open the pool data device, if it was specified */
	if (zfs_info->pool_data_devpath[0] != '\0') {
		char bname[BDEVNAME_SIZE] = {'\0'};

		/*
		 * note that fs_info->bdev_holder is already initialized here,
		 * although it is not used when FMODE_EXCL is not set
		 */
		zfs_info->pool_data_bdev = blkdev_get_by_path(zfs_info->pool_data_devpath, FMODE_READ|FMODE_WRITE, fs_info->bdev_holder);
		if (IS_ERR(zfs_info->pool_data_bdev)) {
			ret = PTR_ERR(zfs_info->pool_data_bdev);
			ZBTRFSLOG(fs_info, Z_KERR, "blkdev_get_by_path(%s) failed, ret=%d", zfs_info->pool_data_devpath, ret);
			zfs_info->pool_data_bdev = NULL;
			return ret;
		}

		ZBTRFSLOG(fs_info, Z_KINFO, "Opened bdev[%s] at path=%s", bdevname(zfs_info->pool_data_bdev, bname), zfs_info->pool_data_devpath);
	}

	ret = zbtrfs_control_start(fs_info);
	if (unlikely(ret!=0))
		return ret;

	/* if granularity was supplied, check that it's valid */
	if (zfs_info->pool_gran_bytes > 0) {
		/* btrfs cannot allocate less than a page */
		if (zfs_info->pool_gran_bytes < PAGE_CACHE_SIZE ||
			 /* must be power of 2 */
			((zfs_info->pool_gran_bytes - 1) & zfs_info->pool_gran_bytes) != 0 ||
			/* if lower than BTRFS_STRIPE_LEN, should divide nicely */
			(zfs_info->pool_gran_bytes < BTRFS_STRIPE_LEN && BTRFS_STRIPE_LEN % zfs_info->pool_gran_bytes != 0) ||
			/* if higher than BTRFS_STRIPE_LEN, then should be aligned by it */
			(zfs_info->pool_gran_bytes >= BTRFS_STRIPE_LEN && zfs_info->pool_gran_bytes % BTRFS_STRIPE_LEN != 0)) {
			ZBTRFSLOG(fs_info, Z_KERR, "pool_gran_bytes=%u invalid (BTRFS_STRIPE_LEN=%u)", zfs_info->pool_gran_bytes, BTRFS_STRIPE_LEN);
			return -EINVAL;
		}
	}

	/* on read-only mount, we don't mount the journal */
	if (zfs_info->pool_id != 0 && !(fs_info->sb->s_flags & MS_RDONLY)) {
		ret = zjournal_mount(zfs_info->pool_id, latest_trans_before_mount, fs_info);
		if (unlikely(ret!=0))
			return ret;
	}

	return 0;
}

/*
 * Called at the very end of mount sequence: does journal replay,
 * opens up sysfs and releases the cleaner and the committer threads.
 */
int zbtrfs_fs_info_start2(struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	struct btrfs_trans_handle *trans = NULL;

	ZBTRFSLOG(fs_info,Z_KINFO, "START2");

	/* on read-only mount, we do not replay the journal */
	if (zfs_info->pool_id != 0 && !(fs_info->sb->s_flags & MS_RDONLY)) {
		trans = btrfs_join_transaction(fs_info->tree_root);
		if (unlikely(IS_ERR(trans))) {
			ret = PTR_ERR(trans);
			ZBTRFSLOG(fs_info, Z_KERR, "btrfs_start_transaction() failed, ret=%d", ret);
			zbtrfs_force_abort_transaction(NULL/*trans*/, fs_info->tree_root, ret);
			goto out;
		}

		ret = zjournal_replay(zfs_info->pool_id);
		if (unlikely(ret)) {
			ZBTRFSLOG(fs_info, Z_KERR, "zjournal_replay(pool_id=%u) failed, ret=%d", zfs_info->pool_id, ret);
			zbtrfs_force_abort_transaction(trans, fs_info->tree_root, ret);
			btrfs_end_transaction(trans, fs_info->tree_root);
		} else {
			ret = btrfs_commit_transaction(trans, fs_info->tree_root);
			if (unlikely(ret))
				ZBTRFSLOG(fs_info, Z_KERR, "btrfs_commit_transaction() failed, ret=%d", ret);
		}
	}

	if (ret == 0)
		zbtrfs_sysfs_start(fs_info, fs_info->sb->s_id);

	/* in any case - awake everybody waiting for replay */
	zfs_info->replay_completed = true;
	smp_mb();
	wake_up(&zfs_info->replay_completed_wait);

out:
	return ret;
}

/*
 * This function undoes the effect of zbtrfs_fs_info_start2().
 * If zbtrfs_fs_info_start1() was called and succeeded, this function is
 * guaranteed to be called (even if zbtrfs_fs_info_start2() was not called at all).
 * If zbtrfs_fs_info_start1() did not succeed, however, this function will not
 * be called.
 */
void zbtrfs_fs_info_stop(struct btrfs_fs_info *fs_info)
{
	ZBTRFSLOG(fs_info, Z_KINFO, "STOP");

	zbtrfs_sysfs_stop(fs_info);
}

/*
 * This function undoes the effects of zbtrfs_fs_info_start1() and zbtrfs_fs_info_init().
 * If zbtrfs_fs_info_init() was called, then this function is guaranteed to be called
 * (even if zbtrfs_fs_info_start1() was not called at all).
 */
void zbtrfs_fs_info_fini(struct btrfs_fs_info *fs_info)
{
	struct zbtrfs_fs_info *zfs_info = &fs_info->zfs_info;
	LIST_HEAD(deleted_subvols);
	int rc;

	zklog(Z_KINFO, "FS[%s]: FINI", fs_info->sb ? fs_info->sb->s_id : "---");

	zbtrfs_sysfs_fini(fs_info);

	/* note: it is ok to call zjournal_umount() even on read-only mount */
	if (zfs_info->pool_id != 0) {
		rc = zjournal_umount(zfs_info->pool_id);
		BUG_ON(rc!=0);
	}

	zbtrfs_control_stop(fs_info);
	zbtrfs_control_fini(fs_info);

	/*
	 * control device is down, so nobody will attempt
	 * to fetch from the deletion tracking list, so
	 * we can free it now.
	 */
	spin_lock(&zfs_info->deleted_subvols_lock);
	list_splice_init(&zfs_info->deleted_subvols, &deleted_subvols);
	spin_unlock(&zfs_info->deleted_subvols_lock);
	zbtrfs_subvol_deletion_list_free(fs_info, &deleted_subvols);

	if (zfs_info->pool_data_bdev)
		blkdev_put(zfs_info->pool_data_bdev, FMODE_READ|FMODE_WRITE);
}

/********** global stuff init/exit ****************/
static void zexit_btrfs_journal(void)
{
	zjournal_exit();
}

static int zinit_btrfs_journal(void)
{
	int ret;

	ret = zjournal_init();
	if (ret != 0)
		return ret;

	ret = zjournal_sysfs_init();
	if (ret != 0)
		goto out;

	ret = 0;
out:
	if(ret!=0)
		zexit_btrfs_journal();
	return ret;
}

static void zexit_btrfs_globals(void)
{
	zbtrfs_globals_control_exit();

	if (zbtrfs_globals.replay_ctx_cachep!=NULL) {
		kmem_cache_destroy(zbtrfs_globals.replay_ctx_cachep);
		zbtrfs_globals.replay_ctx_cachep = NULL;
	}
	if (zbtrfs_globals.deleted_subvol_cachep!=NULL) {
		kmem_cache_destroy(zbtrfs_globals.deleted_subvol_cachep);
		zbtrfs_globals.deleted_subvol_cachep = NULL;
	}
	if (zbtrfs_globals.send_ctx_cachep!=NULL) {
		kmem_cache_destroy(zbtrfs_globals.send_ctx_cachep);
		zbtrfs_globals.send_ctx_cachep = NULL;
	}
	if (zbtrfs_globals.send_arg_cachep!=NULL) {
		kmem_cache_destroy(zbtrfs_globals.send_arg_cachep);
		zbtrfs_globals.send_arg_cachep = NULL;
	}
	if (zbtrfs_globals.changed_chunks_ctx_cachep!=NULL) {
		kmem_cache_destroy(zbtrfs_globals.changed_chunks_ctx_cachep);
		zbtrfs_globals.changed_chunks_ctx_cachep = NULL;
	}
	if (zbtrfs_globals.async_delayed_refs_cachep!=NULL) {
		kmem_cache_destroy(zbtrfs_globals.async_delayed_refs_cachep);
		zbtrfs_globals.async_delayed_refs_cachep = NULL;
	}

	if (zbtrfs_globals.kcopyd_client != NULL) {
		dm_kcopyd_client_destroy(zbtrfs_globals.kcopyd_client);
		zbtrfs_globals.kcopyd_client = NULL;
	}
}

static int zinit_btrfs_globals(void)
{
	int ret = 0;

	/* initialize stuff that cannot fail first */
	zbtrfs_globals.is_unit_test = false;

	ret = zbtrfs_globals_control_init();
	if (ret != 0)
		goto out;

	zbtrfs_globals.kcopyd_client = dm_kcopyd_client_create(NULL/*throttle*/);
	if (IS_ERR(zbtrfs_globals.kcopyd_client)) {
		ret = PTR_ERR(zbtrfs_globals.kcopyd_client);
		zklog(Z_KERR, "Could not create kcopyd client, ret = %d", ret);
		zbtrfs_globals.kcopyd_client = NULL;
		goto out;
	}

	zbtrfs_globals.replay_ctx_cachep = kmem_cache_create("zbtrfs_replay_ctx", zbtrfs_replay_ctx_size()/*size*/, 0/*align*/, 
														 SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL/*ctor*/);
	if (zbtrfs_globals.replay_ctx_cachep == NULL) {
		zklog(Z_KERR, "kmem_cache_create(replay_ctx_cachep)");
		ret = -ENOMEM;
		goto out;
	}
	zbtrfs_globals.deleted_subvol_cachep = kmem_cache_create("zbtrfs_del_subv", sizeof(struct zbtrfs_deleted_subvol_info)/*size*/, 0/*align*/, 
														 SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL/*ctor*/);
	if (zbtrfs_globals.deleted_subvol_cachep == NULL) {
		zklog(Z_KERR, "kmem_cache_create(deleted_subvol_cachep)");
		ret = -ENOMEM;
		goto out;
	}
	zbtrfs_globals.send_ctx_cachep = kmem_cache_create("zbtrfs_send_ctx", zbtrfs_send_ctx_size()/*size*/, 0/*align*/, 
														 SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL/*ctor*/);
	if (zbtrfs_globals.send_ctx_cachep == NULL) {
		zklog(Z_KERR, "kmem_cache_create(send_ctx_cachep)");
		ret = -ENOMEM;
		goto out;
	}
	zbtrfs_globals.send_arg_cachep = kmem_cache_create("zbtrfs_send_arg", zbtrfs_send_arg_size()/*size*/, 0/*align*/, 
														 SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL/*ctor*/);
	if (zbtrfs_globals.send_arg_cachep == NULL) {
		zklog(Z_KERR, "kmem_cache_create(send_arg_cachep)");
		ret = -ENOMEM;
		goto out;
	}
	zbtrfs_globals.changed_chunks_ctx_cachep = kmem_cache_create("zbtrfs_ch_ch_ctx", zbtrfs_changed_chunks_ctx_size()/*size*/, 0/*align*/, 
		                                                        SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL/*ctor*/);
	if (zbtrfs_globals.changed_chunks_ctx_cachep == NULL) {
		zklog(Z_KERR, "kmem_cache_create(changed_chunks_ctx_cachep)");
		ret = -ENOMEM;
		goto out;
	}
	zbtrfs_globals.async_delayed_refs_cachep = kmem_cache_create("zbtrfs_async_dref", zbtrfs_async_delayed_refs_size()/*size*/, 0/*align*/, 
		                                                        SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL/*ctor*/);
	if (zbtrfs_globals.async_delayed_refs_cachep == NULL) {
		zklog(Z_KERR, "kmem_cache_create(async_delayed_refs_cachep)");
		ret = -ENOMEM;
		goto out;
	}

out:
	if (ret != 0)
		zexit_btrfs_globals();
	return ret;
}

static void zexit_btrfs_klog(void)
{
	zklog_unregister_module();
}

static int zinit_btrfs_klog(void)
{
	int ret;

	ret = zklog_register_module(Z_KINFO);
	if (ret != 0) {
		ZKLOG_RAW_LOG(KERN_ERR, "zinit_btrfs_fs: zklog_register_module() failed, ret=%d", ret);
		return ret;
	}

	ret = zklog_add_tag("tc", "TreeCompare", Z_KINFO, &ZKLOG_TAG_TR_COMP);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('tc') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("sr", "SendReceive", Z_KINFO, &ZKLOG_TAG_SR);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('sr') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("cp", "CheckPoint", Z_KINFO, &ZKLOG_TAG_CHCKP);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('cp') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("bv", "BlockVirt", Z_KINFO, &ZKLOG_TAG_BLKVIRT);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('bv') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("cre", "SubvCre", Z_KINFO, &ZKLOG_TAG_SUBVOL_CRE);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('cre') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("dl", "SubvDel", Z_KINFO, &ZKLOG_TAG_SUBVOL_DEL);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('dl') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("su", "SpaceUsage", Z_KINFO, &ZKLOG_TAG_SPACE_USAGE);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('su') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("tx", "Transaction", Z_KINFO, &ZKLOG_TAG_TXN);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('tx') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("cu", "ChunkAlloc", Z_KINFO, &ZKLOG_TAG_CHUNK_ALLOC);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('cu') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("sc", "SpaceCaching", Z_KINFO, &ZKLOG_TAG_SPACE_CACHING);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('sc') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("ea", "ExtentAlloc", Z_KINFO, &ZKLOG_TAG_EXTENT_ALLOC);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('ea') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("fsp", "FreeSpCache", Z_KINFO, &ZKLOG_TAG_FREE_SP_CACHE);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('fsp') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("sz", "Resize", Z_KINFO, &ZKLOG_TAG_RESIZE);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('sz') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("di", "DelayedInode", Z_KINFO, &ZKLOG_TAG_DINODE);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('di') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("tn", "ZTenant", Z_KINFO, &ZKLOG_TAG_ZTENANT);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('tn') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("dr", "DelayedRef", Z_KINFO, &ZKLOG_TAG_DREF);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('dr') failed, ret=%d", ret);
		goto out;
	}

	ret = zklog_add_tag("cc", "ChangedChunks", Z_KINFO, &ZKLOG_TAG_CH_CHUNKS);
	if (ret != 0) {
		zklog(Z_KERR, "zklog_add_tag('cc') failed, ret=%d", ret);
		goto out;
	}

	ret = 0;

out:

	if(ret!=0)
		zexit_btrfs_klog();
	return ret;
}

/* sysfs is initialized at this point */
int zinit_btrfs_fs(void)
{
	int ret = 0;

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
#error Not compatible with with Zadara block-virt on-disk format!!!
	BUILD_BUG_ON(1);
#endif /*CONFIG_BTRFS_FS_CHECK_INTEGRITY*/

	ret = zinit_btrfs_klog();
	if (ret != 0)
		goto out;

	ret = zinit_btrfs_globals();
	if (ret != 0)
		goto out;

	ret = zinit_btrfs_journal();
	if (ret != 0)
		goto out;

#ifdef MODULE
	zklog(Z_KINFO, "srcversion=%s", THIS_MODULE->srcversion);
#endif /*MODULE*/
out:
	/* always safe to call */
	if (ret)
		zexit_btrfs_fs();

	return ret;
}

void zexit_btrfs_fs(void)
{
	zexit_btrfs_journal();

	zexit_btrfs_globals();

	zexit_btrfs_klog();
}
#endif /*CONFIG_BTRFS_ZADARA*/

