#ifdef CONFIG_BTRFS_ZADARA
#include <linux/delay.h>
#include "ctree.h"
#include "transaction.h"

void zbtrfs_zstats_init(struct btrfs_fs_info *fs_info)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int idx = 0;

	memset(zst, 0, sizeof(struct zstats));

	for (idx = 0; idx < ARRAY_SIZE(zst->txns); ++idx) {
		atomic_set(&zst->txns[idx].blocked, 0);
		atomic_set(&zst->txns[idx].committers_count, 0);
		atomic64_set(&zst->txns[idx].npages_flushed_txn_commit, 0);
		atomic64_set(&zst->txns[idx].npages_flushed_total, 0);
		atomic64_set(&zst->txns[idx].total_delayed_ref_runtime_nsec, 0);
		atomic64_set(&zst->txns[idx].total_num_delayed_refs, 0);
		atomic64_set(&zst->txns[idx].commit_num_delayed_refs, 0);
	}

	atomic64_set(&zst->npages_read, 0);

	atomic64_set(&zst->n_commits, 0);
	atomic64_set(&zst->total_commit_run_delayed_refs_time_ms, 0);
	atomic64_set(&zst->total_commit_writeout_time_ms, 0);
	atomic64_set(&zst->total_commit_elapsed_time_ms, 0);
	atomic64_set(&zst->max_commit_elapsed_time_ms, 0);
	atomic64_set(&zst->total_commit_bytes_flushed, 0);
	atomic64_set(&zst->re_read_marker, 0);
	
	atomic64_set(&zst->n_txn_joins, 0);
	atomic64_set(&zst->total_txn_join_elapsed_time_us, 0);
	atomic64_set(&zst->max_txn_join_elapsed_time_us, 0);

	atomic64_set(&zst->n_cow_unmapped, 0);
	atomic64_set(&zst->n_cow_mapped, 0);
	atomic64_set(&zst->n_cow_allocator, 0);
	atomic64_set(&zst->n_nocow, 0);
	atomic64_set(&zst->n_unmap, 0);
}

static int __zstats_find_txn_slot(struct zstats *zst, u64 transid, unsigned int *out_slot, struct btrfs_fs_info *fs_info, const char *func, bool print_err)
{
	unsigned int slot = 0, nslots = ARRAY_SIZE(zst->txns);

	for (slot = 0; slot < nslots; ++slot) {
		if (zst->txns[slot].transid == transid)
			break;
	}
	if (unlikely(slot >= nslots)) {
		if (print_err)
			ZBTRFS_WARN(1, "FS[%s]: [%s] did not find slot for transid=%llu", fs_info->sb->s_id, func, transid);
		return -ENOENT;
	}

	*out_slot = slot;

	return 0;
}

void zbtrfs_new_txn_started(struct btrfs_fs_info *fs_info, struct btrfs_transaction *new_trans)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int slot = 0;

	/* This is called under spinlock, we are safe to search for a free slot here */
	if (__zstats_find_txn_slot(zst, 0/*transid*/, &slot, fs_info, __FUNCTION__, false/*print_err*/) != 0) {
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "did not find free slot");
		return;
	}

	/* init the slot */
	memset(&zst->txns[slot], 0, sizeof(struct zstats_txn_stats));
	zst->txns[slot].transid = new_trans->transid;
	zst->txns[slot].start_time = ZTIME_START();
	atomic_set(&zst->txns[slot].blocked, 0);
	atomic_set(&zst->txns[slot].committers_count, 0);
	atomic64_set(&zst->txns[slot].npages_flushed_txn_commit, 0);
	atomic64_set(&zst->txns[slot].npages_flushed_total, 0);
	atomic64_set(&zst->txns[slot].total_delayed_ref_runtime_nsec, 0);
	atomic64_set(&zst->txns[slot].total_num_delayed_refs, 0);
	atomic64_set(&zst->txns[slot].commit_num_delayed_refs, 0);

	ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "txn[%llu] NEW", new_trans->transid);
	if (zklog_will_print_tag(Z_KDEB2, ZKLOG_TAG_TXN))
		dump_stack();
}

void ZBTRFS_TXN_START_WAIT_STARTED(struct btrfs_fs_info *fs_info, ktime_t *start)
{
	*start = ZTIME_START();
}

#define TXN_START_MSECS_THRESHOLD_PRINTWARN	3*1000

void ZBTRFS_TXN_START_WAIT_DONE(struct btrfs_fs_info *fs_info, ktime_t *start)
{
	u64 elapsed_us = ZTIME_US_ELAPSED(*start);
	/*
	 * Do not touch fs_info->running_transaction here.
	 * We may have waited for previous transaction to unblock, which
	 * sets fs_info->running_transaction to NULL.
	 */
	if (elapsed_us >= TXN_START_MSECS_THRESHOLD_PRINTWARN*1000)
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "Start transaction took [%llu ms]", elapsed_us/1000);
}

void ZBTRFS_TXN_JOIN_WAIT_STARTED(struct btrfs_fs_info *fs_info, ktime_t *start)
{
	*start = ZTIME_START();
}

#define TXN_JOIN_MSECS_THRESHOLD_PRINTWARN	3*1000

void ZBTRFS_TXN_JOIN_WAIT_DONE(struct btrfs_fs_info *fs_info, ktime_t *start)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	u64 elapsed_us = ZTIME_US_ELAPSED(*start);

	atomic64_inc(&zst->n_txn_joins);
	atomic64_add(elapsed_us, &zst->total_txn_join_elapsed_time_us);
	if (elapsed_us > atomic64_read(&zst->max_txn_join_elapsed_time_us))
		atomic64_set(&zst->max_txn_join_elapsed_time_us, elapsed_us);

	/* it's OK to touch fs_info->running_transaction here, we joined it */
	if (elapsed_us >= TXN_JOIN_MSECS_THRESHOLD_PRINTWARN*1000)
		ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "Join transaction took [%llu ms] for transid[%llu]", elapsed_us/1000, fs_info->running_transaction->transid);
}

void __zbtrfs_txn_blocked(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans, bool in_commit, const char* func, unsigned int line)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int slot = 0;
	int prev_blocked = 0;

	if (__zstats_find_txn_slot(zst, curr_trans->transid, &slot, fs_info, __FUNCTION__, true/*print_err*/) != 0)
		return;

	/* we are interested only in the first blocker */
	prev_blocked = atomic_xchg(&zst->txns[slot].blocked, 1);
	if (prev_blocked == 0) {
		zst->txns[slot].blocked_time = ZTIME_START();
		ZBTRFSLOG_TAG(fs_info, Z_KDEB1, ZKLOG_TAG_TXN, "txn[%llu] - BLOCKED[%s:%u]", curr_trans->transid, func, line);
	}

	/* set the real committer */
	if (in_commit) {
		/* we are called under fs_info->trans_lock */
		if (!ZBTRFS_WARN(zst->txns[slot].real_committer_pid != 0, "FS[%s]: transid=%llu already has real_committer=%d", 
			 fs_info->sb->s_id, curr_trans->transid, zst->txns[slot].real_committer_pid))
			 zst->txns[slot].real_committer_pid = current->pid;
	}
}

void zbtrfs_metadata_page_flushed(struct btrfs_fs_info *fs_info, u64 transid)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int slot = 0;

	if (__zstats_find_txn_slot(zst, transid, &slot, fs_info, __FUNCTION__, false/*print_err*/) != 0) {
		ZBTRFS_WARN(1, "FS[%s]: ZBTRFS_METADATA_PAGE_FLUSHED[transid=%llu] no such transaction!", fs_info->sb->s_id, transid);
	} else {
		atomic64_inc(&zst->txns[slot].npages_flushed_total);
		if (zst->txns[slot].in_commit_flush && current->pid == zst->txns[slot].real_committer_pid)
			atomic64_inc(&zst->txns[slot].npages_flushed_txn_commit);
	}
}

void zbtrfs_metadata_page_read(struct btrfs_fs_info *fs_info, unsigned int npages)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	atomic64_inc(&zst->npages_read);
}

void zbtrfs_account_delayed_ref_runtime(struct btrfs_fs_info *fs_info, u64 transid, u64 runtime_nsec, u64 count)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int slot = 0;

	if (__zstats_find_txn_slot(zst, transid, &slot, fs_info, __FUNCTION__, true/*print_err*/) != 0)
		return;

	atomic64_add(runtime_nsec, &zst->txns[slot].total_delayed_ref_runtime_nsec);
	atomic64_add(count, &zst->txns[slot].total_num_delayed_refs);
	if (current->pid == zst->txns[slot].real_committer_pid || current->pid == zst->txns[slot].first_committer_pid)
		atomic64_add(count, &zst->txns[slot].commit_num_delayed_refs);
}

void ZBTRFS_TXN_COMMIT_PHASE_STARTED(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans, ktime_t *start, enum zstats_txn_commit_phase phase)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int slot = 0;

	*start = ZTIME_START();

	switch (phase) {
		/* only in those we are interested */
		case RUN_DELAYED_REFS_1:
		case WAIT_FOR_COMMIT:
		case WAIT_FOR_PREV_COMMIT:
		case WRITE_AND_WAIT:
			break;
		default:
			return;
	}

	if (__zstats_find_txn_slot(zst, curr_trans->transid, &slot, fs_info, __FUNCTION__, true/*print_err*/) != 0)
		return;

	switch (phase) {
		case RUN_DELAYED_REFS_1:
			/* If we are the first committer, record some stuff */
			if (atomic_inc_return(&zst->txns[slot].committers_count) == 1) {
				ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "txn[%llu] COMMIT extwr:%d wr:%d", curr_trans->transid, 
					          atomic_read(&curr_trans->num_extwriters), atomic_read(&curr_trans->num_writers));
				zst->txns[slot].commit_start_time = *start;
				zst->txns[slot].first_committer_pid = current->pid;
			}
			break;
		case WAIT_FOR_COMMIT:
			ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "txn[%llu] WAIT_FOR_COMMIT extwr:%d wr:%d", curr_trans->transid,
				          atomic_read(&curr_trans->num_extwriters), atomic_read(&curr_trans->num_writers));
			break;
		case WAIT_FOR_PREV_COMMIT:
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "txn[%llu] WAIT_FOR_PREV_COMMIT extwr:%d wr:%d", curr_trans->transid,
				          atomic_read(&curr_trans->num_extwriters), atomic_read(&curr_trans->num_writers));
			break;
		case WRITE_AND_WAIT:
			zst->txns[slot].in_commit_flush = true;
			break;
		default:
			break;
	}
}

#define TXN_TIME_MSECS_THRESHOLD_PRINTWARN	10*1000

static const char* s_phase_to_name[] = {
	[RUN_DELAYED_REFS_1]					= "rdr1",
	[CRE_BLOCK_GROUPS]						= "cbg",
	[RUN_DELAYED_REFS_2]					= "rdr2",
	[WAIT_FOR_COMMIT]						= "wc",
	[WAIT_FOR_PREV_COMMIT]					= "wpc",
	[START_DELAL_RUN_DEL_ITEMS] 			= "wdl",
	[WAIT_EXT_WRITERS]						= "wew",
	[RUN_DEL_ITEMS_WAIT_DELAL_PO] 			= "rdl",
	[WAIT_WRITERS]							= "ww",
	[CRE_SNAPSHOTS] 						= "cs",
	[RUN_DELAYED_ITEMS] 					= "rdi",
	[RUN_DELAYED_REFS_3]					= "rdr3",
	[COMMIT_FS_ROOTS]						= "cfr",
	[COMMIT_COWONLY_ROOTS]					= "ccr",
	[COMMIT_COWONLY_ROOTS_ZTENANTS_SYNC]	= "zts",
	[PREP_EXTENT_COMMIT]					= "pec",
	[WRITE_AND_WAIT]						= "wrw",
	[WRITE_SUPER]							= "wrs",
};

void ZBTRFS_TXN_COMMIT_PHASE_DONE(struct btrfs_fs_info *fs_info, struct btrfs_transaction *curr_trans, ktime_t *start, enum zstats_txn_commit_phase phase)
{
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int slot = 0;
	u64 elapsed_ms = ZTIME_MS_ELAPSED(*start);

	if (ZBTRFS_WARN_ON(phase < 0 || phase >= ZSTATS_TXN_COMMIT_NUM_PHASES))
		return;

	switch (phase) {
		case WAIT_FOR_COMMIT:
			ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "txn[%llu] WAIT_FOR_COMMIT done", curr_trans->transid);
			break;
		case WAIT_FOR_PREV_COMMIT:
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "txn[%llu] WAIT_FOR_PREV_COMMIT done", curr_trans->transid);
			break;
		default:
			break;
	}

	if (__zstats_find_txn_slot(zst, curr_trans->transid, &slot, fs_info, __FUNCTION__, false/*print_err*/) != 0) {
		/* on WAIT_FOR_COMMIT, we always hit this warning, so shut it off */
		if (phase != WAIT_FOR_COMMIT)
			ZBTRFSLOG_TAG(fs_info, Z_KWARN, ZKLOG_TAG_TXN, "did not find slot for transid=%llu", curr_trans->transid);
		return;
	}

	atomic64_add(elapsed_ms, &zst->txns[slot].phases[phase]);

	switch (phase) {
	case PREP_EXTENT_COMMIT:
		zst->txns[slot].unblocked_time = ZTIME_START();
		/*
		 * at this point fs_info->running_transaction was reset,
		 * so assume all pages read up to now belong to the current transaction.
		 */
		zst->txns[slot].npages_read = atomic64_xchg(&zst->npages_read, 0);
		break;
	case WRITE_SUPER:
	{
		u64 re_read_marker = 0;
		unsigned long nrpages = fs_info->btree_inode->i_mapping->nrpages;
		u64 fs_avg_delayed_ref_runtime = 0;
		u64 total_delayed_ref_runtime_nsec = atomic64_read(&zst->txns[slot].total_delayed_ref_runtime_nsec);
		u64 total_num_delayed_refs = atomic64_read(&zst->txns[slot].total_num_delayed_refs);

		smp_mb();
		fs_avg_delayed_ref_runtime = fs_info->avg_delayed_ref_runtime;

		elapsed_ms = ZTIME_MS_ELAPSED(zst->txns[slot].commit_start_time);
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "txn[%llu] took %llums committers=%d open=%llums blocked=%llums read=%lluKB flushed=%lu/%luKb",
			  curr_trans->transid,
			  elapsed_ms, atomic_read(&zst->txns[slot].committers_count),
			  ZTIME_MS_ELAPSED_BETWEEN(zst->txns[slot].start_time, zst->txns[slot].blocked_time),
			  ZTIME_MS_ELAPSED_BETWEEN(zst->txns[slot].blocked_time, zst->txns[slot].unblocked_time),
			  (zst->txns[slot].npages_read << PAGE_CACHE_SHIFT) >> 10,
			  (atomic64_read(&zst->txns[slot].npages_flushed_txn_commit) << PAGE_CACHE_SHIFT) >> 10,
			  (atomic64_read(&zst->txns[slot].npages_flushed_total) << PAGE_CACHE_SHIFT) >> 10);

		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "txn[%llu] %s:%lu %s:%lu %s:%lu", curr_trans->transid,
			  s_phase_to_name[RUN_DELAYED_REFS_1],    atomic64_read(&zst->txns[slot].phases[RUN_DELAYED_REFS_1]),
			  s_phase_to_name[CRE_BLOCK_GROUPS],      atomic64_read(&zst->txns[slot].phases[CRE_BLOCK_GROUPS]),
			  s_phase_to_name[RUN_DELAYED_REFS_2],    atomic64_read(&zst->txns[slot].phases[RUN_DELAYED_REFS_2]));
		ZBTRFSLOG_TAG(fs_info, Z_KINFO, ZKLOG_TAG_TXN, "txn[%llu] %s:%lu %s:%lu %s:%lu %s:%lu %s:%lu", curr_trans->transid,
			  s_phase_to_name[WAIT_FOR_COMMIT],             atomic64_read(&zst->txns[slot].phases[WAIT_FOR_COMMIT]),
			  s_phase_to_name[WAIT_FOR_PREV_COMMIT],        atomic64_read(&zst->txns[slot].phases[WAIT_FOR_PREV_COMMIT]),
			  s_phase_to_name[START_DELAL_RUN_DEL_ITEMS],   atomic64_read(&zst->txns[slot].phases[START_DELAL_RUN_DEL_ITEMS]),
			  s_phase_to_name[WAIT_EXT_WRITERS],            atomic64_read(&zst->txns[slot].phases[WAIT_EXT_WRITERS]),
			  s_phase_to_name[RUN_DEL_ITEMS_WAIT_DELAL_PO], atomic64_read(&zst->txns[slot].phases[RUN_DEL_ITEMS_WAIT_DELAL_PO]));
		zklog_tag(Z_KINFO, ZKLOG_TAG_TXN, "-FS[%s] txn[%llu] %s:%lu %s:%lu %s:%lu %s:%lu", fs_info->sb->s_id, curr_trans->transid,
			  s_phase_to_name[WAIT_WRITERS],          atomic64_read(&zst->txns[slot].phases[WAIT_WRITERS]),
			  s_phase_to_name[CRE_SNAPSHOTS],         atomic64_read(&zst->txns[slot].phases[CRE_SNAPSHOTS]),
			  s_phase_to_name[RUN_DELAYED_ITEMS],     atomic64_read(&zst->txns[slot].phases[RUN_DELAYED_ITEMS]),
			  s_phase_to_name[RUN_DELAYED_REFS_3],    atomic64_read(&zst->txns[slot].phases[RUN_DELAYED_REFS_3]));
		zklog_tag(Z_KINFO, ZKLOG_TAG_TXN, "-FS[%s] txn[%llu] %s:%lu %s:%lu(%s:%lu) %s:%lu" , fs_info->sb->s_id, curr_trans->transid,
			  s_phase_to_name[COMMIT_FS_ROOTS],       atomic64_read(&zst->txns[slot].phases[COMMIT_FS_ROOTS]),
			  s_phase_to_name[COMMIT_COWONLY_ROOTS],  atomic64_read(&zst->txns[slot].phases[COMMIT_COWONLY_ROOTS]),
			  s_phase_to_name[COMMIT_COWONLY_ROOTS_ZTENANTS_SYNC], atomic64_read(&zst->txns[slot].phases[COMMIT_COWONLY_ROOTS_ZTENANTS_SYNC]),
			  s_phase_to_name[PREP_EXTENT_COMMIT],    atomic64_read(&zst->txns[slot].phases[PREP_EXTENT_COMMIT]));
		zklog_tag(Z_KINFO, ZKLOG_TAG_TXN, "FS[%s] txn[%llu] %s:%lu %s:%lu del-refs[fs-avg=%lluus avg=%lluus/%llu(%llu)] page-cache=%lu Kb", fs_info->sb->s_id, curr_trans->transid,
			  s_phase_to_name[WRITE_AND_WAIT],        atomic64_read(&zst->txns[slot].phases[WRITE_AND_WAIT]),
			  s_phase_to_name[WRITE_SUPER],           atomic64_read(&zst->txns[slot].phases[WRITE_SUPER]),
			  fs_avg_delayed_ref_runtime / NSEC_PER_USEC,
			  total_num_delayed_refs == 0 ? 0 : (total_delayed_ref_runtime_nsec / total_num_delayed_refs) / NSEC_PER_USEC,
			  total_num_delayed_refs,
			  (u64)atomic64_read(&zst->txns[slot].commit_num_delayed_refs),
			  (nrpages << PAGE_CACHE_SHIFT) >> 10);

		WARN(elapsed_ms >= TXN_TIME_MSECS_THRESHOLD_PRINTWARN,
			 "FS[%s] txn[%llu] commit took %llu ms", fs_info->sb->s_id, curr_trans->transid, elapsed_ms);

		/* 
		 * update stats with the new commit stats.
		 * note that at this point, we are the only thread doing
		 * this, since the current transaction is not out of the transaction list yet,
		 * so the subsequent transaction cannot get to WRITE_SUPER.
		 */

		/* make sure the marker is odd */
		re_read_marker = atomic64_inc_return(&zst->re_read_marker);
		if (ZBTRFS_WARN(re_read_marker % 2 == 0, "re_read_marker(%llu) MOD 2 == 0", re_read_marker))
			atomic64_inc(&zst->re_read_marker);

		atomic64_inc(&zst->n_commits);
		atomic64_add(atomic64_read(&zst->txns[slot].phases[RUN_DELAYED_REFS_1]) +
			         atomic64_read(&zst->txns[slot].phases[RUN_DELAYED_REFS_2]) +
			         atomic64_read(&zst->txns[slot].phases[RUN_DELAYED_REFS_3]),
			         	&zst->total_commit_run_delayed_refs_time_ms);
		atomic64_add(atomic64_read(&zst->txns[slot].phases[WRITE_AND_WAIT]) +
			         atomic64_read(&zst->txns[slot].phases[WRITE_SUPER]),
			         	&zst->total_commit_writeout_time_ms);
		atomic64_add(elapsed_ms, &zst->total_commit_elapsed_time_ms);
		if (elapsed_ms > atomic64_read(&zst->max_commit_elapsed_time_ms))
			atomic64_set(&zst->max_commit_elapsed_time_ms, elapsed_ms);
		atomic64_add((atomic64_read(&zst->txns[slot].npages_flushed_txn_commit) << PAGE_CACHE_SHIFT), &zst->total_commit_bytes_flushed);

		/* make the marker is even again */
		re_read_marker = atomic64_inc_return(&zst->re_read_marker);
		ZBTRFS_WARN(re_read_marker % 2 != 0, "re_read_marker(%llu) MOD 2 != 0", re_read_marker);

		/* free the slot */
		zst->txns[slot].transid = 0;
		break;
	}
	default:
		break;
	}
}

int zbtrfs_ioctl_get_stats(struct btrfs_fs_info *fs_info, struct btrfs_ioctl_stats_args *args)
{
	int ret = 0;
	struct zstats *zst = &fs_info->zfs_info.zstats;
	u64 re_read_marker = 0;
	unsigned int n_enter_tries = 0, n_tries = 0;

again:
	n_enter_tries = 0;
again_enter:
	/* catch the marker while it's even */
	re_read_marker = atomic64_read(&zst->re_read_marker);
	if (re_read_marker % 2 != 0) {
		++n_enter_tries;
		if (WARN_ON(n_enter_tries >= 3)) {
			ret = -EAGAIN;
			goto out;
		}
		msleep_interruptible(5/*msecs*/);
		goto again_enter;
	}

	/* read the values */
	args->n_commits                                 = atomic64_read(&zst->n_commits);
	args->total_commit_run_delayed_refs_time_ms     = atomic64_read(&zst->total_commit_run_delayed_refs_time_ms);
	args->total_commit_writeout_time_ms             = atomic64_read(&zst->total_commit_writeout_time_ms);
	args->total_commit_elapsed_time_ms              = atomic64_read(&zst->total_commit_elapsed_time_ms);
	args->max_commit_elapsed_time_ms                = atomic64_xchg(&zst->max_commit_elapsed_time_ms, 0);
	args->total_commit_bytes_flushed                = atomic64_read(&zst->total_commit_bytes_flushed);

	/* if the marker changed, retry */
	if (atomic64_read(&zst->re_read_marker) != re_read_marker) {
		++n_tries;
		if (WARN_ON(n_tries >= 3)) {
			ret = -EAGAIN;
			goto out;
		}
		msleep_interruptible(50/*msecs*/);
		goto again;
	}

	/* now fetch the txn join values - we can fetch inconsistent results here... */
	args->n_txn_joins                      = atomic64_read(&zst->n_txn_joins);
	args->total_txn_join_elapsed_time_us   = atomic64_read(&zst->total_txn_join_elapsed_time_us);
	args->max_txn_join_elapsed_time_us     = atomic64_xchg(&zst->max_txn_join_elapsed_time_us, 0);

out:	
	return ret;
}

ssize_t zbtrfs_zstats_show(struct btrfs_fs_info *fs_info, char *buf, size_t buf_size)
{
	ssize_t size = 0;
	struct zstats *zst = &fs_info->zfs_info.zstats;
	unsigned int slot = 0, nslots = ARRAY_SIZE(zst->txns);
	u64 n_cow_unmapped = 0, n_cow_mapped = 0, n_cow_allocator = 0, n_nocow = 0, n_unmap = 0, n_total = 0;

	/* this is a little racy, but never mind */
	for (slot = 0; slot < nslots; ++slot) {
		u64 transid = zst->txns[slot].transid;
		ktime_t start_time = zst->txns[slot].start_time;
		int committers_count = atomic_read(&zst->txns[slot].committers_count);
		ktime_t commit_start_time = zst->txns[slot].commit_start_time;

		if (transid > 0) {
			u64 open_ms = ZTIME_MS_ELAPSED(start_time);
			if (committers_count > 0) {
				u64 in_commit_ms = ZTIME_MS_ELAPSED(commit_start_time);
				size += scnprintf(buf + size, buf_size - size, "txn[%llu]: open %llu committing %llu\n", transid, open_ms, in_commit_ms);
			} else {
				size += scnprintf(buf + size, buf_size - size, "txn[%llu]: open %llu\n", transid, open_ms);
			}
		}
	}

	size += scnprintf(buf + size, buf_size - size, "max_commit_ms : %lu\n", atomic64_read(&zst->max_commit_elapsed_time_ms));
	size += scnprintf(buf + size, buf_size - size, "max_txnjoin_ms: %lu\n", atomic64_read(&zst->max_txn_join_elapsed_time_us) / 1000);

	/* show COW stats */
	n_cow_unmapped      = atomic64_xchg(&zst->n_cow_unmapped, 0);
	n_cow_mapped        = atomic64_xchg(&zst->n_cow_mapped, 0);
	n_cow_allocator     = atomic64_xchg(&zst->n_cow_allocator, 0);
	n_nocow             = atomic64_xchg(&zst->n_nocow, 0);
	n_unmap             = atomic64_xchg(&zst->n_unmap, 0);
	n_total = n_cow_unmapped + n_cow_mapped + n_cow_allocator + n_nocow + n_unmap;

	size += scnprintf(buf + size, buf_size - size, "COW_UNMAPPED:\t%llu/%llu %llu%%\n",
		              n_cow_unmapped, n_total,
		              n_total == 0 ? 0 : (n_cow_unmapped * 100) / n_total);
	size += scnprintf(buf + size, buf_size - size, "COW_MAPPED:\t%llu/%llu %llu%%\n",
		              n_cow_mapped, n_total,
		              n_total == 0 ? 0 : (n_cow_mapped * 100) / n_total);
	size += scnprintf(buf + size, buf_size - size, "COW_ZALLOC:\t%llu/%llu %llu%%\n",
		              n_cow_allocator, n_total,
		              n_total == 0 ? 0 : (n_cow_allocator * 100) / n_total);
	size += scnprintf(buf + size, buf_size - size, "NOCOW:\t\t%llu/%llu %llu%%\n",
		              n_nocow, n_total,
		              n_total == 0 ? 0 : (n_nocow * 100) / n_total);
	size += scnprintf(buf + size, buf_size - size, "UNMAP:\t\t%llu/%llu %llu%%\n",
		              n_unmap, n_total,
		              n_total == 0 ? 0 : (n_unmap * 100) / n_total);

	return size;
}
#endif /*CONFIG_BTRFS_ZADARA*/


