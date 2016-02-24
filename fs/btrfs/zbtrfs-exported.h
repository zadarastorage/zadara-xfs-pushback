#ifndef __ZBTRFS_EXPORTED_HDR__
#define __ZBTRFS_EXPORTED_HDR__

/* Exported Zadara-BTRFS APIs */

struct zbtrfs_blk_virt_file_info {
	u16 pool_id;
	u64 subvol_treeid;
	u64 inode_num;
	u64 inode_gen;
};

/*
 * Obtain static information about a block-virt BTRFS file.
 * This information is guranteed not to change at least between mounts.
 */
int zbtrfs_blk_virt_get_file_info(struct file *file, struct zbtrfs_blk_virt_file_info *info);

/* 
 * Resolve a chunk for READ.
 * @return <0 on error, 0 if mapping exists, 1 if chunk was not mapped
 * @param out_phys_bytenr relevant if return value is 0; this is the resolved chunk location
 */
int zbtrfs_blk_virt_resolve_read(struct file *file, u64 chunk_index, unsigned int gran_bytes, u64 *out_phys_bytenr);

/*
 * This callback function will be called by block-virt chunk-mapping APIs,
 * in case the chunk is already mapped, but while still attached to a transaction.
 */
typedef void (*zbtrfs_blk_virt_chunk_already_migrated_fn)(void *cb_arg);

/*
 * Chunk is not locked; resolve the location of the chunk.
 * This function is an optimization, to avoid locking of already-mapped chunks.
 * @return <0 on error, 0 if mapping exists and migration not needed, 1 if migration needed
 * @param out_phys_bytenr relevant if return value is 0; this is the resolved chunk location
 * @param alr_migr_cb will be called in case the chunk is already migrated (i.e., the function
 *                         will most probably return 0), while still attached to a transaction
 * @param cb_arg parameter to the alr_migr_cb function
 * @note If this function returns 0, the caller still needs to ensure
 *       that migration is not CURRENTLY happening for this chunk!!!
 */
int zbtrfs_blk_virt_resolve_write_unlocked(struct file *file, u64 chunk_index, unsigned int gran_bytes, u64 *out_phys_bytenr,
		zbtrfs_blk_virt_chunk_already_migrated_fn alr_migr_cb, void *cb_arg);

/* This context is a BLOB for the caller; only inside BTRFS we know what it's about */
struct zbtrfs_blk_virt_resolve_wr_ctx {
	u64 old_ei_bytenr;
	u64 ei_bytenr;
	void *trans_handle;
	u64 transid;
};

/*
 * Chunk is locked; resolve the location of this chunk.
 * @return <0 on error, 0 if mapping exists (migration not needed), 1 if migration needed
 * @param out_old_phys_bytenr relevant when return value is 1: previous chunk location or (u64)-1 if no mapping existed
 * @param out_phys_bytenr the resolved chunk location; relevant if return value is 0 or 1
 * @param out_ctx - will be filled and needs to be given back to chunk_migration_completed() call
 * @param alr_migr_cb will be called in case the chunk is already migrated (i.e., the function
 *                         will most probably return 0), while still attached to a transaction
 * @param cb_arg parameter to the alr_migr_cb function
 */
int zbtrfs_blk_virt_resolve_write_locked(struct file *file, u64 chunk_index, unsigned int gran_bytes,
		u64 *out_old_phys_bytenr, u64 *out_phys_bytenr, struct zbtrfs_blk_virt_resolve_wr_ctx *out_ctx,
		zbtrfs_blk_virt_chunk_already_migrated_fn alr_migr_cb, void *cb_arg);

/*
 * After chunk migration has been completed, this needs to be called.
 * @param tenant_id used to account this chunk allocation against
 * @param ctx exactly the same as returned by zbtrfs_blk_virt_resolve_write_locked()
 * @param migr_ret 0 if migration was successful, errno otherwise
 */
int zbtrfs_blk_virt_chunk_migr_completed(struct file *file, u64 chunk_index, unsigned int gran_bytes, u16 tenant_id,
		struct zbtrfs_blk_virt_resolve_wr_ctx *ctx, int migr_ret);

/*
 * Un-maps the specified chunk from the specified block-virt file.
 * The appropriate subvolume must be RW.
 * Chunk must be locked, i.e., no other activity, except perhaps reading
 * should be ongoing on the chunk in question.
 * @param out_old_phys_bytenr if this function succeeds, will be set to the physical coordinate of the chunk
 *                            if chunk was mapped, otherwise will be set to ULONG_MAX
 * @return 0 on success (even if chunk was not mapped), otherwise error
 */
int zbtrfs_blk_virt_unmap_chunk_locked(struct file *file, u64 chunk_index, unsigned int gran_bytes, u64 *out_old_phys_bytenr);

/*
 * btrfs cannot know exactly of when dm-btrfs performs NOCOW.
 * This API enabled dm-btrfs to account for NOCOWs properly.
 * This is just for stats.
 */
void zbtrfs_blk_virt_account_nocow(struct file *file, unsigned int count);

/* This mimics zbtrfs_changed_chunks_common_params */
struct zbtrfs_blk_virt_changed_chunks_params {
	/* input checkpoint */
	void __user *in_cp;
	u32 in_cp_size_bytes;

	u64 __user *changed_superchunks;
	u32 n_changed_superchunks;

	void __user *out_cp;
	u32 out_cp_size_bytes;

	u8 end_of_data;
};

/*
 * Determine changed superchunks between the "new" block-virt file and the "old" block-virt file.
 */
int zbtrfs_blk_virt_changed_superchunks(struct file *left_file, struct file *right_file,
		struct zbtrfs_blk_virt_changed_chunks_params *params,
		unsigned int n_chunks_in_superchunk);

typedef void (*zjournal_end_io_func)(void *cb_arg, int error);
struct btrfs_fs_info;

/** 
 * Called from dm-btrfs
 * @return 0 on success 
 *  -EINVAL		invalid pool_id
 *  -EBADF		journal was not opened
 *  -EBADF		pool was not mounted
 *  -EAGAIN		pool was not replayed
 *  -ENOSPC		no free slot on the journal device
 *  -errno		other error
 */
void zjournal_write(u16 pool_id, u64 subvol_treeid, u64 inode_num, u64 inode_gen, u64 file_offset, u64 address, u64 transid, u16 tenant_id, zjournal_end_io_func cb_func, void *cb_arg);

#endif /* __ZBTRFS_EXPORTED_HDR__ */

