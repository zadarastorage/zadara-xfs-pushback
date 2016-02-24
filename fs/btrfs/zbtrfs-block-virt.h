#ifndef __ZBTRFS__BLOCK_VIRT_HDR__
#define __ZBTRFS__BLOCK_VIRT_HDR__

/********Core block-virt APIs *********************************/

struct btrfs_bv_file_extent_item;

/*
 * Check validity of struct btrfs_bv_file_extent_item found in a leaf of a file tree.
 */
int zbtrfs_blk_virt_check_bv_file_extent_item(struct btrfs_root *root, u64 ino, u64 offset, unsigned int gran_bytes,
					struct extent_buffer *leaf, int slot, struct btrfs_bv_file_extent_item *bfei);

/*
 * Map a block-virt chunk from extent-tree coordinate (logical) to the physical coordinate 
 * on the pool block device.
 * @param combination of BTRFS_BLOCK_GROUP_DATA/SYSTEM/METADATA
 * @param length length of the block-virt chunk in bytes.
 */
int zbtrfs_blk_virt_map_block(struct btrfs_fs_info *fs_info, u64 type, u64 logical, u64 length, u64 *physical);

/********Snap creation******************************************/

/*
 * Snapshot creation is coordinated with dm-btrfs objects.
 * During create_pending_snapshots() we flush outstanding writes
 * on relevant dm-btrfs objects.
 * Below structures and functions support that.
 */
struct zbtrfs_blk_virt_cre_snap_ctx {
	unsigned int flush_writes_ioctl_cmd;
	/* currently we have a single dm-btrfs in each subvolume */
	struct block_device *dm_btrfs_bdev;
};

/*
 * Init the context by opening the relevant dm-btrfs devpath.
 * Currently we support only one dm-btrfs per subvolume,
 * otherwise we need to pass array of names.
 */
int zbtrfs_blk_virt_cre_snap_ctx_init(struct zbtrfs_blk_virt_cre_snap_ctx *ctx, const char *dm_btrfs_devpath, u32 flush_writes_ioctl_cmd);

/*
 * Flush outstanding writes on the relevant dm-btrfs objects.
 * This is called during create_pending_snapshots(), while transaction
 * commit is in critical section, i.e., not allowing new transactions
 * to be opened.
 */
int zbtrfs_blk_virt_cre_snap_flush_writes(struct btrfs_fs_info *fs_info, struct btrfs_transaction *trans, struct zbtrfs_blk_virt_cre_snap_ctx *ctx);

/*
 * Free resources allocated in zbtrfs_blk_virt_cre_snap_ctx_init()
 */
void zbtrfs_blk_virt_cre_snap_ctx_fini(struct zbtrfs_blk_virt_cre_snap_ctx *ctx);

/********Journal replay*****************************************/

/*
 * Allocate new chunk to replay journal entry.
 * @return <0 on error, 0 if chunk was allocated.
 * @param out_phys_bytenr if return value is 0: this is allocated chunk physical location,
 * @param replay_ctx relevant only if return value is 0, caller need to pass it back to 
 * 				zbtrfs_blk_virt_journal_replay_entry 
 * @note After call to this function, journal should search for entry with address that match out_phys_bytenr in same pool
 *  	If found, call zbtrfs_blk_virt_journal_replay_entry with found entry parameters.
 *  	If not found, call zbtrfs_blk_virt_journal_replay_entry with first entry
 */
int zbtrfs_blk_virt_get_chunk_for_replay(struct btrfs_fs_info *fs_info, u64 tree_id,
							   u64 *out_phys_bytenr, void **replay_ctx);

struct zjournal_entry {
	u64 subvol_treeid;
	u64 inode_num;
	u64 inode_gen;
	u64 file_offset;
	u64 address;
} __attribute__ ((packed));

/*
 * Replay journal entry.
 * @return <0 on error, 0 if entry was replayed, 1 if entry not replayed due to "logical error".
 * @param entry->address is address of entry from journal,
 * @param allocated_address of chunk (out_phys_bytenr) returned from zbtrfs_blk_virt_get_chunk_for_replay,
 * @param tenant_id to account the allocation against
 * @param replay_ctx is context returned from zbtrfs_blk_virt_get_chunk_for_replay 
 */
int zbtrfs_blk_virt_journal_replay_entry(struct btrfs_fs_info *fs_info, const struct zjournal_entry *entry, u64 allocated_address, u16 tenant_id, void *replay_ctx);

/*
 * Release resources acquired by zbtrfs_blk_virt_journal_replay_entry() when
 * for some reason we decide not to replay the entry.
 */
int zbtrfs_blk_virt_cancel_journal_replay_entry(struct btrfs_fs_info *fs_info, void *replay_ctx);

#endif /*__ZBTRFS__BLOCK_VIRT_HDR__*/
