#ifdef CONFIG_BTRFS_ZADARA

#ifndef __ZBTRFS_CHANGED_CHUNKS__
#define __ZBTRFS_CHANGED_CHUNKS__

/*
 * This is Zadara's way to do "send" for block-virt files.
 * This is the "changed chunks" infrastructure.
 * 
 * Send is stream oriented, i.e., it generates a stream of commands, which must be applied in
 * a strict order at destination. Send also needs to deal with complexities such as:
 * - Complex chains of file/dir renames and moves, which need to be exactly reproduced at destination.
 * - Variable file extent sizes, which lead to complex logic of determining what data in the file was changed.
 * For Zadara, all these complexities are avoided, because:
 * - Zadara block-virt file names are (or at least should be) unique (in the world),
 *   they are never renamed and moved, and there are no directores within our subvolumes.
 *   As a result, we don't have to deal with rename/move issues that send has to deal with. We can identify our volumes by names, and not
 *   by inode numbers and inode generations like send has to.
 * - We work with fixed-size extents. This makes it very simple to find whether a particular block-virt extent was changed, unmapped etc.
 * - Once we determine a set of changed extents, we can READ their data in parallel, and ship it in parallel to destination. 
 *   In other words, we don't have to be stream-oriented.
 *
 * Currently (18/05/2014), this infrastructure is used only for Volume Migration/Copy. For Remote Mirror, we still go the "send" way,
 * improved by our checkpointing support. It is envisioned, however, that sometimes we can move to use "changed chunks" infrastructure
 * for Remote Mirror as well.
 * Update (31/07/2014): we started using this infrastructure for Remote Mirror as well.
 *
 *
 * Notes:
 * - Volume Migration and Copy use the notion of "superchunk", when source and destination chunk sizes are different.
 *   Then superchunk is the highest chunk size of both.
 */

struct zbtrfs_changed_chunks_common_params {
	/* input checkpoint */
	struct btrfs_changed_chunks_checkpoint __user *in_cp;  /* in: input checkpoint; kernel must check version and size; NULL if not specified */
	u32 in_cp_size_bytes;                                  /* in: size of the user-space buffer */

	u64 __user *changed_superchunks;			           /* out: array, where kernel will put the superchunks that require syncing */
	u32 n_changed_superchunks;				               /* in/out: number of entries in the array; out: how many valid entries we have */

	struct btrfs_changed_chunks_checkpoint __user *out_cp; /* out: the output checkpoint; this would be he checkpoint AFTER all the entries in "changed_superchunks" are synced */
	u32 out_cp_size_bytes;								   /* in/out: the size of the user-space buffer at "out_cp"; out: size of the output checkpoint */

	u8 end_of_data;                                        /* out: signals to the caller that this batch of changed superchunks is the last one */
};

struct zbtrfs_changed_chunks_addtnl_params {
	unsigned int n_chunks_in_superchunk;

	/* these two are used only when n_chunks_in_superchunk == 1 */
	u64 __user *changed_chunks_lbas;					   /* out: for each chunk in "changed_superchunks" array, this is the physical coordinate on
															  the pool data device, where the chunk resides in "left_i". In case the chunk is not
															  mapped (was unmapped), this will be ULONG_MAX.
															  The size of this array is indicated via "n_changed_superchunks", similar to the
															  "changed_superchunks" array. */

	u64 __user *parent_chunks_lbas; 					   /* out: this array is optional, and will be used only when "parent_file_path" has been specified.
															  For each chunk in "changed_superchunks" array, this indicates the mapping of the chunk in the
															  the "right_i" inode, against which we are going to compare "left_i" inode.
															  ULONG_MAX will be used for "unmapped". The size of this array is indicated via "n_changed_superchunks",
															  similar to the "n_changed_superchunks" array. */
};

/*
 * Scan for changed chunks between the "old" block-virt file and the "new" block-virt file.
 * @param left_i the "new" block-virt file; mandatory
 * @param right_i the "old" block-virt file; optional
 * @param common_params in/out params
 * @param n_chunks_in_superchunk if > 1, then several consecutive chunks are treated as a single superchunk
 */
int zbtrfs_changed_chunks(struct inode *left_i, struct inode *right_i,
	                      struct zbtrfs_changed_chunks_common_params *common_params,
	                      struct zbtrfs_changed_chunks_addtnl_params *addtnl_params);

#endif /*__ZBTRFS_CHANGED_CHUNKS__*/

#endif /*CONFIG_BTRFS_ZADARA*/

