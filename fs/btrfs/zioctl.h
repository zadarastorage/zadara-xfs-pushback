/*
 * IOCTLs added by Zadara.
 * This file is meant to be included directly from ctree.h, 
 * so no #ifndef/#define/#endif protection or similar is needed.
 * If Zadara changes are ever accepted by the community, the contents of this file
 * will move into ioctl.h and this file will disappear.
 */

/******** The different Zadara IOCTL arg structs go here *************************/

struct btrfs_ioctl_subvol_info_args {
	__u64 subvol_treeid;					/* out - objectid of the subvolume ROOT_ITEM */
	__u64 otransid;				            /* out - transid of when this subvol has been created */
	struct btrfs_ioctl_timespec otime;		/* out - subvol/snap creation time */
	__u64 flags;							/* out - possible flags: BTRFS_SUBVOL_RDONLY */
	__u8 received_uuid[BTRFS_UUID_SIZE];	/* out - used for mirroring */
	__u64 ctransid;							/* out - used for mirroring */
	__u64 num_mapped_chunks_subvol;         /* out - how many chunks were mapped onto this subvolume */

	__u64 info_select_flags;				/* in - which additional information we want to receive */
};

struct btrfs_ioctl_blk_virt_vol_info_args {
	__u16 tenant_id;                        /* in  - ztenant_id of the volume; ZBTRFS_ZTENANT_SYSTEM_ID if this info is not needed */

	__u64 subvol_treeid;					/* out - objectid of the subvolume ROOT_ITEM */
	__u64 otransid;				            /* out - transid of when this subvol has been created */
	struct btrfs_ioctl_timespec otime;		/* out - subvol/snap creation time */
	__u64 flags;							/* out - possible flags: BTRFS_SUBVOL_RDONLY */
	__u8 received_uuid[BTRFS_UUID_SIZE];	/* out - used for mirroring */
	__u64 ctransid;							/* out - used for mirroring */
	__u64 num_mapped_chunks_subvol;         /* out - how many chunks were mapped onto this subvolume, including the not-yet committed transaction */
	__u64 num_mapped_chunks_blk_virt_vol;   /* out - how many chunks were mapped onto this block-virt volume, including the not-yet committed transaction */
	__u64 num_mapped_chunks_synced_blk_virt_vol; /* out - how many chunks were mapped onto this block-virt volume up to the last committed transaction */
	__u64 bytes_used_tenant;                /* out - how many bytes are used by this tenant, including the not-yet committed transaction */
	__u64 bytes_used_synced_tenant;         /* out - how many bytes are used up to the last committed transaction */

	__u64 info_select_flags;				/* in - which additional information we want to receive */
};

 /**************** CHECKPOINTING THE SEND STREAM **********************************************
  * A checkpoint is a blob. Only the kernel on the sending side is able to properly parse it.
  *
  * User-space on the sending side is also allowed to peek into first two fields of the
  * checkpoint, which are cp_size_bytes and version. (For easier debugging, however, we expose
  * the whole checkpoint structure for the user-space as well).
  * User-space on the sending side receives checkpoints from two sources:
  * - local kernel, which produces the send-stream
  * - receiving side, which sent the checkpoint to restart the send on the sending side
  *
  * At least for now, user-space on the sending side can check the following:
  * cp_size_bytes == sizeof(btrfs_send_checkpoint), as we don't intend to alter this structure
  * version <= BTRFS_SEND_CHECKPOINT_VERSION (if checkpoint is received from the kernel, then version==BTRFS_SEND_CHECKPOINT_VERSION)
  *
  * On the receiving side, it is forbidden to do any validations on the checkpoint.
  * Receving side must accept any checkpoint, and treat it as a blob. It can assume the 
  * maximal checkpoint size of 128 bytes.
  *
  * For the sending side, checkpoint defines two things:
  * - exact position in the send stream
  * - fully-deterministic content of the send-stream until that position
  *
  ***************** CHECKPOINT VERSIONING ************************************************** 
  * The content of the send-stream is defined by two properties:
  * - version of the checkpoint
  * - "supported" flags, like BTRFS_ZIOC_SEND_SUPPORT_UNMAP, passed to the sending side
  *
  * The sending side must behave as follows:
  * - receive the checkpoint from user-space and make sure that version<=BTRFS_SEND_CHECKPOINT_VERSION
  * - if the received checkpoint has: n_cmds_since_cp>0 || offset_in_write_cmd_bytes>0,
  *        replay the stream to the point at which n_cmds_since_cp==0 && offset_in_write_cmd_bytes==0
  *        behave as if our latest version == received version
  * - at this point n_cmds_since_cp==0 && offset_in_write_cmd_bytes==0
  * - continue generating the stream using latest checkpoint version
  * - use "supported" flags to check which commands can be sent to destination
  *
  * IMPORTANT: 
  *  - checkpoint versioning is relevant for block-virt only; non-block-virt send always uses version==1
  *  - pretty soon we will stop sending partial chunks for block-virt, but this change will not require
  *    incrementing the checkpoint version, as it is compatible with all versions.
  * Update (31/07/2014): we are moving to chunk-based diff, and thus not doing any additional changes
  * to the stream-based send.
  */

 /*
  * This is a tree comparison checkpoint.
  * This information is enough to rearm the tree comparison process 
  * to restart from the point where it was interrupted.
  *
  * This struct needs to be in strict endian and alignment, because it is sent over network.
  */
struct btrfs_compare_trees_checkpoint {
	__le64 left_key__objectid;
	__u8   left_key__type;
	__le64 left_key__offset;

	__le64 right_key__objectid;
	__u8   right_key__type;
	__le64 right_key__offset;
} __attribute__ ((__packed__));

 /*
  * This structure is used to restart the "send" stream
  * from some previously checkpointed position.
  * It needs strict endian and alignment, because it is sent over network.
  */ 
struct btrfs_send_checkpoint {
	__le32 cp_size_bytes;
 	__le32 version;

	/* Tree comparison checkpoint */
	struct btrfs_compare_trees_checkpoint tree_cmp_cp;

	/* Send context checkpoint */
	__le64 cur_ino;
	__le64 cur_inode_gen;
	__u8   cur_inode_new;
	__u8   cur_inode_new_gen;
	__u8   cur_inode_deleted;
	__le64 cur_inode_size;
	__le64 cur_inode_mode;
	__le64 send_progress;

	/* 
	 * Kernel cannot produce a checkpoint between any two commands, so
	 * this allows us to skip the required number of commands since
	 * the previous checkpoint.
	 * Also, if the last command was a large WRITE command, but we can send
	 * only a part of it, and later send the remainder. 
	 * IMPORTANT: soon we will stop sending partial chunks and then all new
	 * checkpoints will have offset_in_write_cmd_bytes==0
	 */
	__le64 n_cmds_since_cp;
 	__le64 offset_in_write_cmd_bytes;

} __attribute__ ((__packed__));

enum {
	BTRFS_SEND_CHECKPOINT_VERSION_1 = 1, /* first version */
	BTRFS_SEND_CHECKPOINT_VERSION_2 = 2, /* supports UNMAP commands for block-virt */

	BTRFS_SEND_CHECKPOINT_VERSION = BTRFS_SEND_CHECKPOINT_VERSION_2
};

#define BTRFS_HAS_TREE_CMP_CHECKPOINT(tree_cp)           \
	((le64_to_cpu((tree_cp)->left_key__objectid) != 0) && \
	 (le64_to_cpu((tree_cp)->right_key__objectid) != 0))

#define BTRFS_HAS_SEND_CHECKPOINT(cp) BTRFS_HAS_TREE_CMP_CHECKPOINT(&((cp)->tree_cmp_cp))

struct btrfs_ioctl_checkpoint_send_args {

#define BTRFS_ZIOC_SEND_BLOCK_VIRT         (1ULL << 0)
#define BTRFS_ZIOC_SEND_SUPPORT_UNMAP      (1ULL << 1)
	__u64 flags;            /* in */

	__u64 parent_root;		/* in, 0 if no parent */
	
	struct btrfs_send_checkpoint __user *in_cp;   /* in: checkpoint, kernel must check the version and size */
	__u32 in_cp_size_bytes;                       /* in: the size of the checkpoint buffer */

#define BTRFS_ZIOC_MIN_SEND_SIZE_BYTES (16*1024)	
	__u8 __user *send_buffer;                     /* in/out: this buffer will be filled with commands by kernel */
	__u32 send_buffer_size_bytes;                 /* in:  the size of send_buffer, must be at least BTRFS_ZIOC_MIN_SEND_SIZE_BYTES,
	                                                 out: the amount of valid data on successful completion */

	struct btrfs_send_checkpoint out_cp;          /* out: the checkpoint for the next batch of commands */
	__u8 end_of_data;                             /* out: whether we have pulled the last batch */
};
/**************************************************************************************************/

#define ZBTRFS_BLKVIRT_CONTROL_DEVICE_PREFIX "zbtrfs-bv-"
#define ZBTRFS_FS_CONTROL_DEVICE_PREFIX      "zbtrfs-fs-"

struct btrfs_ioctl_monitor_fs_args {
	__u8 is_periodic;                            /* in: hint whether this is a periodic call, or just an occasional call to check something specific */
	__u64 last_trans_committed;                  /* out: last transaction that was committed */

#define BTRFS_ZIOC_FS_STATE_SUPER_ERROR                 (1ULL << 2)
#define BTRFS_ZIOC_FS_STATE_JOURNAL_CORRUPTION          (1ULL << 3)	
#define BTRFS_ZIOC_FS_STATE_TREE_CORRUPTION             (1ULL << 4)
	__u64 fs_state;

	struct btrfs_ioctl_subvol_id_args __user *deleted_subvols; /* out: used to report deleted subvol */
	__u32 deleted_subvol_cnt;                                  /* in : size of deleted_subvols array */
	                                                           /* out: number of valid entries in this array */
};

struct btrfs_ioctl_subvol_id_args {
	__u64 subvol_treeid;
	__u64 otransid;
};


struct btrfs_ioctl_stats_args {
	__u64 n_commits;
	__u64 total_commit_run_delayed_refs_time_ms;
	__u64 total_commit_writeout_time_ms;
	__u64 total_commit_elapsed_time_ms;
	__u64 max_commit_elapsed_time_ms;
	__u64 total_commit_bytes_flushed;
	
	__u64 n_txn_joins;
	__u64 total_txn_join_elapsed_time_us;
	__u64 max_txn_join_elapsed_time_us;
};

/* THIS IOCTL WAS USED FOR SMR ALLOCATOR, BUT NOW IT IS OBSOLETE!!! */
struct btrfs_ioctl_rg_map_args {
	__u16 pool_id;                          /* in - to which pool this is intended */
	__u32 n_rgs;                            /* number of raid-groups in the below array */
	struct btrfs_ioctl_rg_info_args {       
		char name[16];
		__u64 num_sectors;
		__u8 num_data_disks;                /* for category-B block-group selection */
	} __user *rgs;                          /* raid-groups of the pool */
};

struct btrfs_ioctl_snap_create_batched_args {
	__u32 flush_writes_ioctl_cmd; /* in - which ioctl we should send to dm-btrfs to flush writes */
	
	__u32 n_snaps;                /* in - the size of the below array */
	struct btrfs_ioctl_snap_create_batched_entry {
		__s64 src_subvol_fd;                   /* in - fd to the source subvolume */
		__s64 dst_dir_fd;                      /* in - fd to the directory, in which the snapshot will be created */
		__u64 flags;                           /* in - BTRFS_SUBVOL_RDONLY */
		char __user *name;                     /* in - the name of the snapshot to be created */
		__u32 namelen;                         /* in - len of the above len, without '\0' */
		char dm_btrfs_devpath[32];             /* in  - dm-btrfs devpath to flush writes, optional */
		int error;                             /* out - whether the snap was created (user-space errno) */
	} __user *snaps;
};

/**************** CHECKPOINTING IN 'CHANGED-CHUNKS' **********************************************/

/*
 * This structure is used to continue the "changed-chunks" operation.
 * It needs strict endian and alignment, because it could be sent over network.
 */ 
struct btrfs_changed_chunks_checkpoint {
	__le32 cp_size_bytes;
 	__le32 version;

	/* Tree comparison checkpoint */
	struct btrfs_compare_trees_checkpoint tree_cmp_cp;

	/* we are always diffing the same inode in different subvolumes */
	__le64 ino_gen;

	/* how many consecutive chunks are treated as as "superchunk */
	__le32 n_chunks_in_superchunk;

	/* since tree_cmp_cp */
	__le64 last_reported_superchunk;

} __attribute__ ((__packed__));

enum {
	BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION_1 = 1, /* first version */

	BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION = BTRFS_CHANGED_CHUNKS_CHECKPOINT_VERSION_1
};

#define BTRFS_HAS_CHANGED_CHUNKS_CHECKPOINT(cp) BTRFS_HAS_TREE_CMP_CHECKPOINT(&((cp)->tree_cmp_cp))
/**************************************************************************************************/

struct btrfs_ioctl_changed_chunks_args {
	/* input checkpoint */
	struct btrfs_changed_chunks_checkpoint __user *in_cp;  /* in: input checkpoint; kernel must check version and size; NULL if not specified */
	__u32 in_cp_size_bytes;                                /* in: size of the user-space buffer */

	__u64 __user *changed_chunks;                          /* out: array, where kernel will put the chunks that require syncing */
	__u32 n_changed_chunks;                                /* in/out: number of entries in the array; out: how many valid entries we have */

	struct btrfs_changed_chunks_checkpoint __user *out_cp; /* out: the output checkpoint; this would be he checkpoint AFTER all the entries in "changed_chunks" are copied */
	__u32 out_cp_size_bytes;                               /* in/out: the size of the user-space buffer at "out_cp"; out: size of the output checkpoint */

	__u8 end_of_data;                                      /* out: signals to the caller that this batch of changed chunks is the last one */

	char parent_file_path[256];                            /* in: this is the blk-virt file (right_inode) against which we are going to compare our file (left_inode), 0 if none */

	__u64 __user *changed_chunks_lbas;                     /* out: for each chunk in "changed_chunks" array, this is the physical coordinate on
                                                              the pool data device, where the chunk resides. In case the chunk is not
                                                              mapped (was unmapped), this will be ULONG_MAX.
                                                              The size of this array is indicated via "n_changed_chunks", similar to the "changed_chunks" array. */

	__u64 __user *parent_chunks_lbas;                      /* out: this array is optional, and will be used only when "parent_file_path" has been specified.
                                                              For each chunk in "changed_chunks" array, this indicates the mapping of the chunk in the
                                                              the blk-virt file (right_inode) against which we are going to compare our file (left_inode).
                                                              ULONG_MAX will be used for "unmapped". The size of this array is indicated via "n_changed_chunks",
                                                              similar to the "changed_chunks" array. */
};

struct btrfs_ioctl_zjournal_open_args {
	char journal_dev_path[256];
	__u8 vpsaid[BTRFS_UUID_SIZE];
	__u8 new_journal;
};

struct btrfs_ioctl_zjournal_write_args {
	__u64 subvol_treeid;
	__u64 inode_num;
	__u64 inode_gen;
	__u64 file_offset;
	__u64 address;
	__u64 transid;
	__u16 tenant_id;
};

/********** Zadara IOCTLs go here ***************/
/* ATTENTION! "nr" can go only up to 255 */
enum {
	BTRFS_ZIOC_FIRST_NR = 200,
	BTRFS_ZJIOC_FIRST_NR = 230,
};

#define BTRFS_ZIOC_GET_SUBVOL_INFO       _IOR(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  0, struct btrfs_ioctl_subvol_info_args)
#define BTRFS_ZIOC_SEND_WITH_CHECKPOINT _IOWR(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  1, struct btrfs_ioctl_checkpoint_send_args)
#define BTRFS_ZIOC_MONITOR_FS			_IOWR(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  2, struct btrfs_ioctl_monitor_fs_args)
#define BTRFS_ZIOC_ABORT_TRANS            _IO(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  3)
#define BTRFS_ZIOC_IS_SUBVOL_DELETED     _IOW(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  4, struct btrfs_ioctl_subvol_id_args)
#define BTRFS_ZIOC_GET_STATS             _IOR(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  5, struct btrfs_ioctl_stats_args)

/* THIS IOCTL WAS USED FOR SMR ALLOCATOR, BUT NOW IT IS OBSOLETE!!! */
#define BTRFS_ZIOC_SET_RG_MAP            _IOW(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  6, struct btrfs_ioctl_rg_map_args)

#define BTRFS_ZIOC_SNAP_CREATE_BATCHED  _IOWR(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  7, struct btrfs_ioctl_snap_create_batched_args)
#define BTRFS_ZIOC_GET_BLK_VIRT_VOL_INFO _IOR(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  8, struct btrfs_ioctl_blk_virt_vol_info_args)
#define BTRFS_ZIOC_CHANGED_CHUNKS       _IOWR(BTRFS_IOCTL_MAGIC, BTRFS_ZIOC_FIRST_NR +  9, struct btrfs_ioctl_changed_chunks_args)

#define BTRFS_ZJIOC_OPEN		_IOW(BTRFS_IOCTL_MAGIC, BTRFS_ZJIOC_FIRST_NR + 0, struct btrfs_ioctl_zjournal_open_args)	/* sent to /dev/btrfs-control */
#define BTRFS_ZJIOC_CLOSE		_IO (BTRFS_IOCTL_MAGIC, BTRFS_ZJIOC_FIRST_NR + 1)											/* sent to /dev/btrfs-control */
#define BTRFS_ZJIOC_CREATE_POOL	_IOW(BTRFS_IOCTL_MAGIC, BTRFS_ZJIOC_FIRST_NR + 2, u16/*pool_id*/)							/* sent to /dev/btrfs-control */
#define BTRFS_ZJIOC_DELETE_POOL	_IOW(BTRFS_IOCTL_MAGIC, BTRFS_ZJIOC_FIRST_NR + 3, u16/*pool_id*/)							/* sent to /dev/btrfs-control */
/*#define BTRFS_ZJIOC_REPLAY	_IO (BTRFS_IOCTL_MAGIC, BTRFS_ZJIOC_FIRST_NR + 4)	                                    OBSOLETE - now performed as part of mount */
#define BTRFS_ZJIOC_WRITE		_IOW(BTRFS_IOCTL_MAGIC, BTRFS_ZJIOC_FIRST_NR + 5, struct btrfs_ioctl_zjournal_write_args)	/* sent to btrfs, used for testing only */
#define BTRFS_ZJIOC_COMMIT		_IOW(BTRFS_IOCTL_MAGIC, BTRFS_ZJIOC_FIRST_NR + 6, u64/*transid*/)							/* sent to btrfs, used for testing only */

