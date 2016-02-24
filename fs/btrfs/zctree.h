/*
 * Misc Zadara stuff.
 * This file is meant to be included directly from fs/btrfs/ctree.h
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 * If Zadara changes are ever accepted by the community, the contents of this file
 * will move into ctree.h and this file will disappear.
 */

/*
 * This replaces the normal btrfs_file_extent_item, by knocking off
 * fields that are not needed for block-virt.
 */
struct btrfs_bv_file_extent_item {
	/*
	 * This is key.objectid of EXTENT_ITEM in the extent tree,
	 * just like with regular btrfs_file_extent_item.
	 */
	__le64 disk_bytenr;

} __attribute__ ((__packed__));

BTRFS_SETGET_FUNCS(bv_file_extent_disk_bytenr, struct btrfs_bv_file_extent_item, disk_bytenr, 64);

/*
 * We need somehow to differentiate between the regular btrfs_file_extent_item
 * and the block-virt one.
 * Primarily, we will differentiate based on size, because our size should smaller.
 * If our size eventually gets bigger (which kind of kills the idea of introducing
 * our own item type), we will need to have "type" field at the same offset as
 * the original btrfs_file_extent_item, and the value of this field
 * will be BTRFS_FILE_EXTENT_BLOCK_VIRT, distinct from BTRFS_FILE_EXTENT_REG/INLINE/PREALLOC.
 */
static inline
bool btrfs_is_bv_file_extent_item(struct extent_buffer *eb, int nr)
{
	/* we make sure that currently we are strictly smaller! */
	BUILD_BUG_ON(sizeof(struct btrfs_bv_file_extent_item) >= sizeof(struct btrfs_file_extent_item));
	
	return 
		btrfs_item_size_nr(eb,nr) == sizeof(struct btrfs_bv_file_extent_item);
}

static inline
const char * btrfs_block_rsv_type_to_str(unsigned short type)
{
	const char *res = "???";

	switch (type) {
		case BTRFS_BLOCK_RSV_GLOBAL:
			res = "GLOB";
			break;
		case BTRFS_BLOCK_RSV_DELALLOC:
			res = "DELL";
			break;
		case BTRFS_BLOCK_RSV_TRANS:
			res = "TRAN";
			break;
		case BTRFS_BLOCK_RSV_CHUNK:
			res = "CHUN";
			break;
		case BTRFS_BLOCK_RSV_DELOPS:
			res = "DELO";
			break;
		case BTRFS_BLOCK_RSV_EMPTY:
			res = "EMPT";
			break;
		case BTRFS_BLOCK_RSV_TEMP:
			res = "TEMP";
			break;
	}

	return res;
}

static const char* const __flush_state_to_str[] = {
	"DELAYED_NR",
	"DELAYED",
	"DELALLOC",
	"DELALLOC_WAIT",
	"ALLOC_CHUNK",
	"COMMIT",
};
#define btrfs_flush_state_to_str(st) ENUM_TO_STR(__flush_state_to_str, (st), 1)

static inline
const char * btrfs_fs_key_type_to_str(u8 type)
{
	const char *res = NULL;
	
	switch (type)
	{
		case BTRFS_INODE_ITEM_KEY  	: res = "INO"        ; break;
        case BTRFS_INODE_REF_KEY   	: res = "REF"        ; break;
		case BTRFS_INODE_EXTREF_KEY	: res = "XRF"        ; break;		
		case BTRFS_XATTR_ITEM_KEY  	: res = "XAT"        ; break;
		case BTRFS_DIR_ITEM_KEY    	: res = "DIT"        ; break;
		case BTRFS_DIR_INDEX_KEY   	: res = "DIN"        ; break;
		case BTRFS_EXTENT_DATA_KEY 	: res = "EXT"        ; break;
		case (u8)-1                	: res = "-1"         ; break;
		default                    	: res = "???"        ; break;
	}

	return res;
}

static inline
const char *btrfs_extent_ref_type_to_str(u8 type)
{
	const char *res = NULL;

	switch (type)
	{
		case BTRFS_TREE_BLOCK_REF_KEY    : res = "TBR"; break;
		case BTRFS_EXTENT_DATA_REF_KEY   : res = "EDR"; break;
		case BTRFS_SHARED_BLOCK_REF_KEY  : res = "SBR"; break;
		case BTRFS_SHARED_DATA_REF_KEY   : res = "SDR"; break;
		default                          : res = "???"; break;
	}

	return res;
}

static const char* const __compare_tree_result_to_str[] = {
	"NEW",
	"DEL",
	"CHG",
	"SAM",
};
#define btrfs_compare_tree_result_to_str(res) ENUM_TO_STR(__compare_tree_result_to_str, (res), 0)

/* type_str needs to be at least 4-chars long */
static inline
const char *btrfs_block_group_type_to_str(u64 type)
{
	if ((type & BTRFS_BLOCK_GROUP_DATA) && (type & BTRFS_BLOCK_GROUP_METADATA))
		return "DM";
	if (type & BTRFS_BLOCK_GROUP_DATA)
		return "D";
	if (type & BTRFS_BLOCK_GROUP_SYSTEM)
		return "S";
	if (type & BTRFS_BLOCK_GROUP_METADATA)
		return "M";

	return "???";
}

static const char* const __block_group_caching_to_str[] = {
	"NO",
	"ST",
	"FT",
	"FN",
	"ER",
};
#define btrfs_block_group_caching_to_str(c) ENUM_TO_STR(__block_group_caching_to_str, (c), 0)

static inline
const char * btrfs_raid_type_to_str(u64 type)
{
	const char *res = NULL;

	switch (type & BTRFS_BLOCK_GROUP_PROFILE_MASK) {
		case BTRFS_BLOCK_GROUP_RAID0:
			res = "RD0";
			break;
		case BTRFS_BLOCK_GROUP_RAID1:
			res = "RD1";
			break;
		case BTRFS_BLOCK_GROUP_DUP:
			res = "DUP";
			break;
		case BTRFS_BLOCK_GROUP_RAID10:
			res = "R10";
			break;
		case BTRFS_BLOCK_GROUP_RAID5:
			res = "RD5";
			break;
		case BTRFS_BLOCK_GROUP_RAID6:
			res = "RD6";
			break;
		case 0:
			res = "SNG";
			break; 
		default:
			res = "???";
			break;
	}

	return res;
}

static const char* const __trans_state_to_str[] = {
	"RUNN",
	"BLCK",
	"C_ST",
	"C_DO",
	"UNBL",
	"CMPL",
};
#define btrfs_trans_state_to_str(st) ENUM_TO_STR(__trans_state_to_str, (st), 0)

bool btrfs_compare_trees_key_tree_end_reached(struct btrfs_key *key);

int btrfs_compare_trees_rearm_cp(const struct btrfs_compare_trees_checkpoint *cp,
	struct btrfs_root *left_root, struct btrfs_root *right_root,
	/* Output goes here */
	struct btrfs_path *left_path, struct btrfs_path *right_path,
	struct btrfs_key *left_key, int *left_level, int *left_end_reached,
	struct btrfs_key *right_key, int *right_level, int *right_end_reached);

struct btrfs_compare_trees_checkpoint*
btrfs_compare_trees_gen_checkpoint(struct btrfs_compare_trees_checkpoint *cp,
                            const struct btrfs_key *left_key, int left_end_reached,
                            const struct btrfs_key *right_key, int right_end_reached);

const char *btrfs_trans_type_to_str(unsigned int type);

