/*
 * journal sysfs interfaces added by Zadara.
 * This file is meant to be included directly from fs/btrfs/sysfs.c,
 * so no #ifndef/#define/#endif protection or function declarations are needed.
 */

#include "zjournal.h"

#define DELIMITERS " \t\n"

static int zjournal_sysfs_open(char *buf);
static int zjournal_sysfs_close(char *buf);
static int zjournal_sysfs_create_pool(char *buf);
static int zjournal_sysfs_delete_pool(char *buf);
static int zjournal_sysfs_mount(char *buf);
static int zjournal_sysfs_umount(char *buf);
static int zjournal_sysfs_replay(char *buf);
static int zjournal_sysfs_get_unreplayed(char *buf);
static int zjournal_sysfs_commit(char *buf);
static int zjournal_sysfs_write(char *buf);
static int zjournal_sysfs_dump(char *buf);
static int zjournal_sysfs_enable(char *buf);
static int zjournal_sysfs_disable(char *buf);

static void zjournal_sysfs_write_cb(void *arg, int error);

struct zjournal_sysfs_cmd {
	const char *name;
	const char *args;
	int (*handle)(char *buf);
};

struct zjournal_sysfs_cmd zjournal_sysfs_cmds[] = {
	/* name				args																								handle	*/
	{"open",			"<journal-dev> <vpsa-id> [sb_init [wipe_out]]",														zjournal_sysfs_open},
	{"close",			"[force]",																							zjournal_sysfs_close},
	{"create",			"<pool_id>",																						zjournal_sysfs_create_pool},
	{"delete",			"<pool_id>",																						zjournal_sysfs_delete_pool},
	{"mount",			"<pool_id> <transid>",																				zjournal_sysfs_mount},
	{"umount",			"<pool_id>"	,																						zjournal_sysfs_umount},
	{"get_unreplayed",	"<pool_id> <start_addr> <num_addr>",																zjournal_sysfs_get_unreplayed},	
	{"replay",			"<pool_id>",																						zjournal_sysfs_replay},
	{"commit",			"<pool_id> <transid>",																				zjournal_sysfs_commit},
	{"write",			"<pool_id> <subvol_treeid> <inode_num> <inode_gen> <file_offset> <address> <transid> <tenant_id>",	zjournal_sysfs_write},
	{"dump",			"<out-file>",																						zjournal_sysfs_dump},
	{"enable",			"",																									zjournal_sysfs_enable},
	{"disable",			"",																									zjournal_sysfs_disable},
};

static ssize_t zjournal_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t zjournal_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);

ZBTRFS_GLOBAL_RW_ATTR(zjournal);

int zjournal_sysfs_init(void)
{
	int rc;

	rc = sysfs_create_file(&btrfs_kset->kobj, &zbtrfs_global_attr_zjournal.attr);
	if (rc!=0) {
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "sysfs_create_file() failed, rc=%d", rc);
		return rc;
	}

	return 0;
}

static ssize_t zjournal_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t size = 0;
	int i;
	size += scnprintf(buf+size, PAGE_SIZE-size, "# Commands:\n");
	for (i=0; i<ARRAY_SIZE(zjournal_sysfs_cmds); i++) {
		struct zjournal_sysfs_cmd *cmd = &zjournal_sysfs_cmds[i];
		size += scnprintf(buf+size, PAGE_SIZE-size, "#   %-6s %s\n", cmd->name, cmd->args);
	}
	size += zjournal_show_globals(buf+size, PAGE_SIZE-size);
	return size;
}

static ssize_t zjournal_store(struct kobject *kobj, struct kobj_attribute *attr, const char *_buf, size_t count)
{
	struct zjournal_sysfs_cmd *cmd = NULL;
	const char *cmd_name = NULL;
	char *buf = NULL;
	char *buf0 = NULL;
	int rc, i;

	buf = kstrdup(_buf, GFP_KERNEL);
	if (buf==NULL) {
		rc = -ENOMEM;
		goto end;
	}
	buf0 = buf;

	if( buf[count-1] == '\n')
		buf[count-1] = '\0';

	cmd_name = strsep(&buf, DELIMITERS);
	if (cmd_name==NULL) {
		rc = -EINVAL;
		goto end;
	}

	for (i=0; i<ARRAY_SIZE(zjournal_sysfs_cmds); i++) {
		cmd = &zjournal_sysfs_cmds[i];
		if (strcmp(cmd_name, cmd->name)==0)
			break;
		cmd = NULL;
	}

	if (cmd==NULL) {
		rc = -EINVAL;
		goto end;
	}

	rc = cmd->handle(buf);

end:

	zklog_tag(rc == 0 ? Z_KINFO : Z_KWARN, ZKLOG_TAG_JOURNAL, "buf=[%s]: rc=%d", buf, rc);

	kfree(buf0);
	if (rc == 0)
		return count;
	else
		return rc;
}

static int zjournal_sysfs_open(char *buf)
{
	const char *jpath;
	const char *vpsaid_str;
	char vpsaid[BTRFS_UUID_SIZE] = "";
	const char *sb_init;
	const char *wipe_out;
	int i, rc;

	jpath = strsep(&buf, DELIMITERS);
	if(jpath==NULL)
		return -EINVAL;

	vpsaid_str = strsep(&buf, DELIMITERS);
	if(vpsaid_str==NULL)
		return -EINVAL;
	if(strlen(vpsaid_str) > 2*BTRFS_UUID_SIZE)
		return -ENAMETOOLONG;
	for(i=0; i<BTRFS_UUID_SIZE; i++) {
		char s[3] = "";
		s[0] = vpsaid_str[2*i];
		s[1] = vpsaid_str[2*i+1];
		rc = kstrtou8(s, 16, &vpsaid[i]);
		if(rc!=0)
			return rc;
	}

	sb_init = strsep(&buf, DELIMITERS);
	wipe_out = strsep(&buf, DELIMITERS);

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_open(jpath, vpsaid, wipe_out!=NULL, sb_init!=NULL);
}

static int zjournal_sysfs_close(char *buf)
{
	const char *force = NULL;

	force = strsep(&buf, DELIMITERS);

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_close(force!=NULL);
}

static int zjournal_sysfs_create_pool(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	int rc;

	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (rc!=0)
		return rc;

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_create_pool(pool_id);
}

static int zjournal_sysfs_delete_pool(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	int rc;

	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (rc!=0)
		return rc;

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_delete_pool(pool_id);
}

static int zjournal_sysfs_mount(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	const char *transid_str;
	u64 transid;
	int rc;
	
	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (rc!=0)
		return rc;

	transid_str = strsep(&buf, DELIMITERS);
	if(transid_str==NULL)
		return -EINVAL;
	rc = kstrtou64(transid_str, 0, &transid);
	if (rc!=0)
		return rc;

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_mount(pool_id, transid, NULL/*fs_info*/);
}

static int zjournal_sysfs_umount(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	int rc;

	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (rc!=0)
		return rc;

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_umount(pool_id);
}

static int zjournal_sysfs_get_unreplayed(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	const char *start_str;
	u64 start_addr;
	const char *num_str;
	u64 num_addr;
	int rc;

	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (rc!=0)
		return rc;

	start_str = strsep(&buf, DELIMITERS);
	if(start_str==NULL)
		return -EINVAL;
	rc = kstrtou64(start_str, 0, &start_addr);
	if (rc!=0)
		return rc;

	num_str = strsep(&buf, DELIMITERS);
	if(num_str==NULL)
		return -EINVAL;
	rc = kstrtou64(num_str, 0, &num_addr);
	if (rc!=0)
		return rc;

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_get_unreplayed_addresses(pool_id, start_addr, num_addr, NULL, NULL);
}

static int zjournal_sysfs_replay(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	int rc;

	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (rc!=0)
		return rc;

	if (buf!=NULL)
		return -E2BIG;

	rc = zjournal_replay(pool_id);

	return rc;
}

static int zjournal_sysfs_commit(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	const char *transid_str;
	u64 transid;
	int rc;

	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (rc!=0)
		return rc;

	transid_str = strsep(&buf, DELIMITERS);
	if(transid_str==NULL)
		return -EINVAL;
	rc = kstrtou64(transid_str, 0, &transid);
	if (rc!=0)
		return rc;

	if (buf!=NULL)
		return -E2BIG;

	return zjournal_commit(pool_id, transid);
}

struct zjournal_sysfs_write_sync {
	struct completion wait;
	int rc;
};

static int zjournal_sysfs_write(char *buf)
{
	const char *pool_id_str;
	u16 pool_id;
	const char *subvolid_str;
	u64 subvolid;
	const char *inode_num_str;
	u64 inode_num;
	const char *inode_gen_str;
	u64 inode_gen;
	const char *off_str;
	u64 off;
	const char *addr_str;
	u64 addr;
	const char *transid_str;
	u64 transid;
	const char *tenant_str;
	u16 tenant_id;
	struct zjournal_sysfs_write_sync sync;

	pool_id_str = strsep(&buf, DELIMITERS);
	if(pool_id_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou16(pool_id_str, 0, &pool_id);
	if (sync.rc!=0)
		return sync.rc;

	subvolid_str = strsep(&buf, DELIMITERS);
	if(subvolid_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou64(subvolid_str, 0, &subvolid);
	if (sync.rc!=0)
		return sync.rc;

	inode_num_str = strsep(&buf, DELIMITERS);
	if(inode_num_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou64(inode_num_str, 0, &inode_num);
	if (sync.rc!=0)
		return sync.rc;

	inode_gen_str = strsep(&buf, DELIMITERS);
	if(inode_gen_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou64(inode_gen_str, 0, &inode_gen);
	if (sync.rc!=0)
		return sync.rc;

	off_str = strsep(&buf, DELIMITERS);
	if(off_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou64(off_str, 0, &off);
	if (sync.rc!=0)
		return sync.rc;

	addr_str = strsep(&buf, DELIMITERS);
	if(addr_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou64(addr_str, 0, &addr);
	if (sync.rc!=0)
		return sync.rc;

	transid_str = strsep(&buf, DELIMITERS);
	if(transid_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou64(transid_str, 0, &transid);
	if (sync.rc!=0)
		return sync.rc;

	tenant_str = strsep(&buf, DELIMITERS);
	if(tenant_str==NULL)
		return -EINVAL;
	sync.rc = kstrtou16(tenant_str, 0, &tenant_id);
	if (sync.rc!=0)
		return sync.rc;

	if (buf!=NULL)
		return -E2BIG;

	init_completion(&sync.wait);

	zjournal_write(pool_id, subvolid, inode_num, inode_gen, off, addr, transid, tenant_id, zjournal_sysfs_write_cb, &sync);

	wait_for_completion(&sync.wait);

	return sync.rc;
}

static void zjournal_sysfs_write_cb(void *arg, int error)
{
	struct zjournal_sysfs_write_sync *sync = (struct zjournal_sysfs_write_sync*)arg;
	sync->rc = error;
	complete(&sync->wait); 
}

static int zjournal_sysfs_dump(char *buf)
{
	const char *outfile;
	struct file *fd;
	int rc;

	outfile = strsep(&buf, DELIMITERS);
	if(outfile==NULL)
		return -EINVAL;

	if (buf!=NULL)
		return -E2BIG;

	fd = filp_open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (unlikely(IS_ERR(fd))) {
		rc = PTR_ERR(fd);
		zklog_tag(Z_KWARN, ZKLOG_TAG_JOURNAL, "filp_open(%s) failed, rc=%d", outfile, rc);
		return rc;
	}

	rc = zjournal_dump_map(fd);

	filp_close(fd, NULL);

	return rc;
}

static int zjournal_sysfs_enable(char *buf)
{
	if (buf!=NULL)
		return -E2BIG;

	zjournal_enable(true);
	return 0;
}

static int zjournal_sysfs_disable(char *buf)
{
	if (buf!=NULL)
		return -E2BIG;

	zjournal_enable(false);
	return 0;
}

