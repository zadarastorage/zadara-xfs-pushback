#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/nfsd/export.h>
#include <asm/uaccess.h>
#include "nfsd.h"
#include "state.h"
#include "xdr3.h"
#include "xdr4.h"
#include "zstats.h"

#define NFSDDBG_ZSTATS		(NFSDDBG_NOCHANGE+1)
#define NFSDDBG_FACILITY	NFSDDBG_ZSTATS

#define zprintk(log_level, format, ...)																							\
do {																															\
	if(strcmp(log_level, KERN_DEBUG)==0)																						\
		dprintk("[%d]nfsd-zstats [%s:%d]: " format, task_pid_vnr(current), __FUNCTION__, __LINE__, ##__VA_ARGS__);				\
	else																														\
		printk(log_level "[%d]nfsd-zstats [%s:%d]: " format, task_pid_vnr(current), __FUNCTION__, __LINE__, ##__VA_ARGS__);		\
} while(0)

#define PROCFS_NFS_ZADARA_DIR			"fs/nfs/zadara"
#define PROCFS_NFS_ZADARA_MGMT			"mgmt"
#define PROCFS_NFS_ZADARA_STATS			"zstats"
#define PROCFS_NFS_ZADARA_SHARE_PATH	"share-path"

#define PROCFS_NFS_ZADARA_CMD_ADD_SHARE		"add share"
#define PROCFS_NFS_ZADARA_CMD_DEL_SHARE		"del share"
#define PROCFS_NFS_ZADARA_CMD_ADD_EXPORT	"add export"
#define PROCFS_NFS_ZADARA_CMD_DEL_EXPORT	"del export"
#define PROCFS_NFS_ZADARA_CMD_DEL_ALL		"del all"
#define PROCFS_NFS_ZADARA_CMD_RESET_ALL		"reset all"

// must match zmeter.h::ZMETER_IO_BUCKET
typedef enum {
	ZSTATS_BUCKET_NONE		= 0,
	ZSTATS_BUCKET_OTHERS	= 1,
	ZSTATS_BUCKET_CREATE	= 2,	// create file/directory/link
	ZSTATS_BUCKET_DELETE	= 3,	// delete file/directory/link
	ZSTATS_BUCKET_RENAME	= 4,	// rename file/directory/link
	ZSTATS_BUCKET_READ		= 5,	// read from file
	ZSTATS_BUCKET_WRITE		= 6,	// write to file
	ZSTATS_BUCKET_FLUSH		= 7,	// flush cache
	ZSTATS_BUCKET_LOCK		= 8,	// lock file
	ZSTATS_BUCKET_UNLOCK	= 9,	// unlock file
	ZSTATS_BUCKET_GETATTR	= 10,	// get file attributes/access rights/lock status
	ZSTATS_BUCKET_SETATTR	= 11,	// set file attributes/access rights
	ZSTATS_BUCKET_READDIR	= 12,	// read directory content

	ZSTATS_BUCKET_MAX
} zstats_bucket_t;

static const char* zstats_bucket_names[ZSTATS_BUCKET_MAX] = {
	[ZSTATS_BUCKET_NONE]	= "NONE ",
	[ZSTATS_BUCKET_OTHERS]	= "OTHER",
	[ZSTATS_BUCKET_CREATE]	= "CREAT",
	[ZSTATS_BUCKET_DELETE]	= "DELET",
	[ZSTATS_BUCKET_RENAME]	= "RENAM",
	[ZSTATS_BUCKET_READ]	= "READ ",
	[ZSTATS_BUCKET_WRITE]	= "WRITE",
	[ZSTATS_BUCKET_FLUSH]	= "FLUSH",
	[ZSTATS_BUCKET_LOCK]	= "LOCK ",
	[ZSTATS_BUCKET_UNLOCK]	= "ULOCK",
	[ZSTATS_BUCKET_GETATTR]	= "GETA ",
	[ZSTATS_BUCKET_SETATTR]	= "SETA ",
	[ZSTATS_BUCKET_READDIR]	= "RDDIR",
};

struct zstats_info {
	unsigned long		ios;
	unsigned long		active_ios;
	unsigned long		errors;
	unsigned long long	bytes;
	unsigned long long	total_resp_time_usec;
	unsigned long		max_resp_time_usec;
	unsigned int		max_op_code;
};

struct zstats_export_entry {
	struct list_head		lnode;	// zstats_share_entry::exports
	const char*				address;
	struct proc_dir_entry	*pde_root;
	struct zstats_info		info[ZSTATS_BUCKET_MAX];
};

struct zstats_share_entry {
	struct list_head		lnode;		// zstats_stats::shares
	u64						share_id;
	const char				*share_path;
	const char				*share_name;
	struct list_head		exports;	// zstats_export_entry::lnode
	struct proc_dir_entry	*pde_root;
};

struct zstats_cmd {
	const char *cmd;
	int	(*func)(const char *arg);
};

struct zstats_svc_rqst {
	struct list_head			lnode;		// zstats_global::zrqsts
	const struct svc_rqst		*rqst;
	struct zstats_export_entry	*export_entry;
};

struct zstats_global {
	struct list_head		shares;		// zstats_share_entry::lnode
	struct list_head		zrqsts;		// zstats_svc_rqst::lnode
	char					*dpath_buf;
	struct proc_dir_entry	*pde_root;
	struct zstats_cmd		cmds[6];
};

DEFINE_MUTEX(zstats_mutex);
static struct zstats_global zstats_global;

static int zstats_cmd_add_share(const char *kbuf);
static int zstats_cmd_del_share(const char *kbuf);
static int zstats_cmd_add_export(const char *kbuf);
static int zstats_cmd_del_export(const char *kbuf);
static int zstats_cmd_del_all(const char *kbuf);
static int zstats_cmd_reset_all(const char *kbuf);

static int zstats_share_add(const char *share_path, const char *share_name, u64 share_id);
static int zstats_share_del(const char *share_path);
static void zstats_share_del_all(void);
static void zstats_share_reset_all(void);
static struct zstats_share_entry* __zstats_share_ctor(const char *share_path, const char *share_name, u64 share_id);
static void __zstats_share_dtor(struct zstats_share_entry *share_entry);
static struct zstats_share_entry* __zstats_share_get(const char *share_path);

static int zstats_export_add(const char *share_path, const char *address);
static int zstats_export_del(const char *share_path, const char *address);
static int __zstats_export_get_dpath(const struct svc_export *fh_export, char **path);
static int __zstats_export_get_zshareid(const char *share_path, u64 *share_id);

static struct zstats_export_entry* __zstats_export_entry_ctor(const struct zstats_share_entry *share_entry, const char *address);
static void __zstats_export_entry_dtor(struct zstats_export_entry *export_entry);
static struct zstats_export_entry *__zstats_export_entry_get_by_address(const struct zstats_share_entry *share_entry, const char *address, size_t addr_len);
static struct zstats_export_entry *__zstats_export_entry_get_by_auth_domain(const struct zstats_share_entry *share_entry, const struct auth_domain *client);
static struct zstats_export_entry* __zstats_export_entry_get_by_svc_export(const struct svc_export *fh_export);

////////////////////////////////////////////////////////////////
///
///

//                          	 1234567890123456
#define ZSTATS_EXPORT_HEADER	"ADDRESS_________ "
#define ZSTATS_EXPORT_FORMAT	"%-16s "

//							 12 12345 123456789012 123456 12345 123456789012 123456789012 12345678 123456789
#define ZSTATS_INFO_HEADER	"BUCKET__ IOS_________ ACTIVE ERROR BYTES_______ TOTAL-USEC__ MAX_USEC(VerPrcOpc) "
#define ZSTATS_INFO_FORMAT	"%2d %5s %12lu %6lu %5lu %12llu %12llu %8lu %#9x"

static ssize_t zstats_info_printf(char *kbuf, size_t size, const char *address, const struct zstats_info info[ZSTATS_BUCKET_MAX])
{
	size_t p = 0;
	bool address_printed = false;
	int i;

	for (i=0; i<ZSTATS_BUCKET_MAX; i++) {
		if (info[i].ios == 0 && i != ZSTATS_BUCKET_READ && i != ZSTATS_BUCKET_WRITE)
			continue;
		if (address != NULL) {
			p += scnprintf(kbuf+p, size-p, ZSTATS_EXPORT_FORMAT, address_printed ? "" : address);
			address_printed = true;
		}
		p += scnprintf(kbuf+p, size-p, ZSTATS_INFO_FORMAT"\n", i, zstats_bucket_names[i],
					   info[i].ios, info[i].active_ios, info[i].errors, info[i].bytes, info[i].total_resp_time_usec, info[i].max_resp_time_usec, info[i].max_op_code);
	}

	return p;
}

////////////////////////////////////////////////////////////////
///
///		/proc/fs/nfs/zadara/mgmt

static ssize_t zstats_mgmt_proc_read(struct file *file, char __user *buf, size_t size, loff_t *pos)
{
	char kbuf[512] = "";
	size_t p = 0;

	p += scnprintf(kbuf+p, sizeof(kbuf)-p, "Commands:\n");
	p += scnprintf(kbuf+p, sizeof(kbuf)-p, "  %s <share-path> <share-name> <share-id>\n", PROCFS_NFS_ZADARA_CMD_ADD_SHARE);
	p += scnprintf(kbuf+p, sizeof(kbuf)-p, "  %s <share-path>\n", PROCFS_NFS_ZADARA_CMD_DEL_SHARE);
	p += scnprintf(kbuf+p, sizeof(kbuf)-p, "  %s <share-path> <address>\n", PROCFS_NFS_ZADARA_CMD_ADD_EXPORT);
	p += scnprintf(kbuf+p, sizeof(kbuf)-p, "  %s <share-path> <address>\n", PROCFS_NFS_ZADARA_CMD_DEL_EXPORT);
	p += scnprintf(kbuf+p, sizeof(kbuf)-p, "  %s\n", PROCFS_NFS_ZADARA_CMD_DEL_ALL);
	p += scnprintf(kbuf+p, sizeof(kbuf)-p, "  %s\n", PROCFS_NFS_ZADARA_CMD_RESET_ALL);

	return simple_read_from_buffer(buf, size, pos, kbuf, p);
}

static ssize_t zstats_mgmt_proc_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	char kbuf[512] = "";
	char *p;
	size_t i, cmd_len;
	int	rc;

	if (size > sizeof(kbuf)-1)
		return -ENOMEM;
	if (copy_from_user(kbuf, buf, size))
		return -EFAULT;

	p = strchr(kbuf, '\n');
	if (p!=NULL)
		*p = '\0';

	for (i=0; i<ARRAY_SIZE(zstats_global.cmds); i++) {
		cmd_len = strlen(zstats_global.cmds[i].cmd);
		if(strncmp(kbuf, zstats_global.cmds[i].cmd, cmd_len)==0)
			break;
	}

	if (i<ARRAY_SIZE(zstats_global.cmds)) {
		rc = zstats_global.cmds[i].func(kbuf+cmd_len);	
	}
	else {
		zprintk(KERN_ERR, "Invalid input: [%s]\n", kbuf);
		rc = -EINVAL;
	}

	return rc!=0 ? rc : size;
}

static const struct file_operations zstats_mgmt_ops = {
	.owner	= THIS_MODULE,
	.read	= zstats_mgmt_proc_read,
	.write	= zstats_mgmt_proc_write,
};

////////////////////////////////////////////////////////////////
///
///		/proc/fs/nfs/zadara/$SHARE/*

static ssize_t zstats_share_stats_proc_read(struct file *file, char __user *buf, size_t size, loff_t *pos)
{
	const struct zstats_share_entry *share_entry = (struct zstats_share_entry*)PDE_DATA(file->f_path.dentry->d_inode);
	const struct zstats_export_entry *export_entry = NULL;
	struct zstats_info *total_info = NULL;
	char *kbuf = NULL;
	size_t p = 0;
	int i, rc;

	total_info = kzalloc(sizeof(struct zstats_info)*ZSTATS_BUCKET_MAX, GFP_KERNEL);
	if (unlikely(total_info == NULL)) {
		rc = -ENOMEM;
		goto end;
	}
	
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(kbuf == NULL)) {
		rc = -ENOMEM;
		goto end;
	}

	mutex_lock(&zstats_mutex);

	p += scnprintf(kbuf+p, PAGE_SIZE-p, ZSTATS_EXPORT_HEADER ZSTATS_INFO_HEADER "\n");

	list_for_each_entry(export_entry, &share_entry->exports, lnode) {

		p += zstats_info_printf(kbuf+p, PAGE_SIZE-p, export_entry->address, export_entry->info);

		for (i=0; i<ZSTATS_BUCKET_MAX; i++) {
			total_info[i].ios += export_entry->info[i].ios;
			total_info[i].active_ios += export_entry->info[i].active_ios;
			total_info[i].errors += export_entry->info[i].errors;
			total_info[i].bytes += export_entry->info[i].bytes;
			total_info[i].total_resp_time_usec += export_entry->info[i].total_resp_time_usec;
			if (total_info[i].max_resp_time_usec < export_entry->info[i].max_resp_time_usec) {
				total_info[i].max_resp_time_usec = export_entry->info[i].max_resp_time_usec;
				total_info[i].max_op_code = export_entry->info[i].max_op_code;
			}
		}
	}

	p += zstats_info_printf(kbuf+p, PAGE_SIZE-p, "TOTAL:", total_info);
	p += scnprintf(kbuf+p, PAGE_SIZE-p, "\n");

	mutex_unlock(&zstats_mutex);

	rc = simple_read_from_buffer(buf, size, pos, kbuf, p);

end:
	kfree(total_info);
	kfree(kbuf);

	return rc;
}

static const struct file_operations zstats_share_stats_ops = {
	.owner	= THIS_MODULE,
	.read	= zstats_share_stats_proc_read,
};

static ssize_t zstats_share_path_proc_read(struct file *file, char __user *buf, size_t size, loff_t *pos)
{
	const struct zstats_share_entry *share_entry = (struct zstats_share_entry*)PDE_DATA(file->f_path.dentry->d_inode);
	char *kbuf = NULL;
	size_t p = 0;
	int rc;

	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(kbuf == NULL)) {
		rc = -ENOMEM;
		goto end;
	}

	p += scnprintf(kbuf+p, PAGE_SIZE-p, "%s\n", share_entry->share_path);

	rc = simple_read_from_buffer(buf, size, pos, kbuf, p);

end:
	kfree(kbuf);

	return rc;
}

static const struct file_operations zstats_share_path_ops = {
	.owner	= THIS_MODULE,
	.read	= zstats_share_path_proc_read,
};

////////////////////////////////////////////////////////////////
///
///		/proc/fs/nfs/zadara/$SHARE/$EXPORT/*

static ssize_t zstats_export_proc_read(struct file *file, char __user *buf, size_t size, loff_t *pos)
{
	struct zstats_export_entry *export_entry = (struct zstats_export_entry*)PDE_DATA(file->f_path.dentry->d_inode);
	char *kbuf = NULL;
	size_t p = 0;
	int i, rc;

	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(kbuf == NULL)) {
		rc = -ENOMEM;
		goto end;
	}

	p += zstats_info_printf(kbuf+p, PAGE_SIZE-p, NULL, export_entry->info);

	for (i=0; i<ZSTATS_BUCKET_MAX; i++) {
		export_entry->info[i].max_resp_time_usec = 0;
		export_entry->info[i].max_op_code = 0;
	}

	rc = simple_read_from_buffer(buf, size, pos, kbuf, p);

end:

	kfree(kbuf);
	return rc;
}

static const struct file_operations zstats_export_ops = {
	.owner	= THIS_MODULE,
	.read	= zstats_export_proc_read,
};

////////////////////////////////////////////////////////////////
///
///	commands

static const char* pzstats_cmd_parse_string(const char *kbuf, char *str, size_t size);
static const char* pzstats_cmd_parse_int(const char *kbuf, s64 *n);

static int zstats_cmd_add_share(const char *kbuf)
{
	char share_path[128] = "";
	char share_name[128] = "";
	u64	share_id = 0;
	
	kbuf = pzstats_cmd_parse_string(kbuf, share_path, sizeof(share_path));
	kbuf = pzstats_cmd_parse_string(kbuf, share_name, sizeof(share_name));
	kbuf = pzstats_cmd_parse_int(kbuf, &share_id);

	if(kbuf==NULL)
		return -EINVAL;

	return zstats_share_add(share_path, share_name, share_id);
}

static int zstats_cmd_del_share(const char *kbuf)
{
	char share_path[128] = "";

	kbuf = pzstats_cmd_parse_string(kbuf, share_path, sizeof(share_path));

	if(kbuf==NULL)
		return -EINVAL;

	return zstats_share_del(share_path);
}

static int zstats_cmd_add_export(const char *kbuf)
{
	char share_path[128] = "";
	char address[128] = "";

	kbuf = pzstats_cmd_parse_string(kbuf, share_path, sizeof(share_path));
	kbuf = pzstats_cmd_parse_string(kbuf, address, sizeof(address));

	if(kbuf==NULL)
		return -EINVAL;

	return zstats_export_add(share_path, address);
}

static int zstats_cmd_del_export(const char *kbuf)
{
	char share_path[128] = "";
	char address[128] = "";

	kbuf = pzstats_cmd_parse_string(kbuf, share_path, sizeof(share_path));
	kbuf = pzstats_cmd_parse_string(kbuf, address, sizeof(address));

	if(kbuf==NULL)
		return -EINVAL;

	return zstats_export_del(share_path, address);
}

static int zstats_cmd_del_all(const char *kbuf)
{
	// Primarily only for debug purpose. We dont call nfs4 unhash here
	zstats_share_del_all();
	return 0;
}

static int zstats_cmd_reset_all(const char *kbuf)
{
	// Primarily only for debug purpose
	zstats_share_reset_all();
	return 0;
}

static const char* pzstats_cmd_parse_string(const char *kbuf, char *str, size_t size)
{
	size_t p, i, j;
	bool esc = false;

	if (kbuf==NULL)
		return kbuf;

	// Skip initial whitespaces
	p = strspn(kbuf, " \t");
	kbuf += p;

	for (i=0, j=0; kbuf[i]!='\0' && j<size-1; i++) {
		if (esc) {
			str[j++] = kbuf[i];
			esc = false;
		}
		else if (kbuf[i]==' ' || kbuf[i]=='\t') {
			break;
		}
		else if (kbuf[i]=='\\') {
			esc = true;
		}
		else {
			str[j++] = kbuf[i];
		}
	}

	if(esc) {
		// Last char is '\'
		zprintk(KERN_ERR, "Invalid buffer: [%s]\n", kbuf);
		return NULL;
	}

	if(j==0) {
		// Output is empty
		zprintk(KERN_ERR, "Empty buffer: [%s]\n", kbuf);
		return NULL;
	}
	else {
		str[j] = '\0';
		return kbuf+i;
	}
}

static const char* pzstats_cmd_parse_int(const char *kbuf, s64 *n)
{
	size_t p;
	char *endptr;

	if (kbuf==NULL)
		return kbuf;

	// Skip initial whitespaces
	p = strspn(kbuf, " \t");
	kbuf += p;

	*n = simple_strtoll(kbuf, &endptr, 0);

	if(endptr==kbuf)
		return NULL;
	else
		return endptr;
}

////////////////////////////////////////////////////////////////
///
///	init/fini

int zstats_init(void)
{
	zprintk(KERN_INFO, "init called\n");
	memset(&zstats_global, 0, sizeof(struct zstats_global));

	zstats_global.dpath_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (zstats_global.dpath_buf == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&zstats_global.shares);
	INIT_LIST_HEAD(&zstats_global.zrqsts);

	zstats_global.cmds[0].cmd = PROCFS_NFS_ZADARA_CMD_ADD_SHARE;	zstats_global.cmds[0].func = zstats_cmd_add_share;
	zstats_global.cmds[1].cmd = PROCFS_NFS_ZADARA_CMD_DEL_SHARE;	zstats_global.cmds[1].func = zstats_cmd_del_share;
	zstats_global.cmds[2].cmd = PROCFS_NFS_ZADARA_CMD_ADD_EXPORT;	zstats_global.cmds[2].func = zstats_cmd_add_export;
	zstats_global.cmds[3].cmd = PROCFS_NFS_ZADARA_CMD_DEL_EXPORT;	zstats_global.cmds[3].func = zstats_cmd_del_export;
	zstats_global.cmds[4].cmd = PROCFS_NFS_ZADARA_CMD_DEL_ALL;		zstats_global.cmds[4].func = zstats_cmd_del_all;
	zstats_global.cmds[5].cmd = PROCFS_NFS_ZADARA_CMD_RESET_ALL;	zstats_global.cmds[5].func = zstats_cmd_reset_all;

	return 0;
}

void zstats_fini(void)
{
	zprintk(KERN_INFO, "fini called\n");

	zstats_share_del_all();

	kfree(zstats_global.dpath_buf);
}

int zstats_proc_create(void)
{
	const struct proc_dir_entry *pde;

	zstats_global.pde_root = proc_mkdir(PROCFS_NFS_ZADARA_DIR, NULL);
	if (zstats_global.pde_root == NULL) {
		zprintk(KERN_ERR, "proc_mkdir(%s) failed\n", PROCFS_NFS_ZADARA_DIR);
		return -ENOMEM;
	}

	pde = proc_create(PROCFS_NFS_ZADARA_MGMT, 0/*mode*/, zstats_global.pde_root, &zstats_mgmt_ops);
	if (pde == NULL) {
		zprintk(KERN_ERR, "proc_create(%s/%s) failed\n", PROCFS_NFS_ZADARA_DIR, PROCFS_NFS_ZADARA_MGMT);
		zstats_proc_remove();
		return -ENOMEM;
	}

	return 0;
}

void zstats_proc_remove(void)
{
	if (likely(zstats_global.pde_root != NULL)) {
		proc_remove(zstats_global.pde_root);
		zstats_global.pde_root = NULL;
	}
}

////////////////////////////////////////////////////////////////
///
///	SHARES

static int zstats_share_add(const char *share_path, const char *share_name, u64 share_id)
{
	struct zstats_share_entry *share_entry = NULL;
	int	rc;

	zprintk(KERN_INFO, "Share[%s]: add name=%s, id=%llu\n", share_path, share_name, share_id);

	mutex_lock(&zstats_mutex);

	share_entry = __zstats_share_get(share_path);
	if (share_entry != NULL) {
		zprintk(KERN_ERR, "Share[%s]: already exists\n", share_path);
		rc = -EEXIST;
		goto out;
	}

	share_entry = __zstats_share_ctor(share_path, share_name, share_id);
	if (share_entry == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	list_add(&share_entry->lnode, &zstats_global.shares);
	rc = 0;

out:
	mutex_unlock(&zstats_mutex);

	return rc;
}

static int zstats_share_del(const char *share_path)
{
	struct zstats_share_entry *share_entry = NULL;
	u64 share_id = 0;
	int	rc;

	mutex_lock(&zstats_mutex);
	rc = __zstats_export_get_zshareid(share_path, &share_id);
	if (rc!=0)
		goto out;
//	mutex_unlock(&zstats_mutex);
//
//	nfs4_unhash_zshare_stateids(share_id);
//
//	mutex_lock(&zstats_mutex);

	share_entry = __zstats_share_get(share_path);
	if (share_entry == NULL) {
		zprintk(KERN_ERR, "Share[%s]: not found\n", share_path);
		rc = -ENOENT;
		goto out;
	}

	zprintk(KERN_INFO, "Share[%s]: delete\n", share_entry->share_path);

	list_del(&share_entry->lnode);
	__zstats_share_dtor(share_entry);

	rc = 0;

out:
	mutex_unlock(&zstats_mutex);
	return rc;
}

static void zstats_share_del_all(void)
{
	struct zstats_share_entry *share_entry = NULL;

	zprintk(KERN_INFO, "Delete all shares\n");

	mutex_lock(&zstats_mutex);

	while(!list_empty(&zstats_global.shares)) {
		share_entry = list_first_entry(&zstats_global.shares, struct zstats_share_entry, lnode);
		list_del(&share_entry->lnode);
		__zstats_share_dtor(share_entry);
	}

	mutex_unlock(&zstats_mutex);

	zprintk(KERN_INFO, "Successfully deleted all shares\n");
}

static void zstats_share_reset_all(void)
{
	struct zstats_share_entry *share_entry = NULL;
	struct zstats_export_entry *export_entry = NULL;

	zprintk(KERN_INFO, "Reset all stats\n");

	mutex_lock(&zstats_mutex);

	list_for_each_entry(share_entry, &zstats_global.shares, lnode) {
		list_for_each_entry(export_entry, &share_entry->exports, lnode) {
			memset(&export_entry->info, 0, sizeof(export_entry->info));
		}
	}

	mutex_unlock(&zstats_mutex);
}

static struct zstats_share_entry* __zstats_share_ctor(const char *share_path, const char *share_name, u64 share_id)
{
	struct zstats_share_entry *share_entry = NULL;
	const struct proc_dir_entry *pde;

	share_entry = kzalloc(sizeof(struct zstats_share_entry), GFP_KERNEL);
	if (share_entry == NULL)
		return NULL;

	share_entry->share_id = share_id;
	share_entry->share_path = kstrdup(share_path, GFP_KERNEL);
	share_entry->share_name = kstrdup(share_name, GFP_KERNEL);

	INIT_LIST_HEAD(&share_entry->exports);

	zprintk(KERN_DEBUG, "Share[%s]: proc_mkdir(%s/%s)\n", share_path, PROCFS_NFS_ZADARA_DIR, share_name);
	share_entry->pde_root = proc_mkdir(share_name, zstats_global.pde_root);
	if (share_entry->pde_root == NULL) {
		zprintk(KERN_ERR, "Share[%s]: proc_mkdir(%s/%s) failed\n", share_path, PROCFS_NFS_ZADARA_DIR, share_name);
		__zstats_share_dtor(share_entry);
		return NULL;
	}

	zprintk(KERN_DEBUG, "Share[%s]: proc_create_data(%s/%s/%s)\n", share_path, PROCFS_NFS_ZADARA_DIR, share_name, PROCFS_NFS_ZADARA_STATS);
	pde = proc_create_data(PROCFS_NFS_ZADARA_STATS, 0/*mode*/, share_entry->pde_root, &zstats_share_stats_ops, share_entry);
	if (pde == NULL) {
		zprintk(KERN_ERR, "Share[%s]: proc_create_data(%s/%s/%s) failed\n", share_path, PROCFS_NFS_ZADARA_DIR, share_name, PROCFS_NFS_ZADARA_STATS);
		__zstats_share_dtor(share_entry);
		return NULL;
	}

	zprintk(KERN_DEBUG, "Share[%s]: proc_create_data(%s/%s/%s)\n", share_path, PROCFS_NFS_ZADARA_DIR, share_name, PROCFS_NFS_ZADARA_SHARE_PATH);
	pde = proc_create_data(PROCFS_NFS_ZADARA_SHARE_PATH, 0/*mode*/, share_entry->pde_root, &zstats_share_path_ops, share_entry);
	if (pde == NULL) {
		zprintk(KERN_ERR, "Share[%s]: proc_create_data(%s/%s/%s) failed\n", share_path, PROCFS_NFS_ZADARA_DIR, share_name, PROCFS_NFS_ZADARA_SHARE_PATH);
		__zstats_share_dtor(share_entry);
		return NULL;
	}

	zprintk(KERN_DEBUG, "Share[%s]: allocate %p\n", share_entry->share_path, share_entry);

	return share_entry;
}

static void __zstats_share_dtor(struct zstats_share_entry *share_entry)
{
	struct zstats_export_entry *export_entry = NULL;

	if(share_entry==NULL)
		return;

	zprintk(KERN_DEBUG, "Share[%s]: free %p\n", share_entry->share_path, share_entry);

	while (!list_empty(&share_entry->exports)) {
		export_entry = list_first_entry(&share_entry->exports, struct zstats_export_entry, lnode);
		list_del(&export_entry->lnode);
		__zstats_export_entry_dtor(export_entry);
	}

	if (likely(share_entry->pde_root != NULL)) {
		proc_remove(share_entry->pde_root);
		share_entry->pde_root = NULL;
	}

	kfree(share_entry->share_path);
	kfree(share_entry->share_name);

	kfree(share_entry);
}

static struct zstats_share_entry* __zstats_share_get(const char *share_path)
{
	struct zstats_share_entry *share_entry = NULL;

	list_for_each_entry(share_entry, &zstats_global.shares, lnode) {
		if (strcmp(share_entry->share_path, share_path)==0) {
		   zprintk(KERN_DEBUG, "Share[%s]: get %p\n", share_entry->share_path, share_entry);
		   return share_entry;
		}
	}

	return NULL;
}

////////////////////////////////////////////////////////////////
///
///	EXPORT ENTRIES

static struct zstats_export_entry* __zstats_export_entry_ctor(const struct zstats_share_entry *share_entry, const char *address)
{
	struct zstats_export_entry *export_entry;
	const struct proc_dir_entry *pde;
	char address_procname[128] = "";
	char *p;

	export_entry = kzalloc(sizeof(struct zstats_export_entry), GFP_KERNEL);
	if (export_entry==NULL)
		return NULL;

	export_entry->address = kstrdup(address, GFP_KERNEL);
	if (export_entry==NULL) {
		__zstats_export_entry_dtor(export_entry);
		return NULL;
	}

	snprintf(address_procname, sizeof(address_procname), "%s", export_entry->address);
	p = strchr(address_procname, '/');
	if(p!=NULL)
		*p = '\\';

	zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: proc_mkdir(%s/%s/%s)\n", 
			share_entry->share_path, export_entry->address, 
			PROCFS_NFS_ZADARA_DIR, share_entry->share_name, address_procname);
	export_entry->pde_root = proc_mkdir(address_procname, share_entry->pde_root);
	if (export_entry->pde_root == NULL) {
		zprintk(KERN_ERR, "Share[%s]: Export[%s]: proc_mkdir(%s/%s/%s) failed\n", 
				share_entry->share_path, export_entry->address, 
				PROCFS_NFS_ZADARA_DIR, share_entry->share_name, address_procname);
		__zstats_export_entry_dtor(export_entry);
		return NULL;
	}
	
	zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: proc_create_data(%s/%s/%s/%s)\n", 
			share_entry->share_path, export_entry->address, 
			PROCFS_NFS_ZADARA_DIR, share_entry->share_name, address_procname, PROCFS_NFS_ZADARA_STATS);
	pde = proc_create_data(PROCFS_NFS_ZADARA_STATS, 0/*mode*/, export_entry->pde_root, &zstats_export_ops, export_entry);
	if (pde == NULL) {
		zprintk(KERN_ERR, "Share[%s]: Export[%s]: proc_create_data(%s/%s/%s/%s) failed\n", 
				share_entry->share_path, export_entry->address, 
				PROCFS_NFS_ZADARA_DIR, share_entry->share_name, address_procname, PROCFS_NFS_ZADARA_STATS);
		__zstats_export_entry_dtor(export_entry);
		return NULL;
	}

	zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: allocate %p\n", share_entry->share_path, export_entry->address, export_entry);

	return export_entry;
}

static void __zstats_export_entry_dtor(struct zstats_export_entry *export_entry)
{
	zprintk(KERN_DEBUG, "Export[%s]: free %p\n", export_entry->address, export_entry);
	if (likely(export_entry->pde_root != NULL)) {
		proc_remove(export_entry->pde_root);
		export_entry->pde_root = NULL;
	}
	kfree(export_entry->address);
	kfree(export_entry);
}

static struct zstats_export_entry *__zstats_export_entry_get_by_address(const struct zstats_share_entry *share_entry, const char *address, size_t addr_len)
{
	struct zstats_export_entry *export_entry;

	list_for_each_entry(export_entry, &share_entry->exports, lnode) {
		if (strncmp(export_entry->address, address, addr_len) == 0) {
			zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: get %p\n", share_entry->share_path, export_entry->address, export_entry);
			return export_entry;
		}
	}

	return NULL;
}

static struct zstats_export_entry *__zstats_export_entry_get_by_auth_domain(const struct zstats_share_entry *share_entry, const struct auth_domain *client)
{
	struct zstats_export_entry *export_entry = NULL;
	const char *name, *p;

	name = client->name;
	
	while(name[0]!='\0') {
		p = strchr(name, ',');
		if(p==NULL) {
			export_entry = __zstats_export_entry_get_by_address(share_entry, name, -1);
			break;
		}

		export_entry = __zstats_export_entry_get_by_address(share_entry, name, p-name);
		
		if(export_entry!=NULL)
			break;

		name = p+1;
	}

	return export_entry;
}

static struct zstats_export_entry* __zstats_export_entry_get_by_svc_export(const struct svc_export *fh_export)
{
	const struct auth_domain *ex_client = NULL;
	struct zstats_share_entry *share_entry = NULL;
	struct zstats_export_entry *export_entry = NULL;
	char *share_path = NULL;
	int rc;

	if (fh_export == NULL) {
		zprintk(KERN_DEBUG, "fh_export == NULL\n");
		return NULL;
	}

	ex_client = fh_export->ex_client;
	if (ex_client == NULL) {
		zprintk(KERN_DEBUG, "fh_export->ex_client == NULL\n");
		return NULL;
	}

	rc = __zstats_export_get_dpath(fh_export, &share_path);
	if (rc != 0)
		return NULL;

	share_entry = __zstats_share_get(share_path);
	if (share_entry == NULL) {
		zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: share not found\n", share_path, ex_client->name);
		return NULL;
	}

	export_entry = __zstats_export_entry_get_by_auth_domain(share_entry, ex_client);
	if (export_entry == NULL) {
		zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: export not found\n", share_entry->share_path, ex_client->name);
		return NULL;
	}

	return export_entry;
}

////////////////////////////////////////////////////////////////
///
///	EXPORTS

static int zstats_export_add(const char *share_path, const char *address)
{
	struct zstats_share_entry *share_entry;
	struct zstats_export_entry *export_entry;
	int	rc;

	mutex_lock(&zstats_mutex);

	share_entry = __zstats_share_get(share_path);
	if (share_entry == NULL) {
		zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: share not found\n", share_path, address);
		rc = -ENOENT;
		goto cleanup;
	}

	zprintk(KERN_INFO, "Share[%s]: Export[%s]: add\n", share_entry->share_path, address);

	export_entry = __zstats_export_entry_get_by_address(share_entry, address, -1);
	if (export_entry!=NULL) {
		zprintk(KERN_ERR, "Share[%s]: Export[%s]: already exists\n", share_entry->share_path, address);
		rc = -EEXIST;
		goto cleanup;
	}
	
	export_entry = __zstats_export_entry_ctor(share_entry, address);
	if (export_entry==NULL) {
		rc = -ENOMEM;
		goto cleanup;
	}

	list_add(&export_entry->lnode, &share_entry->exports);
	rc = 0;
	
cleanup:
	mutex_unlock(&zstats_mutex);

	return rc;
}

static int zstats_export_del(const char *share_path, const char *address)
{
	struct zstats_share_entry *share_entry;
	struct zstats_export_entry *export_entry;
	int	rc;

	mutex_lock(&zstats_mutex);

	share_entry = __zstats_share_get(share_path);
	if (share_entry == NULL) {
		zprintk(KERN_DEBUG, "Share[%s]: Export[%s]: share not found\n", share_path, address);
		rc = -ENOENT;
		goto cleanup;
	}

	zprintk(KERN_INFO, "Share[%s]: Export[%s]: delete\n", share_entry->share_path, address);

	export_entry = __zstats_export_entry_get_by_address(share_entry, address, -1);
	if (export_entry==NULL) {
		zprintk(KERN_ERR, "Share[%s]: Export[%s]: export not found\n", share_entry->share_path, address);
		rc = -ENOENT;
		goto cleanup;
	}

	list_del(&export_entry->lnode);
	__zstats_export_entry_dtor(export_entry);
	rc = 0;

cleanup:
	mutex_unlock(&zstats_mutex);
	return rc;
}

static int __zstats_export_get_dpath(const struct svc_export *fh_export, char **path)
{
	const struct auth_domain *ex_client = fh_export->ex_client;
	const struct path *ex_path = &fh_export->ex_path;
	char *p;
	int rc;
	
	p = d_path(ex_path, zstats_global.dpath_buf, PAGE_SIZE);
	if (IS_ERR(p)) {
		rc = PTR_ERR(p);
		zprintk(KERN_ERR, "Export[%s]: d_path() failed, rc=%d\n", ex_client->name, rc);
		return rc;
	}

	*path = p;
	return 0;
}

////////////////////////////////////////////////////////////////
///
///	REQUESTS

static struct zstats_svc_rqst *__zstats_svc_rqst_find(const struct svc_rqst *rqst);
static zstats_bucket_t svc_rqst_get_zstats_bucket(const struct svc_rqst *rqst);
static unsigned long long svc_rqst_get_bytes(const struct svc_rqst *rqst);
static const struct nfsd4_op *__zstats_svc_rqst_get_v4_compound_op(const struct svc_rqst *rqst);

#define zprint_svc_rqst(log_level, rqst, format, ...)																											\
do {																																							\
	const struct nfsd4_op *_op = __zstats_svc_rqst_get_v4_compound_op((rqst));																					\
	if (likely(_op != NULL))																																	\
		zprintk(log_level, "Request[%p, rq_vers=%d, rq_proc=%d, opnum=%d]: " format, (rqst), (rqst)->rq_vers, (rqst)->rq_proc, _op->opnum, ##__VA_ARGS__);		\
	else																																						\
		zprintk(log_level, "Request[%p, rq_vers=%d, rq_proc=%d]: " format, (rqst), (rqst)->rq_vers, (rqst)->rq_proc, ##__VA_ARGS__);							\
} while(0)


unsigned long zstats_svc_rqst_start(const struct svc_rqst *rqst)
{
	struct zstats_svc_rqst *zrqst = NULL;
	struct timeval start_time;
	unsigned long start_time_usec = 0;

	if (likely(rqst->rq_vers == 4 && rqst->rq_proc == NFSPROC4_COMPOUND)) {
		struct nfsd4_compoundres *resp = rqst->rq_resp;
		if (resp->opcnt == 0) {
			// Called from nfsd_dispatch
			return 0;
		}
		else {
			// Called from nfsd4_proc_compound
		}
	}

	mutex_lock(&zstats_mutex);

	zrqst = __zstats_svc_rqst_find(rqst);
	if (unlikely(zrqst != NULL)) {
		zprint_svc_rqst(KERN_ERR, rqst, "already exists\n");
		goto end;
	}

	zrqst = kmalloc(sizeof(struct zstats_svc_rqst), GFP_KERNEL);
	if (unlikely(zrqst == NULL))
		goto end;

	zrqst->rqst = rqst;
	zrqst->export_entry = NULL;
	list_add(&zrqst->lnode, &zstats_global.zrqsts);

	do_gettimeofday(&start_time);
	start_time_usec = (start_time.tv_sec * 1000 * 1000) + start_time.tv_usec;

end:
	mutex_unlock(&zstats_mutex);
	return start_time_usec;
}

void zstats_svc_rqst_set_export(const struct svc_rqst *rqst, const struct svc_export *fh_export)
{
	struct zstats_svc_rqst *zrqst = NULL;
	struct zstats_export_entry *export_entry = NULL;
	zstats_bucket_t bucket;

	mutex_lock(&zstats_mutex);

	zrqst = __zstats_svc_rqst_find(rqst);
	if (unlikely(zrqst == NULL)) {
		zprint_svc_rqst(KERN_ERR, rqst, "not found\n");
		goto end;
	}

	export_entry = __zstats_export_entry_get_by_svc_export(fh_export);

	if (zrqst->export_entry == NULL) {
		if (unlikely(export_entry == NULL)) {
			zprint_svc_rqst(KERN_DEBUG, rqst, "export not found\n");
			goto end;
		}
		zrqst->export_entry = export_entry;
	}
	else {
		if (likely(zrqst->export_entry == export_entry))
			zprint_svc_rqst(KERN_DEBUG, rqst, "Export[%s]: already exists\n", zrqst->export_entry->address);
		else if (export_entry != NULL)
			zprint_svc_rqst(KERN_NOTICE, rqst, "Old Export[%s], New Export[%s]\n", zrqst->export_entry->address, export_entry->address);
		else
			zprint_svc_rqst(KERN_NOTICE, rqst, "Old Export[%s], New Export[NULL]\n", zrqst->export_entry->address);
		goto end;
	}

	bucket = svc_rqst_get_zstats_bucket(rqst);
	zrqst->export_entry->info[bucket].active_ios++;
	zprint_svc_rqst(KERN_DEBUG, rqst, "Export[%s]: bucket=%s, active_ios=%ld\n",
					zrqst->export_entry->address, zstats_bucket_names[bucket], zrqst->export_entry->info[bucket].active_ios);

end:
	mutex_unlock(&zstats_mutex);
}

void zstats_svc_rqst_end(const struct svc_rqst *rqst, __be32 nfserr, unsigned long start_time)
{
	struct zstats_svc_rqst *zrqst = NULL;
	struct zstats_info *info = NULL;
	struct timeval current_time;
	unsigned long long bytes;
	unsigned long duration_usec;
	zstats_bucket_t bucket;

	mutex_lock(&zstats_mutex);

	zrqst = __zstats_svc_rqst_find(rqst);
	if (unlikely(zrqst == NULL)) {
		zprint_svc_rqst(KERN_ERR, rqst, "not found\n");
		goto end;
	}

	if (unlikely(zrqst->export_entry == NULL)) {
		zprint_svc_rqst(KERN_DEBUG, rqst, "export not set, nfserr=%d\n", be32_to_cpu(nfserr));
		goto end;
	}

	do_gettimeofday(&current_time);
	duration_usec = ((current_time.tv_sec * 1000 * 1000) + current_time.tv_usec) - start_time;

	bucket = svc_rqst_get_zstats_bucket(rqst);
	info = &zrqst->export_entry->info[bucket];

	info->ios++;
	info->active_ios--;

	if (likely(nfserr == nfs_ok)) {
		bytes = svc_rqst_get_bytes(rqst);
	}
	else {
		zprint_svc_rqst(KERN_DEBUG, rqst, "nfserr=%d\n", be32_to_cpu(nfserr));
		info->errors++;
		bytes = 0;
	}
	info->bytes += bytes;

	info->total_resp_time_usec += duration_usec;
	if (unlikely(info->max_resp_time_usec < duration_usec)) {
		const struct nfsd4_op *op;
		info->max_resp_time_usec = duration_usec;
		op = __zstats_svc_rqst_get_v4_compound_op(rqst);
		if (likely(op!=NULL))
			info->max_op_code = (rqst->rq_vers<<16) + (rqst->rq_proc<<8) + (op->opnum);
		else
			info->max_op_code = (rqst->rq_vers<<16) + (rqst->rq_proc<<8);
	}

	zprint_svc_rqst(KERN_DEBUG, rqst, "Export[%s]: bucket=%s, duration_usec=%lu, bytes=%llu, active_ios=%ld\n",
					zrqst->export_entry->address, zstats_bucket_names[bucket], duration_usec, bytes, info->active_ios);

end:
	if (likely(zrqst != NULL)) {
		list_del(&zrqst->lnode);
		kfree(zrqst);
	}

	mutex_unlock(&zstats_mutex);
}

static struct zstats_svc_rqst *__zstats_svc_rqst_find(const struct svc_rqst *rqst)
{
	struct zstats_svc_rqst *zrqst = NULL;

	list_for_each_entry(zrqst, &zstats_global.zrqsts, lnode) {
		if (zrqst->rqst == rqst)
			return zrqst;
	}

	return NULL;
}

static zstats_bucket_t svc_rqst_get_zstats_bucket(const struct svc_rqst *rqst)
{
	if (likely(rqst->rq_vers == 4)) {
		const struct nfsd4_op *op = __zstats_svc_rqst_get_v4_compound_op(rqst);
		if (unlikely(op == NULL))
			return ZSTATS_BUCKET_OTHERS;

		switch (op->opnum) {
		case OP_OPEN:		return op->u.open.op_create ? ZSTATS_BUCKET_CREATE : ZSTATS_BUCKET_OTHERS;
		case OP_CREATE:		return op->u.create.cr_type==NF4DIR || op->u.create.cr_type==NF4LNK ? ZSTATS_BUCKET_CREATE : ZSTATS_BUCKET_OTHERS;
		case OP_LINK:		return ZSTATS_BUCKET_CREATE;
		case OP_REMOVE:		return ZSTATS_BUCKET_DELETE;
		case OP_RENAME:		return ZSTATS_BUCKET_RENAME;
		case OP_READ:		return ZSTATS_BUCKET_READ;
		case OP_WRITE:		return ZSTATS_BUCKET_WRITE;
		case OP_COMMIT:		return ZSTATS_BUCKET_FLUSH;
		case OP_LOCK:		return ZSTATS_BUCKET_LOCK;
		case OP_LOCKU:		return ZSTATS_BUCKET_UNLOCK;

		case OP_ACCESS:
		case OP_GETATTR:
		case OP_OPENATTR:
		case OP_NVERIFY:
		case OP_LOCKT:
		case OP_VERIFY:		return ZSTATS_BUCKET_GETATTR;
		case OP_SETATTR:	return ZSTATS_BUCKET_SETATTR;
		
		case OP_READDIR:	return ZSTATS_BUCKET_READDIR;
		
		default:			return ZSTATS_BUCKET_OTHERS;
		}
	}
	else if (likely(rqst->rq_vers == 3)) {
		switch (rqst->rq_proc) {
		case NFS3PROC_CREATE:
		case NFS3PROC_MKDIR:
		case NFS3PROC_SYMLINK:
		case NFS3PROC_LINK:			return ZSTATS_BUCKET_CREATE;

		case NFS3PROC_REMOVE:
		case NFS3PROC_RMDIR:		return ZSTATS_BUCKET_DELETE;

		case NFS3PROC_RENAME:		return ZSTATS_BUCKET_RENAME;

		case NFS3PROC_READ:			return ZSTATS_BUCKET_READ;
		case NFS3PROC_WRITE:		return ZSTATS_BUCKET_WRITE;
		case NFS3PROC_COMMIT:		return ZSTATS_BUCKET_FLUSH;

		case NFS3PROC_GETATTR:
		case NFS3PROC_ACCESS:
		case NFS3PROC_FSSTAT:
		case NFS3PROC_FSINFO:
		case NFS3PROC_PATHCONF:		return ZSTATS_BUCKET_GETATTR;

		case NFS3PROC_SETATTR:		return ZSTATS_BUCKET_SETATTR;

		case NFS3PROC_READDIR:
		case NFS3PROC_READDIRPLUS:	return ZSTATS_BUCKET_READDIR;

		default:					return ZSTATS_BUCKET_OTHERS;
		}
	}
	else if (likely(rqst->rq_vers == 2)) {
		switch (rqst->rq_proc) {
		case NFSPROC_CREATE:
		case NFSPROC_MKDIR:
		case NFSPROC_SYMLINK:
		case NFSPROC_LINK:			return ZSTATS_BUCKET_CREATE;

		case NFSPROC_REMOVE:
		case NFSPROC_RMDIR:			return ZSTATS_BUCKET_DELETE;

		case NFSPROC_RENAME:		return ZSTATS_BUCKET_RENAME;

		case NFSPROC_READ:			return ZSTATS_BUCKET_READ;
		case NFSPROC_WRITE:			return ZSTATS_BUCKET_WRITE;
		case NFSPROC_WRITECACHE:	return ZSTATS_BUCKET_FLUSH;

		case NFSPROC_GETATTR:
		case NFSPROC_STATFS:		return ZSTATS_BUCKET_GETATTR;

		case NFSPROC_SETATTR:		return ZSTATS_BUCKET_SETATTR;

		case NFSPROC_READDIR:		return ZSTATS_BUCKET_READDIR;

		default:					return ZSTATS_BUCKET_OTHERS;
		}
	}
	else {
		return ZSTATS_BUCKET_OTHERS;
	}
}

static unsigned long long svc_rqst_get_bytes(const struct svc_rqst *rqst)
{
	if (likely(rqst->rq_vers == 4)) {
		const struct nfsd4_compoundres *resp = rqst->rq_resp;
		const struct nfsd4_op *op = __zstats_svc_rqst_get_v4_compound_op(rqst);
		if (unlikely(op == NULL))
			return 0;
		if (op->opnum == OP_READ)
			return resp->xdr.buf->page_len;
		else if (op->opnum == OP_WRITE)
			return op->u.write.wr_bytes_written;
		else
			return 0;
	}
	else if (likely(rqst->rq_vers == 3)) {
		if (rqst->rq_proc == NFS3PROC_READ)
			return ((struct nfsd3_readres*)(rqst->rq_resp))->count;
		else if (rqst->rq_proc == NFS3PROC_WRITE)
			return ((struct nfsd3_writeres*)(rqst->rq_resp))->count;
		else
			return 0;
	}
	else if (likely(rqst->rq_vers == 2)) {
		if (rqst->rq_proc == NFSPROC_READ)
			return ((struct nfsd_readres*)(rqst->rq_resp))->count;
		else if (rqst->rq_proc == NFSPROC_WRITE)
			return ((struct nfsd_writeargs*)(rqst->rq_resp))->len;
		else
			return 0;
	}
	else {
		return 0;
	}
}

static const struct nfsd4_op *__zstats_svc_rqst_get_v4_compound_op(const struct svc_rqst *rqst)
{
	const struct nfsd4_op *op = NULL;

	if (likely(rqst->rq_vers == 4 && rqst->rq_proc == NFSPROC4_COMPOUND)) {
		struct nfsd4_compoundargs *args = rqst->rq_argp;
		struct nfsd4_compoundres *resp = rqst->rq_resp;

		if (likely(resp->opcnt > 0))
			op = &args->ops[resp->opcnt-1];
		else
			__WARN();
	}

	return op;
}




int zstats_export_get_zshareid(const struct svc_export *fh_export, u64 *share_id)
{
	char *share_path;
	int	rc;

	mutex_lock(&zstats_mutex);

	rc = __zstats_export_get_dpath(fh_export, &share_path);
	if (rc!=0)
		goto cleanup;

	rc = __zstats_export_get_zshareid(share_path, share_id);

cleanup:
	mutex_unlock(&zstats_mutex);
	return rc;
}

static int __zstats_export_get_zshareid(const char *share_path, u64 *share_id)
{
	const struct zstats_share_entry *share_entry;

	share_entry = __zstats_share_get(share_path);
	if (share_entry == NULL) {
		zprintk(KERN_ERR, "Share[%s]: not found\n", share_path);
		return -ENOENT;
	}

	*share_id = share_entry->share_id;
	return 0;
}
