#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kmsg_dump.h>
#include <linux/sysrq.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "zklog.h"

#define ZKMSG_DUMP_FILENAME				"/var/log/kmsg_dump"
#define ZKMSG_TICKET_MARKER_FILENAME	"/var/lib/zadara/tickets/panic"

static int zkmsg_dump_phase = 0;
module_param(zkmsg_dump_phase, int, 0644);
MODULE_PARM_DESC(zkmsg_dump_phase, "zkmsg_dump phase - set to 0 initially & upon panic set to indicate that we are under panic");

static void zkmsg_create_ticket_marker(enum kmsg_dump_reason reason);
static void zkmsg_set_syslog_level(void);
static struct file* zkmsg_file_create(const char *filename);
static void zkmsg_file_unlink(struct file *file, const char *filename);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))
typedef void (*kmsg_dump_func)(enum kmsg_dump_reason reason);za
static kmsg_dump_func kmsg_dump_ptr = NULL;
static void zkmsg_write34(struct file *file, const char *s1, unsigned long l1, const char *s2, unsigned long l2, loff_t *off, bool tix);
static void zkmsg_dump_more_info34(enum kmsg_dump_reason reason);
#else
static void zkmsg_write35(struct file *file, struct kmsg_dumper *dumper, loff_t *off, bool tix);
static void zkmsg_dump_info35_phase1(enum kmsg_dump_reason reason);
static void zkmsg_dump_info35_phase2(void);
#endif

typedef int (*sys_unlink_func)(const char __user *path);
static sys_unlink_func sys_unlink_ptr = NULL;

static char kmsg_dump_filename[256] = "";
static struct file *kmsg_dump_file = NULL;
static char ticket_marker_filename[256] = "";
static struct file *ticket_marker_file = NULL;
static loff_t ticket_marker_file_off = 0;

static const char* kmsg_dump_reason_to_str[] = {
	[KMSG_DUMP_PANIC]	= "panic",
	[KMSG_DUMP_OOPS]	= "oops",
	[KMSG_DUMP_EMERG]	= "emerg",
	[KMSG_DUMP_RESTART]	= "restart",
	[KMSG_DUMP_HALT]	= "halt",
	[KMSG_DUMP_POWEROFF]= "poweroff",
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))
// kmsg_dump() calls registered dumper callback with pointers to data in the log_buf (static buffer in kernel/printk.c). So if dumper calls printk(), 
// new info appears in log_buf, but dumper doesn't see it, because it has only old pointers. But on panic we may want to callect more info, so...
// 
// Ugly workaround: print whatever is required in phase-1, and then call kmsg_dump(), that will call us again with updated pointers. 
// - kmsg_dump() is not exported function, so we call kallsyms_lookup_name("kmsg_dump") to find it.
// - zkmsg_write() is called twice at both phase-1 and phase-2, because log_buf if a cyclic buffer, so new printk's may overwrite 
//   old important messages. But if new printk's produce few messages, older messages may appear twice in the dump file.
// - All dumpers are called twice. Our dumper is designed for that, but others not
static void zkmsg_dump(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason, const char *s1, unsigned long l1, const char *s2, unsigned long l2)
{
	static int phase = 1;
	static loff_t off = 0;

	void *old_journal_info = NULL;

	zkmsg_dump_phase = phase;

	if(phase==1) {
		// If current->journal_info != NULL, root fs (ext4) may try to use it, although it can be journal_info from another fs (btrfs)
		old_journal_info = current->journal_info;
		current->journal_info = NULL;

		off = 0;

		if(reason==KMSG_DUMP_PANIC)
			zkmsg_create_ticket_marker(reason);

		zkmsg_write34(kmsg_dump_file, s1, l1, s2, l2, &off, (reason==KMSG_DUMP_PANIC)/*tix*/);

		if(reason==KMSG_DUMP_PANIC) {
			if(kmsg_dump_ptr!=NULL) {
				zkmsg_dump_more_info34(reason);
				phase = 2;
				kmsg_dump_ptr(reason);	// kmsg_dump
			}
		}

		current->journal_info = old_journal_info;
	}
	else {
		zkmsg_write34(kmsg_dump_file, s1, l1, s2, l2, &off, false/*tix*/);
		phase = 1;
	}
}
#else
// panic() calls smp_send_stop(), that on x86 architecture calls disable_local_APIC(). But we need APIC for file I/O.
// Workaround: boot with option reboot=f[orce], that avoid anything that could hang including disable_local_APIC()
static void zkmsg_dump(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason)
{
	void *old_journal_info = NULL;
	bool irq = false;
	loff_t off = 0;

	zkmsg_dump_phase++;

//#define LOG_CONTEXT(in_ctx)	zklog(Z_KERR, "%s = %d", #in_ctx, (int)in_ctx())
//    LOG_CONTEXT(in_irq);
//    LOG_CONTEXT(in_softirq);
//    LOG_CONTEXT(in_interrupt);
//    LOG_CONTEXT(in_serving_softirq);
//    LOG_CONTEXT(in_nmi);
//    LOG_CONTEXT(in_atomic);
//    LOG_CONTEXT(in_atomic_preempt_off);

	// If current->journal_info != NULL, root fs (ext4) may try to use it, although it can be journal_info from another fs (btrfs)
	old_journal_info = current->journal_info;
	current->journal_info = NULL;

	// panic() calls local_irq_disable(), but we need irq handling for file I/O, so enable it here.
	if(irqs_disabled()) {
		irq = true;
		local_irq_enable();
	}

	if(reason==KMSG_DUMP_PANIC) {
		// if we panic'ed due to FS problem, we may get hunged when trying to write to file.
		// On the other hand, we can't just dump everything to the printk buffer, as we're bound to lose 
		// some of the earlier data in this cyclic buffer.
		// Therefore we dump the most importnat data first, aka 'memory' & 'blocked state', hoping that 
		// it will get at least to the console. Only then we start flushing the buffer to file, and continue
		// with the larger amount of data (aka 'state') - issue #5051
		zklog(Z_KERR, "======== ZKMSG_DUMP: START ========");
		zkmsg_set_syslog_level();
		zkmsg_dump_info35_phase1(reason);
		zkmsg_write35(kmsg_dump_file, dumper, &off, false/*tix*/);
		zkmsg_dump_info35_phase2();
		zkmsg_write35(kmsg_dump_file, dumper, &off, true/*tix*/);
		zklog(Z_KERR, "======== ZKMSG_DUMP: END ==========");
		zkmsg_create_ticket_marker(reason);
	}
	else {
		zkmsg_write35(kmsg_dump_file, dumper, &off, false/*tix*/);
	}

	current->journal_info = old_journal_info;
	if(irq)
		local_irq_disable();
}
#endif // #if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))
static void zkmsg_dump_more_info34(enum kmsg_dump_reason reason)
{
	// More important information must be printed the last, because newer prints may overwrite olders.

	zklog(Z_KERR, "\n");
	handle_sysrq('t');	// Show sTate

	zklog(Z_KERR, "\n");
	if(reason>=0 && reason<ARRAY_SIZE(kmsg_dump_reason_to_str))
		zklog(Z_KERR, "======== REASON: %s(%d) ========", kmsg_dump_reason_to_str[reason], reason);
	else
		zklog(Z_KERR, "======== REASON: %d ========", reason);

	zklog(Z_KERR, "\n");
	handle_sysrq('m');	// Show Memory

	zklog(Z_KERR, "\n");
	handle_sysrq('w');	// Show Blocked State
}
#else
static void zkmsg_dump_info35_phase1(enum kmsg_dump_reason reason)
{
	zklog(Z_KERR, "\n");
	if(reason>=0 && reason<ARRAY_SIZE(kmsg_dump_reason_to_str))
		zklog(Z_KERR, "======== REASON: %s(%d) ========", kmsg_dump_reason_to_str[reason], reason);
	else
		zklog(Z_KERR, "======== ZKMSG_DUMP: REASON: %d ===========", reason);

#ifdef CONFIG_MAGIC_SYSRQ
	zklog(Z_KERR, "\n");
	zklog(Z_KERR, "======== ZKMSG_DUMP: MEMORY ===============");
	handle_sysrq('m');	// Show Memory

	zklog(Z_KERR, "\n");
	zklog(Z_KERR, "======== ZKMSG_DUMP: BLOCKED STATE ========");
	handle_sysrq('w');	// Show Blocked State
#endif /* CONFIG_MAGIC_SYSRQ */
}
static void zkmsg_dump_info35_phase2()
{
#ifdef CONFIG_MAGIC_SYSRQ
	zklog(Z_KERR, "\n");
	zklog(Z_KERR, "======== ZKMSG_DUMP: STATE ================");
	handle_sysrq('t');	// Show sTate
#endif /* CONFIG_MAGIC_SYSRQ */
}
#endif // #if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))


static void zkmsg_set_syslog_level()
{
#ifdef CONFIG_MAGIC_SYSRQ
	handle_sysrq('7');
	zklog(Z_KINFO, "Console loglevel changed to 7");
#endif /* CONFIG_MAGIC_SYSRQ */
}


static void zkmsg_create_ticket_marker(enum kmsg_dump_reason reason)
{
	// Print nothing if any file operation fails - nobody can see these prints! :(
	char subj[256] = "";
	char descr[256] = "";
	mm_segment_t oldfs;

	if(ticket_marker_file==NULL)
		return;

	snprintf(subj, sizeof(subj), "VPSA/SN CRASH!!!\n");
	if(reason>=0 && reason<ARRAY_SIZE(kmsg_dump_reason_to_str))
		snprintf(descr, sizeof(descr), "Kernel %s!\n\n", kmsg_dump_reason_to_str[reason]);
	else
		snprintf(descr, sizeof(descr), "Kernel panic, reason=%d\n\n", reason);

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	ticket_marker_file_off = 0;
	ticket_marker_file->f_op->write(ticket_marker_file, subj, strlen(subj), &ticket_marker_file_off);
	ticket_marker_file->f_op->write(ticket_marker_file, descr, strlen(descr), &ticket_marker_file_off);
	vfs_fsync(ticket_marker_file, 0);

	set_fs(oldfs);
}

static struct file* zkmsg_file_create(const char *filename)
{
	struct file *file;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	file = filp_open(filename, O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRUGO);
	if(IS_ERR(file)) {
		zklog(Z_KERR, "filp_open(%s) failed: rc=%ld", filename, PTR_ERR(file));
		file = NULL;
	}

	set_fs(oldfs);

	return file;
}

static void zkmsg_file_unlink(struct file *file, const char *filename)
{
	mm_segment_t oldfs;

	if (file==NULL)
		return;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filp_close(file, current->files);

	if(sys_unlink_ptr!=NULL)
		sys_unlink_ptr(filename);

	set_fs(oldfs);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))
static void zkmsg_write34(struct file *file, const char *s1, unsigned long l1, const char *s2, unsigned long l2, loff_t *off, bool tix)
{
	// Print nothing if any file operation fails - nobody can see these prints! :(
	mm_segment_t oldfs;
	
	if (file==NULL)
		return;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	if(l1!=0)
		file->f_op->write(file, s1, l1, off);
	if(l2!=0)
		file->f_op->write(file, s2, l2, off);

	vfs_fsync(file, 0);

	if (tix && ticket_marker_file != NULL) {
		// store last 4K of logs (~60-70 lines) as ticket description
		unsigned long ticket_file_size = 4096;
		unsigned long w1, w2;
		w2 = min(ticket_file_size, l2);
		ticket_file_size -= w2;
		w1 = min(ticket_file_size, l1);
		ticket_file_size -= w1;
		if (w1 != 0)
			ticket_marker_file->f_op->write(ticket_marker_file, s1+l1-w1, w1, &ticket_marker_file_off);
		if (w2 != 0)
			ticket_marker_file->f_op->write(ticket_marker_file, s2+l2-w2, w2, &ticket_marker_file_off);
		vfs_fsync(ticket_marker_file, 0);
	}
	
	set_fs(oldfs);
}
#else
static void zkmsg_write35(struct file *file, struct kmsg_dumper *dumper, loff_t *off, bool tix)
{
	// Print nothing if any file operation fails - nobody can see these prints! :(
	char line[512] = "";
	mm_segment_t oldfs;
	s64 now_tm;
	size_t len;
	
	if (file==NULL)
		return;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	now_tm = local_clock() / (1000*1000*1000);

	while(kmsg_dump_get_line(dumper, 0/*syslog*/, line, sizeof(line), &len)) {
		file->f_op->write(file, line, len, off);
		if (tix && ticket_marker_file != NULL) {
			// store last 2 seconds of logs as ticket description
			size_t i;
			for (i=0; i<len; i++) {
				if (isdigit(line[i]))
					break;
			}
			if (i != len) {
				s64 line_tm = simple_strtol(line+i, NULL, 10);
				if (now_tm - line_tm < 2)
					ticket_marker_file->f_op->write(ticket_marker_file, line, len, &ticket_marker_file_off);
			}
		}
	}

	vfs_fsync(file, 0);
	if (tix && ticket_marker_file != NULL)
		vfs_fsync(ticket_marker_file, 0);

	set_fs(oldfs);
}
#endif // #if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))

static struct kmsg_dumper zkmsg_dumper = {
	.dump = zkmsg_dump,
};

int zkmsg_dump_register(void)
{
	int rc;
	unsigned long tm;

	rc = kmsg_dump_register(&zkmsg_dumper);
	if(rc!=0) {
		zklog(Z_KERR, "kmsg_dump_register() failed %d", rc);
		return rc;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))
	kmsg_dump_ptr = (kmsg_dump_func)kallsyms_lookup_name("kmsg_dump");
	if(kmsg_dump_ptr==NULL) {
		zklog(Z_KERR, "kallsyms_lookup_name('kmsg_dump') failed");
		// Do not return error here, we can deal without kmsg_dump_ptr
	}
#endif

	sys_unlink_ptr = (sys_unlink_func)kallsyms_lookup_name("sys_unlink");
	if(sys_unlink_ptr==NULL)
		zklog(Z_KERR, "kallsyms_lookup_name('sys_unlink') failed");

	tm = get_seconds();
	
	snprintf(kmsg_dump_filename, sizeof(kmsg_dump_filename), "%s-%ld", ZKMSG_DUMP_FILENAME, tm);
	kmsg_dump_file = zkmsg_file_create(kmsg_dump_filename);

	snprintf(ticket_marker_filename, sizeof(ticket_marker_filename), "%s-%ld", ZKMSG_TICKET_MARKER_FILENAME, tm);
	ticket_marker_file = zkmsg_file_create(ticket_marker_filename);

	return 0;
}

void zkmsg_dump_unregister(void)
{
	zkmsg_file_unlink(kmsg_dump_file, kmsg_dump_filename);
	zkmsg_file_unlink(ticket_marker_file, ticket_marker_filename);

	kmsg_dump_unregister(&zkmsg_dumper);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))
	kmsg_dump_ptr = NULL;
#endif
	sys_unlink_ptr = NULL;
}

