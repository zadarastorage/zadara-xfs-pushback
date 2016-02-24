#ifdef CONFIG_MD_ZADARA

/* This file is included directly from raid1.c */

enum {
	Z_KNOTE = 1,
	Z_KINFO = 2,
	Z_KDEB1 = 3,
	Z_KDEB2 = 4,
	Z_KWARN = 1000,
	Z_KERR  = 10001
};

#define zklog_cond(mdname, level, cond, fmt, ...)                                                                          \
do {                                                                                                                       \
	int __cond = !!(cond);                                                                                                 \
	if (unlikely(((level)==Z_KWARN || (level)==Z_KERR || (level)<=ZDEBUG) && __cond)) {                                    \
		char *__prefix = ((level)==Z_KWARN || (level)==Z_KERR) ? "*" : "";                                                 \
		pr_info("[%d]%s-R1%s[%s:%u] "fmt"\n", current->pid, (mdname), __prefix, __FUNCTION__, __LINE__, ##__VA_ARGS__);    \
	}                                                                                                                      \
} while (0)

#define zklog(mdname, level, fmt, ...) zklog_cond(mdname, level, 1, fmt, ##__VA_ARGS__)

#define zklog_cond_rl(mdname, level, cond, fmt, ...)                                                                                   \
do {                                                                                                                                   \
	int __cond = !!(cond);                                                                                                             \
	if (unlikely(((level)==Z_KWARN || (level)==Z_KERR || (level)<=ZDEBUG) && __cond)) {                                                \
		char *__prefix = ((level)==Z_KWARN || (level)==Z_KERR) ? "*" : "";                                                             \
		pr_info_ratelimited("[%d]%s-R1%s[%s:%u] "fmt"\n", current->pid, (mdname), __prefix, __FUNCTION__, __LINE__, ##__VA_ARGS__);    \
	}                                                                                                                                  \
} while (0)

#define zklog_rl(mdname, level, fmt, ...) zklog_cond_rl(mdname, level, 1, fmt, ##__VA_ARGS__)

static int ZDEBUG;

static void zraid1_start_sysfs(struct mddev *mddev);
static void zraid1_stop_sysfs(struct mddev *mddev);

#endif /*CONFIG_MD_ZADARA*/

