#ifndef __ZUTILS_KLOG_HDR__
#define __ZUTILS_KLOG_HDR__

#include <linux/sched.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/ratelimit.h>

/************ BUG() handling ************************************/
#ifdef CONFIG_DEBUG_BUGVERBOSE
#define bug_dump_stack()
#else
#define bug_dump_stack()	dump_stack();
#endif

/* Redefine BUG and BUG_ON to do panic */
#ifdef BUG
#undef BUG
#endif
#define BUG() do {				\
	zklog(Z_KERR, "BUG!\n");	\
	bug_dump_stack();			\
	panic("BUG!");				\
} while(0)

#ifdef BUG_ON
#undef BUG_ON
#endif
#define BUG_ON(condition) do {					\
	if (unlikely(condition)) {					\
		zklog(Z_KERR, "BUG: " #condition "\n");	\
		bug_dump_stack();						\
		panic("BUG: " #condition);				\
	}											\
} while(0)


/************ UUID handling ***************************************/
#define PRIx128	"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define PRIX128	"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"

#define UUID_SIZE 16

#define PRI_UUID(uuid)	((u8*)(uuid))[0],  ((u8*)(uuid))[1],  ((u8*)(uuid))[2],  ((u8*)(uuid))[3],	\
						((u8*)(uuid))[4],  ((u8*)(uuid))[5],  ((u8*)(uuid))[6],  ((u8*)(uuid))[7],	\
						((u8*)(uuid))[8],  ((u8*)(uuid))[9],  ((u8*)(uuid))[10], ((u8*)(uuid))[11],	\
						((u8*)(uuid))[12], ((u8*)(uuid))[13], ((u8*)(uuid))[14], ((u8*)(uuid))[15]

static const u8 ZERO_UUID[UUID_SIZE] = {0};

/************ Logging ********************************************/

/* Log level:
      76543210 76543210 76543210 76543210
      ___flags ________ ________ ______pr
*/

/* Priority */
enum zklog_level_t {
	Z_KNOTE = 1,						/**< important message		*/
	Z_KINFO,							/**< regular message		*/
	Z_KDEB1,							/**< debug message			*/
	Z_KDEB2,							/**< noisy debug message	*/

	Z_K_LEVEL_QUIET = 0,                        /* use this to set the log level of a tag - which will shut off all the prints with this tag */
	Z_K_LEVEL_MIN   = Z_KNOTE,
	Z_K_LEVEL_MAX   = Z_KDEB2,
	Z_K_LEVEL_QUIET_PRINT = Z_K_LEVEL_MAX + 1, /* use this with zklog/zklog_tag etc macros, to NOT see the print regardless of the tag's log level */
};

#define ZKLOG_PRIO_MASK 0x000000FF

/* Flags */
#define ZKLOG_FLAGS_SHIFT        24
#define ZKLOG_FLAGS_MASK 0xFF000000

#define Z_BADPATH               (0x01 << ZKLOG_FLAGS_SHIFT)      /**< Logging of the bad path */                              

#define Z_KWARN Z_BADPATH|Z_KINFO
#define Z_KERR  Z_BADPATH|Z_KNOTE

/************* registering/unregistering from logging **********************/
#define ZKLOG_MAX_TAGS 64

struct zklog_module_ctx {
	struct kobject kobj;

	const char *module_name;
	
	struct zklog_tag_entry {
		const char *short_name;
		const char *long_name;
		enum zklog_level_t level;
		struct attribute attr;
	} tags[ZKLOG_MAX_TAGS];
};

/*
 * Each module registering with zklog must define a global variable of this type, named ZKLOG_THIS_MODULE_CTX.
 */
extern struct zklog_module_ctx *ZKLOG_THIS_MODULE_CTX;

/*
 * Registering a module with zklog, should be done in module_init() function.
 * This function registers a default debug tag with the specified default debug level.
 */
#define zklog_register_module(default_level)                                                \
({                                                                                          \
	int __ret = 0;                                                                          \
	if (ZKLOG_THIS_MODULE_CTX != NULL)                                                      \
		__ret = -EEXIST;                                                                    \
	else {                                                                                  \
		ZKLOG_THIS_MODULE_CTX = __zklog_register_module(module_name(THIS_MODULE), default_level);  \
		if (ZKLOG_THIS_MODULE_CTX == NULL)                                                  \
			__ret = -ENOMEM;                                                                \
	}                                                                                       \
	__ret;                                                                                  \
})                                                                                          \

extern struct zklog_module_ctx* __zklog_register_module(const char *module_name, enum zklog_level_t default_level);

/*
 * Unregistering a module, should be done in module_exit() function.
 */
#define zklog_unregister_module()                          \
({                                                         \
	if (ZKLOG_THIS_MODULE_CTX != NULL) {                   \
		__zklog_unregister_module(ZKLOG_THIS_MODULE_CTX);  \
		ZKLOG_THIS_MODULE_CTX = NULL;                      \
	}                                                      \
})                                                         \

extern void __zklog_unregister_module(struct zklog_module_ctx *ctx);

/*
 * Adding tags, beyond the default tag.
 * The tag name strings are not copied, so must be constant.
 * The function is not thread-safe, so best to be called from module_init().
 */
#define zklog_add_tag(short_name, long_name, default_level, out_tag) __zklog_add_tag(ZKLOG_THIS_MODULE_CTX, short_name, long_name, default_level, out_tag)

/* Tag values are >0, while zero is "unknown" */
typedef u8 zklog_tag_t;
#define ZKLOG_DEFAULT_TAG 1

extern int __zklog_add_tag(struct zklog_module_ctx *ctx, const char *short_name, const char *long_name, enum zklog_level_t default_level, zklog_tag_t *out_tag);

/*
 * Logging messages, with/without tags.
 */
#define zklog(level, fmt, ...)			__zklog_print_default_tag(ZKLOG_THIS_MODULE_CTX, level, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define zklog_tag(level, tag, fmt, ...)	__zklog_print_tag(ZKLOG_THIS_MODULE_CTX, level, tag, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#ifdef CONFIG_PRINTK
#define zklog_ratelimited(level, fmt, ...) 			\
({													\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
													\
	if (__ratelimit(&_rs))							\
		__zklog_print_default_tag(ZKLOG_THIS_MODULE_CTX, level, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__); \
})

#define zklog_tag_ratelimited(level, tag, fmt, ...)				\
({													\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
													\
	if (__ratelimit(&_rs))							\
		__zklog_print_tag(ZKLOG_THIS_MODULE_CTX, level, tag, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);	\
})

#else
#define zklog_ratelimited(level, fmt, ...)			__zklog_print_default_tag(ZKLOG_THIS_MODULE_CTX, level, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define zklog_tag_ratelimited(level, tag, fmt, ...)	__zklog_print_tag(ZKLOG_THIS_MODULE_CTX, level, tag, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#endif

/****** in-rcu logging ******************************/
#define zklog_in_rcu(level, fmt, ...)       \
	rcu_read_lock();                        \
	zklog((level), (fmt), ##__VA_ARGS__);   \
	rcu_read_unlock();

#define zklog_tag_in_rcu(level, tag, fmt, ...)          \
	rcu_read_lock();                                    \
	zklog_tag((level), (tag), (fmt), ##__VA_ARGS__);    \
	rcu_read_unlock();

#define zklog_ratelimited_in_rcu(level, fmt, ...)       \
	rcu_read_lock();                                    \
	zklog_ratelimited((level), (fmt), ##__VA_ARGS__);   \
	rcu_read_unlock();

#define zklog_tag_ratelimited_in_rcu(level, tag, fmt, ...)        \
	rcu_read_lock();                                              \
	zklog_tag_ratelimited((level), (tag), (fmt), ##__VA_ARGS__);  \
	rcu_read_unlock();


/**** useful, when you don't want some code to be evaluated *************/
#define zklog_will_print(level)                        zklog_will_print_tag(level,ZKLOG_DEFAULT_TAG)
#define zklog_will_print_tag(level, tag)               __zklog_will_print_tag(ZKLOG_THIS_MODULE_CTX, level, tag)
#define __zklog_will_print_tag(module_ctx, log_level, tag) ((log_level & ZKLOG_PRIO_MASK) <= module_ctx->tags[tag - 1].level)

/****** actual logging functions *******************************/

#ifdef CONFIG_PRINTK
__printf(6, 7)
static inline void __zklog_print_default_tag(struct zklog_module_ctx *ctx,
                  enum zklog_level_t level,
                  const char *filename, const char *func, int line,
                  const char *fmt, ...)
{
	BUG_ON(ctx == NULL);

	if (__zklog_will_print_tag(ctx, level, ZKLOG_DEFAULT_TAG)) {
		va_list args;
		struct va_format vaf;

		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;

		printk(KERN_INFO"[%d]%s%s[%s:%d] %pV\n", current->pid, ctx->module_name, (level & Z_BADPATH) ? "*" : " ", func, line, &vaf);

		va_end(args);
	}
}

__printf(7, 8)
static inline void __zklog_print_tag(struct zklog_module_ctx *ctx,
                  enum zklog_level_t level, zklog_tag_t tag,
                  const char *filename, const char *func, int line,
                  const char *fmt, ...)
{
	BUG_ON(ctx == NULL || tag == 0 || tag > ZKLOG_MAX_TAGS);

	if (__zklog_will_print_tag(ctx, level, tag)) {
		va_list args;
		struct va_format vaf;

		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;

		printk(KERN_INFO"[%d][%s]%s%s[%s:%d] %pV\n", current->pid, ctx->tags[tag - 1].short_name, ctx->module_name, (level & Z_BADPATH) ? "*" : " ", func, line, &vaf);

		va_end(args);
	}
}

/* 
 * This is used to unconditionally print a log message, in situations where zklog has been unregistered already or failed to register, etc. 
 * kern_level is the normal KERN_INFO or KERN_ERR etc.
*/
#define ZKLOG_RAW_LOG(kern_level, fmt, ...) printk(kern_level"%s:[%s] "fmt"\n", module_name(THIS_MODULE), __FUNCTION__, ##__VA_ARGS__)

#else /* CONFIG_PRINTK */
static inline void __zklog_print_default_tag(struct zklog_module_ctx *ctx,
                  enum zklog_level_t level,
                  const char *filename, const char *func, int line,
                  const char *fmt, ...)
{
}

static inline void __zklog_print_tag(struct zklog_module_ctx *ctx,
                  enum zklog_level_t level, zklog_tag_t tag,
                  const char *filename, const char *func, int line,
                  const char *fmt, ...)
{
}

#define ZKLOG_RAW_LOG(kern_level, fmt, ...)

#endif /* CONFIG_PRINTK */


#endif /* __ZUTILS_KLOG_HDR__ */

