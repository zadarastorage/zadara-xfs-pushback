#include <linux/version.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "zklog.h"

/* 
 * All modules registered with zklog will have their zklog sysfs
 * entries under this object.
 */
static struct kobject *zklog_root_kobj = NULL;

static int add_tag_to_slot(struct zklog_module_ctx *ctx, unsigned int slot,
                           const char *short_name, const char *long_name,
                           enum zklog_level_t default_level)
{
	int ret = 0;
	struct zklog_tag_entry *tag = &ctx->tags[slot];

	/* Initialize the attribute and add to sysfs */
	sysfs_attr_init(&tag->attr); /* keep lockep happy */
	tag->attr.name = long_name;
	tag->attr.mode = S_IRUGO|S_IWUSR;
	ret = sysfs_create_file(&ctx->kobj, &tag->attr);
	if (ret != 0) {
		ZKLOG_RAW_LOG(KERN_ERR, "sysfs_create_file() failed for [%s], tag [%s:%s:%u], ret=%d",
		              ctx->module_name, short_name, long_name, default_level, ret);
		return ret;
	}

	tag->short_name = short_name;
	tag->long_name = long_name;
	tag->level = default_level;

	ZKLOG_RAW_LOG(KERN_INFO, "Added tag [%s:%s:%u] to slot %u for module [%s]", short_name, long_name, default_level, slot, ctx->module_name);
	return 0;
}

static const char* prio_names[] = {
	[Z_K_LEVEL_QUIET] = "QUIET",
	[Z_KNOTE]         = "Z_KNOTE",
	[Z_KINFO]         = "Z_KINFO",
	[Z_KDEB1]         = "Z_KDEB1",
	[Z_KDEB2]         = "Z_KDEB2"
};

static ssize_t zklog_tag_level_show(struct kobject *kobj, struct attribute *attr, char *buff)
{
	int ret = 0;
	struct zklog_tag_entry *tag = container_of(attr, struct zklog_tag_entry, attr);

	if (tag->level < Z_K_LEVEL_QUIET || tag->level > Z_K_LEVEL_MAX)
		ret = scnprintf(buff, PAGE_SIZE, "??? (%d)\n", tag->level);
	else
		ret = scnprintf(buff, PAGE_SIZE, "%s (%d)\n", prio_names[tag->level], tag->level);

	return ret;
}

static ssize_t zklog_tag_level_store(struct kobject *kobj, struct attribute *attr, const char *buff, size_t buff_size)
{
	int ret = 0;
	enum zklog_level_t level = 0;
	struct zklog_tag_entry *tag = container_of(attr, struct zklog_tag_entry, attr);
	struct zklog_module_ctx *ctx = container_of(kobj, struct zklog_module_ctx, kobj);

	ret = sscanf(buff, "%d", (int*)&level);
	if (ret != 1) {
		/* Perhaps the user gave a textual value */
		for (level = Z_K_LEVEL_QUIET; level <= Z_K_LEVEL_MAX; ++level) {
			if (strncmp(buff, prio_names[level], strlen(prio_names[level])) == 0)
				break;
		}
	}

	if (level < Z_K_LEVEL_QUIET || level > Z_K_LEVEL_MAX) {
		ZKLOG_RAW_LOG(KERN_WARNING, "Invalid level specified for [%s/%s] %.*s", ctx->module_name, tag->long_name, (int)buff_size, buff);
		return -EINVAL;
	}

	ZKLOG_RAW_LOG(KERN_INFO, "Setting level of [%s/%s] to %s(%d)", ctx->module_name, tag->long_name, prio_names[level], level);
	tag->level = level;

	return buff_size;
}

static struct sysfs_ops zklog_module_sysfs_ops  = {
	.show = zklog_tag_level_show,
	.store = zklog_tag_level_store,
};

static void zklog_module_ctx_release(struct kobject *kobj)
{
	if (kobj != NULL) {
		struct zklog_module_ctx *ctx = container_of(kobj, struct zklog_module_ctx, kobj);
		ZKLOG_RAW_LOG(KERN_INFO, "Freeing context of module [%s]", ctx->module_name);
		kfree(ctx);
	}
}

static struct kobj_type zklog_kobj_type = {
	.release = zklog_module_ctx_release,
	.sysfs_ops = &zklog_module_sysfs_ops,
};

/*
 * Creates a new zklog_module_ctx and registers a ZKLOG_DEFAULT_TAG with the default level specified.
 */
struct zklog_module_ctx* __zklog_register_module(const char *module_name, enum zklog_level_t default_level)
{
	int ret = 0;
	struct zklog_module_ctx *ctx = NULL;

	if (default_level < Z_K_LEVEL_MIN || default_level > Z_K_LEVEL_MAX) {
		ZKLOG_RAW_LOG(KERN_ERR, "Invalid default level(%d) for module [%s]", default_level, module_name);
		return NULL;
	}

	ctx = kzalloc(sizeof(struct zklog_module_ctx), GFP_KERNEL);
	if (ctx == NULL) {
		ZKLOG_RAW_LOG(KERN_ERR, "Failed allocating struct zklog_module_ctx, for module [%s]", module_name);
		return NULL;
	}

	ctx->module_name = module_name;

	ret = kobject_init_and_add(&ctx->kobj, &zklog_kobj_type, zklog_root_kobj, "%s", module_name);
	if (ret != 0) {
		ZKLOG_RAW_LOG(KERN_ERR, "kobject_init_and_add() failed, ret=%d", ret);
		kobject_put(&ctx->kobj);
		return NULL;
	}

	ret = add_tag_to_slot(ctx, ZKLOG_DEFAULT_TAG - 1/*slot*/, "", "Default", default_level);
	if (ret != 0) {
		kobject_put(&ctx->kobj);
		return NULL;
	}

	return ctx;
}
EXPORT_SYMBOL(__zklog_register_module);

void __zklog_unregister_module(struct zklog_module_ctx *ctx)
{
	if (ctx != NULL) {
		ZKLOG_RAW_LOG(KERN_INFO, "Unregister module [%s] from logging", ctx->module_name);
		kobject_put(&ctx->kobj);
	}
}
EXPORT_SYMBOL(__zklog_unregister_module);

int __zklog_add_tag(struct zklog_module_ctx *ctx, const char *short_name, const char *long_name, enum zklog_level_t default_level, zklog_tag_t *out_tag)
{
	int ret = 0;
	unsigned int idx = 0;
	
	if (short_name == NULL || long_name == NULL) {
		ZKLOG_RAW_LOG(KERN_ERR, "Tag names must not be NULL: short=%s, long=%s", short_name, long_name);
		ret = -EINVAL;
		goto out;
	}
	if (default_level < Z_K_LEVEL_MIN || default_level > Z_K_LEVEL_MAX) {
		ZKLOG_RAW_LOG(KERN_ERR, "Invalid default level(%d) for [%s/%s]", default_level, ctx->module_name, long_name);
		ret = -EINVAL;
		goto out;
	}

	ret = -ENOMEM; /* Assume no free slots */
	for (idx = 0; idx < ZKLOG_MAX_TAGS; ++idx) {
		if (ctx->tags[idx].short_name == NULL) {
			WARN_ON(ctx->tags[idx].long_name != NULL);
			ret = add_tag_to_slot(ctx, idx/*slot*/, short_name, long_name, default_level);
			if (ret == 0)
				*out_tag = idx + 1;
			break;
		}
	}

out:
	return ret;
}
EXPORT_SYMBOL(__zklog_add_tag);

int zklog_sysfs_init(struct kobject *sysfs_root_kobj)
{
	zklog_root_kobj = kobject_create_and_add("zklog", sysfs_root_kobj);
	if (zklog_root_kobj == NULL) {
		ZKLOG_RAW_LOG(KERN_ERR, "Failed to create zklog root sysfs kobject");
		return -ENOMEM;
	}
	return 0;
}

void zklog_sysfs_exit(void)
{
	if (zklog_root_kobj != NULL) {
		kobject_put(zklog_root_kobj);
		zklog_root_kobj = NULL;
	}
}


