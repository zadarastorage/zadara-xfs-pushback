#ifdef CONFIG_MD_ZADARA

#include <linux/ctype.h>

static int ZDEBUG = Z_KINFO;
module_param_named(ZDEBUG, ZDEBUG, int, S_IWUSR|S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(ZDEBUG, "Zadara debug prints level (1,2,3,4)");

static ssize_t zraid1_preferred_rdev_for_read_show(struct mddev *mddev, char *buff)
{
	ssize_t ret = 0;
	struct r1conf *conf = mddev->private;
	dev_t preferred1 = conf->zpreferred_rdev_for_read1;
	dev_t preferred2 = conf->zpreferred_rdev_for_read2;

	ret += scnprintf(buff + ret, PAGE_SIZE - ret, "%u:%u %u:%u\n",
		            MAJOR(preferred1), MINOR(preferred1),
		            MAJOR(preferred2), MINOR(preferred2));
	ret += scnprintf(buff + ret, PAGE_SIZE - ret, "select preferred: %s\n", atomic_read(&conf->zselect_preferred) == 0 ? "NO" : "YES");

	return ret;
}

static ssize_t zraid1_preferred_rdev_for_read_store(struct mddev *mddev, const char *buff, size_t size)
{
	ssize_t ret = -EINVAL;
	struct r1conf *conf = mddev->private;
	const char *token1 = NULL, *token2 = NULL;
	const char *s = buff;
	unsigned int maj = 0, min = 0;
	dev_t devt1 = 0, devt2 = 0;

	/* skip leading spaces */
	while (*s != '\0' && isspace(*s))
		++s;
	token1 = s;
	/* skip digits and ':' */
	while (*s != '\0' && !isspace(*s)) {
		if (!isdigit(*s) && *s != ':')
			goto out;
		++s;
	}
	/* skip spaces */
	while (*s != '\0' && isspace(*s))
		++s;
	token2 = s;
	/* skip digits and ':' */
	while (*s != '\0' && !isspace(*s)) {
		if (!isdigit(*s) && *s != ':')
			goto out;
		++s;
	}

	if (*token1 != '\0') {
		ret = sscanf(token1, "%u:%u ", &maj, &min);
		if (ret != 2) {
			ret = -EINVAL;
			goto out;
		}
		devt1 = MKDEV((u64)maj, min);
	}
	if (*token2 != '\0') {
		ret = sscanf(token2, "%u:%u ", &maj, &min);
		if (ret != 2) {
			ret = -EINVAL;
			goto out;
		}
		devt2 = MKDEV((u64)maj, min);
	}

	zklog(mdname(mddev), Z_KINFO, "preferred rdev for read: %u:%u (%llu), %u:%u (%llu)",
		  MAJOR(devt1), MINOR(devt1), (u64)devt1,
		  MAJOR(devt2), MINOR(devt2), (u64)devt2);

	/*
	 * if there is no preferred device, first reset
	 * the preferred mode and then reset the devices.
	 * otherwise, change the devices first
	 * (although this doesn't matter much).
	 */
	if (devt1 == 0 && devt2 == 0)
		atomic_set(&conf->zselect_preferred, 0);
	conf->zpreferred_rdev_for_read1 = devt1;
	conf->zpreferred_rdev_for_read2 = devt2;
	if (devt1 != 0 || devt2 != 0)
		atomic_set(&conf->zselect_preferred, 1);

	ret = size;

out:
	if (ret < 0)
		zklog(mdname(mddev), Z_KERR, "failed parsing: %s", buff);

	return ret;
}

static struct md_sysfs_entry zraid1_preferred_rdev_for_read = 
	__ATTR(zpreferred_rdev_for_read, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH,
			zraid1_preferred_rdev_for_read_show,
			zraid1_preferred_rdev_for_read_store);

static struct attribute* zraid1_attrs[] = {
	&zraid1_preferred_rdev_for_read.attr,
	NULL
};

static struct attribute_group zraid1_attr_group = {
	.name = NULL,
	.attrs = zraid1_attrs
};

static void zraid1_start_sysfs(struct mddev *mddev)
{
	int ret = 0;
	struct r1conf *conf = mddev->private;

	if (mddev->to_remove == &zraid1_attr_group) {
		zklog(mdname(mddev), Z_KWARN, "mddev->to_remove is already set!");
		mddev->to_remove = NULL;
		goto out;
	}
	if (mddev->kobj.sd == NULL) {
		zklog(mdname(mddev), Z_KWARN, "mddev->kobj.sd is NULL!");
		goto out;
	}

	/* before we add our attributes, let's set their default values */
	atomic_set(&conf->zselect_preferred, 0);
	conf->zpreferred_rdev_for_read1 = 0;
	conf->zpreferred_rdev_for_read2 = 0;

	ret = sysfs_create_group(&mddev->kobj, &zraid1_attr_group);
	if (ret)
		zklog(mdname(mddev), Z_KERR, "sysfs_create_group() failed, ret=%d", ret);

out:
	return;
}

static void zraid1_stop_sysfs(struct mddev *mddev)
{
	mddev->to_remove = &zraid1_attr_group;
}


#endif /*CONFIG_MD_ZADARA*/

