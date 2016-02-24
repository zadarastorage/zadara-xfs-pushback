#include <linux/module.h>
#include <linux/init.h>
#include <linux/device-mapper.h>
#include <config/blk/dev/dm.h>

#include "zutils_int.h"
#include "zklog.h"

struct kobject *kernel_zadara_kobj = NULL;
EXPORT_SYMBOL(kernel_zadara_kobj);

struct zklog_module_ctx *ZKLOG_THIS_MODULE_CTX = NULL;

int __init zutils_init(void)
{
	int	rc = 0;

	kernel_zadara_kobj = kobject_create_and_add("zadara", kernel_kobj);
	if (unlikely(kernel_zadara_kobj == NULL)) {
		ZKLOG_RAW_LOG(KERN_ERR, "kobject_create_and_add(zadara) failed\n");
		rc = -ENOMEM;
		goto err;
	}

	rc = zklog_sysfs_init(kernel_zadara_kobj);
	if (unlikely(rc != 0))
		goto err;

	rc = zklog_register_module(Z_KINFO);
	if (unlikely(rc != 0))
		goto err_zklog_sysfs_exit;

	rc = zkmsg_dump_register();
	if (unlikely(rc != 0))
		goto err_zklog_unreg_module;

	rc = zchrdev_init();
	if (unlikely(rc != 0))
		goto err_zkmsg_dump_unreg;

	zklog(Z_KINFO, "zadara-utils init");

	return 0;

err_zkmsg_dump_unreg:
	zkmsg_dump_unregister();
err_zklog_unreg_module:
	zklog_unregister_module();
err_zklog_sysfs_exit:
	zklog_sysfs_exit();
err:
	if (kernel_zadara_kobj != NULL)
		kobject_put(kernel_zadara_kobj);
	return rc;
}

void __exit zutils_exit(void)
{
	zchrdev_exit();
	zkmsg_dump_unregister();
	zklog_unregister_module();
	zklog_sysfs_exit();
	kobject_put(kernel_zadara_kobj);
	ZKLOG_RAW_LOG(KERN_INFO, "zadara-utils exit");
}

module_init(zutils_init);
module_exit(zutils_exit);

MODULE_AUTHOR("Zadara Storage <support@zadarastorage.com>");
MODULE_DESCRIPTION("Misc. utilities");
MODULE_LICENSE("GPL");
