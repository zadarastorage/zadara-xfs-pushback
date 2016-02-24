#ifndef __ZUTILS_INT_HDR__
#define __ZUTILS_INT_HDR__

int zklog_sysfs_init(struct kobject *sysfs_root_kobj);
void zklog_sysfs_exit(void);

int zkmsg_dump_register(void);
void zkmsg_dump_unregister(void);

int zchrdev_init(void);
void zchrdev_exit(void);

#endif /*__ZUTILS_INT_HDR__*/

