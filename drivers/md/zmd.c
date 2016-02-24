#ifdef CONFIG_MD_ZADARA

int ZDEBUG = Z_KINFO;
module_param_named(ZDEBUG, ZDEBUG, int, S_IWUSR|S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(ZDEBUG, "Zadara debug prints level (1,2,3,4)");

#endif /*CONFIG_MD_ZADARA*/

