#ifdef CONFIG_BTRFS_ZADARA
#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS

#include "../ctree.h"
#include "../transaction.h"

/*********** helpers ***********************************/
#define CALL_SHOULD_SUCCEED(ret, name)                                \
({                                                                    \
	if (WARN(ret, "Call: %s should succeed, but ret=%d", #name, ret)) \
		goto out;                                                     \
})

#define CALL_SHOULD_FAIL(ret, name)                                     \
({																		\
	if (WARN(ret==0, "Call: %s should fail, but ret=%d", #name, ret)) { \
		ret = -ECANCELED;												\
		goto out;														\
	}																	\
	ret = 0;															\
})

#define COND_SHOULD_HOLD(cond, name)                            \
({																\
	if (WARN(!(cond), "Condition: %s does not hold",  #name)) { \
		ret = -ECANCELED; 									    \
		goto out;												\
	}															\
})

#define VALUE_SHOULD_BE(val, correct_val, name)                               \
({																			  \
	if (WARN((val) != (correct_val), "Value: %s is %llu but should be %llu",  \
	     #name, (u64)val, (u64)correct_val)) {                                \
		ret = -ECANCELED;													  \
		goto out;															  \
	}																		  \
	ret = 0;																  \
})

static int ztenant_test_ensure_fs_clean(struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	struct zbtrfs_ztenant_config *zt_cfg = &fs_info->ztenant_cfg;
	void* results[1];

	VALUE_SHOULD_BE(fs_info->running_transaction, NULL, running_transaction);

	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);

	spin_lock(&zt_cfg->ztenants_lock);
	ret = radix_tree_gang_lookup(&zt_cfg->ztenants_radix, results, 0/*first_index*/, ARRAY_SIZE(results));
	spin_unlock(&zt_cfg->ztenants_lock);
	VALUE_SHOULD_BE(ret, 0, raidx_tree_entries);

	VALUE_SHOULD_BE(atomic_read(&zt_cfg->updaters), 0, zt_cfg->updaters);
	VALUE_SHOULD_BE(atomic_read(&zt_cfg->syncing), 0, zt_cfg->syncing);

out:
	return ret;
}

static int ztenant_config_clean(struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	u32 tenant_id_u32 = 0;
	struct btrfs_trans_handle *trans = NULL;

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "FS[%s]: clean ztenant config", fs_info->sb->s_id);

	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	for (tenant_id_u32 = 0; tenant_id_u32 <= ZBTRFS_ZTENANT_MAX_ID; ++tenant_id_u32) {
		u16 tenant_id = (u16)tenant_id_u32; /* casting is safe */
		u64 bytes_used = 0, bytes_used_synced = 0;

		/* we don't touch the systemID */
		if (tenant_id == ZBTRFS_ZTENANT_SYSTEM_ID)
			continue;

		zbtrfs_ztenant_get_used(fs_info, tenant_id, &bytes_used, &bytes_used_synced);
		ZBTRFS_BUG_ON(bytes_used > LLONG_MAX);
		if (bytes_used > 0) {
			ret = zbtrfs_ztenant_account_usage(fs_info, trans, tenant_id, -(s64)bytes_used);
			CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_account_usage);
		}
	}

	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;

out:
	if (!IS_ERR_OR_NULL(trans))
		btrfs_end_transaction(trans, fs_info->extent_root);
	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "FS[%s]: clean ztenant config done", fs_info->sb->s_id);
	return ret;
}

struct ztenant_test_info {
	u16 tenant_id;
	u64 bytes_used;
};

static int ztenants_verify(struct btrfs_fs_info *fs_info, struct ztenant_test_info *zts, unsigned int num_zts)
{
	int ret = 0;
	u32 tenant_id_u32 = 0;

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: start verify", fs_info->sb->s_id);

	for (tenant_id_u32 = 0; tenant_id_u32 <= ZBTRFS_ZTENANT_MAX_ID; ++tenant_id_u32) {
		u16 tenant_id = (u16)tenant_id_u32; /* casting is safe */
		unsigned int idx = 0;
		u64 bytes_used_should_be = 0, bytes_used = 0, bytes_used_synced = 0;

		/* we don't touch the systemID */
		if (tenant_id == ZBTRFS_ZTENANT_SYSTEM_ID)
			continue;

		/* check if we have any data for this tenant_id */
		for (idx = 0; idx < num_zts; ++idx) {
			if (zts[idx].tenant_id == tenant_id)
				break;
		}
		if (idx < num_zts)
			bytes_used_should_be = zts[idx].bytes_used;

		zbtrfs_ztenant_get_used(fs_info, tenant_id, &bytes_used, &bytes_used_synced);
		VALUE_SHOULD_BE(bytes_used, bytes_used_synced, bytes_used==bytes_used_synced);
		VALUE_SHOULD_BE(bytes_used_should_be, bytes_used, bytes_used_should_be);
	}

out:
	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: verify done", fs_info->sb->s_id);
	return ret;
}

#define ZTENANT_ID_DELTA(idx, ten_id, delta)                                                 \
({                                                                                           \
	zts[(idx)].tenant_id = (ten_id);                                                         \
	COND_SHOULD_HOLD(zts[(idx)].tenant_id != ZBTRFS_ZTENANT_SYSTEM_ID, using_system_tenant); \
                                                                                             \
	ZBTRFS_BUG_ON((delta) < 0 && zts[(idx)].bytes_used <= -(delta));                         \
	zts[(idx)].bytes_used += (delta);                                                        \
	ret = zbtrfs_ztenant_account_usage(fs_info, trans, zts[(idx)].tenant_id, (delta));       \
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_account_usage);                                  \
})

#define ZTENANT_DELTA(idx, delta) ZTENANT_ID_DELTA(idx, 7*(idx), delta)

#define ZTENANT_DEL(idx)                                                                                  \
({                                                                                                        \
	COND_SHOULD_HOLD(zts[(idx)].tenant_id != ZBTRFS_ZTENANT_SYSTEM_ID, using_system_tenant);              \
                                                                                                          \
	ret = zbtrfs_ztenant_account_usage(fs_info, trans, zts[(idx)].tenant_id, -zts[(idx)].bytes_used);     \
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_account_usage);                                               \
	zts[(idx)].tenant_id = ZBTRFS_ZTENANT_SYSTEM_ID;                                                      \
	zts[(idx)].bytes_used = 0;                                                                            \
})

/*********** tests ***********************************/
static int test_fs_ztenant1(struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	struct btrfs_trans_handle *trans = NULL;

	struct ztenant_test_info zts[21] = {{0}};

	ret = ztenant_test_ensure_fs_clean(fs_info);
	/* Do not use CALL_SHOULD_SUCCEED here, it will wipe everything */
	if (ret)
		return ret;

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: add some initial tenant info", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	ZTENANT_DELTA(1, 20);
	ZTENANT_DELTA(4, 70);
	ZTENANT_DELTA(9, 32);
	ZTENANT_DELTA(12, 777);
	ZTENANT_DELTA(13, 321);
	ZTENANT_DELTA(18, 320);
	ZTENANT_DELTA(19, 430);
	ZTENANT_DELTA(20, 239);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: update some existing tenant info", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	ZTENANT_DELTA(9, 8);
	ZTENANT_DELTA(13, -74);
	ZTENANT_DELTA(18, 81);
	ZTENANT_DELTA(19, -429);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: add some new tenants", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));
	
	ZTENANT_DELTA(3, 9999);
	ZTENANT_DELTA(15, 1357);
	ZTENANT_DELTA(16, 631136);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: delete some tenants", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	ZTENANT_DEL(4);
	ZTENANT_DEL(15);
	ZTENANT_DEL(20);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: update some tenants and add new tenants", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	ZTENANT_DELTA(9, -21);     // upd
	ZTENANT_DELTA(16, 164);    // upd
	ZTENANT_DELTA(19, 16);     // upd
	ZTENANT_DELTA(7, 16384);   // add
	ZTENANT_DELTA(5, 5553211); // add
	ZTENANT_DELTA(17, 39211);  // add
	ZTENANT_DELTA(11, 211);    // add

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: update some tenants and delete some tenants", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	ZTENANT_DEL(17);          // del
	ZTENANT_DELTA(12, -77);   // upd
	ZTENANT_DELTA(5, -211);   // upd
	ZTENANT_DELTA(1, 77);     // upd
	ZTENANT_DEL(19);          // del
	ZTENANT_DELTA(9, 19);     // upd
	ZTENANT_DEL(13);          // del

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: add some tenants and delete some tenants", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));
	
	ZTENANT_DEL(18);              // del
	ZTENANT_DELTA(20, 202020);    // add
	ZTENANT_DELTA(19, 17865);     // add and del!
	ZTENANT_DEL(1);               // del
	ZTENANT_DELTA(14, 141414);    // add
	ZTENANT_DEL(19);              // add and del!
	ZTENANT_DELTA(15, 151515);    // add

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: add some tenants, update some tenants and delete some tenants", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	ZTENANT_DELTA(18, 181818); // add
	ZTENANT_DELTA(3, 1);       // upd
	ZTENANT_DELTA(12, 300);    // upd
	ZTENANT_DEL(5);            // del
	ZTENANT_DELTA(10, 101010); // add
	ZTENANT_DEL(9);            // del
	ZTENANT_DELTA(15, -515);   // upd
	ZTENANT_DELTA(2, 22022);   // add

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, ARRAY_SIZE(zts));
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

out:
	if (!IS_ERR_OR_NULL(trans))
		btrfs_end_transaction(trans, fs_info->extent_root);
	if (ret)
		ztenant_config_clean(fs_info);
	else
		ret = ztenant_config_clean(fs_info);
	return ret;
}

static int test_fs_ztenant2(struct btrfs_fs_info *fs_info)
{
	int ret = 0;
	struct btrfs_trans_handle *trans = NULL;

	struct ztenant_test_info *zts = NULL;
	unsigned int num_zts = 0, i = 0;

	ret = ztenant_test_ensure_fs_clean(fs_info);
	/* Do not use CALL_SHOULD_SUCCEED here, it will wipe everything */
	if (ret)
		return ret;

	num_zts = (unsigned int)ZBTRFS_ZTENANT_MAX_ID + 1;
	zts = vzalloc(sizeof(struct ztenant_test_info) * num_zts);
	COND_SHOULD_HOLD(zts != NULL, zts!=NULL);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: add a lot of tenants", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));
	
	for (i = 1; i < 20000; ++i) {
		ZTENANT_ID_DELTA(i*3, i*3, (u64)i*17);
	}

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, num_zts);
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: add a lot of new tenants, update old ones", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	for (i = 1; i < 20000; ++i) {
		ZTENANT_ID_DELTA(i*3 + 1, i*3 + 1, (u64)i*17);
	}
	for (i = 1; i < 20000; ++i) {
		ZTENANT_ID_DELTA(i*3, i*3, 1);
	}

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, num_zts);
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: delete older tenants, update newer ones", fs_info->sb->s_id);
	trans = btrfs_join_transaction(fs_info->extent_root);
	COND_SHOULD_HOLD(!IS_ERR(trans), !IS_ERR(trans));

	for (i = 1; i < 20000; ++i) {
		ZTENANT_DEL(i*3);
	}
	for (i = 1; i < 20000; ++i) {
		ZTENANT_ID_DELTA(i*3 + 1, i*3 + 1, 2);
	}

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "====== FS[%s]: sync, reload and verify", fs_info->sb->s_id);
	ret = btrfs_commit_transaction(trans, fs_info->extent_root);
	CALL_SHOULD_SUCCEED(ret, btrfs_commit_transaction);
	trans = NULL;
	zbtrfs_ztenant_free_config(fs_info);
	ret = zbtrfs_ztenant_load_config(fs_info);
	CALL_SHOULD_SUCCEED(ret, zbtrfs_ztenant_load_config);
	ret = ztenants_verify(fs_info, zts, num_zts);
	CALL_SHOULD_SUCCEED(ret, ztenants_verify);

out:
	if (!IS_ERR_OR_NULL(trans))
		btrfs_end_transaction(trans, fs_info->extent_root);
	if (ret)
		ztenant_config_clean(fs_info);
	else
		ret = ztenant_config_clean(fs_info);
	vfree(zts);
	return ret;
}

static int test_ztenant1(void)
{
	int ret = 0;
	u32 tenant_id_u32 = 0;
	u32 bit = 0;

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "==== Encode and decode all possible tenant IDs");
	for (tenant_id_u32 = 0; tenant_id_u32 <= ZBTRFS_ZTENANT_MAX_ID; ++tenant_id_u32)
	{
		u16 tenant_id = (u16)tenant_id_u32; /* casting is safe */
		u16 tenant_id_decoded = 0;
		u64 ei_flags = BTRFS_EXTENT_FLAG_DATA         |
			           BTRFS_EXTENT_FLAG_TREE_BLOCK   |
			           BTRFS_BLOCK_FLAG_FULL_BACKREF  |
			           BTRFS_EXTENT_FLAG_SUPER;
		u64 ei_flags_encoded = 0;

		// encode
		ret = btrfs_ztenant_id_to_extent_item_flags(ei_flags, tenant_id, &ei_flags_encoded);
		CALL_SHOULD_SUCCEED(ret, btrfs_ztenant_id_to_extent_item_flags);

		// decode
		tenant_id_decoded = btrfs_extent_item_flags_to_ztenant_id(ei_flags_encoded);
		VALUE_SHOULD_BE(tenant_id_decoded, tenant_id, tenant_id);
	}

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "==== Test that any bit already set in tenantID area won't work");
	for (bit = 0; bit < 64; ++bit)
	{
		u64 ei_flags = 0;
		u64 ei_flags_encoded = 0;

		ei_flags = 1ULL << bit;
		ret = btrfs_ztenant_id_to_extent_item_flags(ei_flags, 17/*tenant_id*/, &ei_flags_encoded);
		if (bit >= 24 && bit < 40) {
			CALL_SHOULD_FAIL(ret, btrfs_ztenant_id_to_extent_item_flags);
		} else {
			CALL_SHOULD_SUCCEED(ret, btrfs_ztenant_id_to_extent_item_flags);
		}
	}

out:
	return ret;
}

/*
 * !!!ATTENTION!!!
 * this test writes data to a live FS!!!
 * never run it in production!!!
 */
int zbtrfs_test_fs_ztenant(struct btrfs_fs_info *fs_info)
{
	int ret = 0;

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "FS[%s]: Running test_fs_ztenant1...", fs_info->sb->s_id);
	ret = test_fs_ztenant1(fs_info);
	CALL_SHOULD_SUCCEED(ret, test_fs_ztenant1);

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "FS[%s]: Running test_fs_ztenant2...", fs_info->sb->s_id);
	ret = test_fs_ztenant2(fs_info);
	CALL_SHOULD_SUCCEED(ret, test_fs_ztenant2);

out:
	return ret;
}

int zbtrfs_test_ztenant(void)
{
	int ret = 0;

	zklog_tag(Z_KINFO, ZKLOG_TAG_ZTENANT, "Running test_ztenant1...");
	ret = test_ztenant1();
	CALL_SHOULD_SUCCEED(ret, test_ztenant1);

out:
	return ret;
}

#endif /*CONFIG_BTRFS_ZADARA*/
#endif /*CONFIG_BTRFS_FS_RUN_SANITY_TESTS*/

