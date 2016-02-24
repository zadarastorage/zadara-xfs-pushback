/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2015 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#ifndef __QLA_DFS_H
#define __QLA_DFS_H
#include <linux/types.h>
#include <linux/debugfs.h>

/* Statistics Macros */
#define inc_ha_stat(__ha, __stat)			\
	atomic64_inc(&__ha->hstat.__stat)
#define inc_vha_stat(__vha, __stat)			\
	atomic64_inc(&__vha->vstat.__stat)
#define inc_fcp_stat(__fcp, __stat)			\
	atomic64_inc(&__fcp->fstat.__stat)
/* Bump the same named stat in vha & ha */
#define inc_vha_common_stat(__vha, __stat) do {		\
	inc_vha_stat(__vha, __stat);			\
	inc_ha_stat(__vha->hw, __stat);			\
} while(0)
/* Bump the same named stat in fcport & vha */
#define inc_fcp_common_stat(__fcp, __stat) do {		\
	inc_fcp_stat(__fcp, __stat);			\
	inc_vha_stat(__fcp->vha, __stat);		\
} while(0)
/* Bump the same named stat in fcport, vha & ha -- Too much? */
#define inc_fcp_common_stat3(__fcp, __stat) do {	\
	inc_fcp_stat(__fcp, __stat);			\
	inc_vha_stat(__fcp->vha, __stat);		\
	inc_ha_stat(__fcp->vha->hw, __stat);		\
} while(0)

/*
 * These are macros to increment based on a count, can be used to
 * track bytes read/written etc.
 */
#define inc_ha_stat_count(__ha, __stat, __cnt)			\
	atomic64_add(__cnt, &__ha->hstat.__stat)
#define inc_vha_stat_count(__vha, __stat, __cnt)		\
	atomic64_add(__cnt, &__vha->vstat.__stat)
#define inc_fcp_stat_count(__fcp, __stat, __cnt)		\
	atomic64_add(__cnt, &__fcp->fstat.__stat)
#define inc_vha_common_stat_count(__vha, __stat, __cnt) do {	\
	inc_vha_stat_count(__vha, __stat, __cnt);		\
	inc_ha_stat_count(__vha->hw, __stat, __cnt);		\
} while(0)
#define inc_fcp_common_stat_count(__vha, __stat, __cnt) do {	\
	inc_fcp_stat_count(__fcp, __stat, __cnt);		\
	inc_vha_stat_count(__fcp->vha, __stat, __cnt);		\
} while(0)
#define inc_fcp_common_stat_count3(__vha, __stat, __cnt) do {	\
	inc_fcp_stat_count(__fcp, __stat, __cnt);		\
	inc_vha_stat_count(__fcp->vha, __stat, __cnt);		\
	inc_ha_stat_count(__fcp->vha->hw, __stat, __cnt);	\
} while(0)

struct qla_ha_stat {
	/* When adding entries here, update HA_STAT_NODE below */
	/* Target specific stats below: prefix with "tgt_" */
	atomic64_t tgt_atio_pkt;
	atomic64_t tgt_qfull_cmd;
};

struct qla_vha_stat {
	/* When adding entries here, update VHA_STAT_NODE below */
	/* Target specific stats below: prefix with "tgt_" */
	atomic64_t tgt_task_mgmt;
	atomic64_t tgt_bad_dest_busy;
	atomic64_t tgt_atio_t7;
	atomic64_t tgt_imm_pkt;
	atomic64_t tgt_abts;
	atomic64_t tgt_abts_sts_good;
	atomic64_t tgt_abts_sts_bad;
};

struct qla_fcport_stat {
	/* When adding entries here, update FCP_STAT_NODE below */
	/* Target specific stats below: prefix with "tgt_" */
	atomic64_t tgt_scsi_cmds;
	atomic64_t tgt_scsi_busy;
	atomic64_t tgt_scsi_tset_full;
	atomic64_t tgt_abts;
	atomic64_t tgt_tm_clear_aca;
	atomic64_t tgt_tm_target_reset;
	atomic64_t tgt_tm_lun_reset;
	atomic64_t tgt_tm_clear_ts;
	atomic64_t tgt_tm_abort_ts;
	atomic64_t tgt_tm_abort_all;
	atomic64_t tgt_tm_abort_all_sess;
	atomic64_t tgt_tm_nexus_loss_sess;
	atomic64_t tgt_tm_nexus_loss;
};

/*
 * qla_dfcport - Structure to hold debugfs data for a port.
 *
 * Have a separate fcport structure for statistics. By keeping it
 * separate, one mode need not worry about finding the equivalent
 * structure (if stat structure is kept there) in the other mode,
 * which may not even exist.
 */
struct qla_dfcport {
	struct list_head df_next;
	uint32_t ref_cnt;
	uint8_t port_name[8];
	struct scsi_qla_host *vha;
	struct qla_fcport_stat fstat;
	struct {
		struct dentry *fcp;
		struct dentry *stats;
	} dfs;
};

#define HA_CLEAR_STAT(__ha, __stat)	\
	atomic64_set(&__ha->hstat.__stat, 0);
#define VHA_CLEAR_STAT(__vha, __stat)	\
	atomic64_set(&__vha->vstat.__stat, 0);
#define FCP_CLEAR_STAT(__fcp, __stat)	\
	atomic64_set(&__fcp->fstat.__stat, 0);

#define HA_STAT_NODE(__ha, __field)				\
	debugfs_create_u64(#__field, S_IRUGO | S_IWUSR,		\
		__ha->dfs.stats, (u64*)&__ha->hstat.__field.counter)
#define VHA_STAT_NODE(__vha, __field)				\
	debugfs_create_u64(#__field, S_IRUGO | S_IWUSR,		\
		__vha->dfs.stats, (u64*)&__vha->vstat.__field.counter)
#define FCP_STAT_NODE(__fcp, __field)				\
	debugfs_create_u64(#__field, S_IRUGO | S_IWUSR,		\
		__fcp->dfs.stats, (u64*)&__fcp->fstat.__field.counter)

/*
 * Statistics: Add entries in the following 3 macros so that they are
 * visible in debugfs
 */
#define DFS_CREATE_HA_STAT_ENTRIES(__ha)		\
do {							\
	HA_STAT_NODE(__ha, tgt_atio_pkt);		\
	HA_STAT_NODE(__ha, tgt_qfull_cmd);		\
} while(0);

#define DFS_CREATE_VHA_STAT_ENTRRIES(__vha)		\
do {							\
	VHA_STAT_NODE(__vha, tgt_task_mgmt);		\
	VHA_STAT_NODE(__vha, tgt_bad_dest_busy);	\
	VHA_STAT_NODE(__vha, tgt_atio_t7);		\
	VHA_STAT_NODE(__vha, tgt_imm_pkt);		\
	VHA_STAT_NODE(__vha, tgt_abts);			\
	VHA_STAT_NODE(__vha, tgt_abts_sts_good);	\
	VHA_STAT_NODE(__vha, tgt_abts_sts_bad);		\
} while(0);

#define DFS_CREATE_FCP_STAT_ENTRIES(__fcp)		\
do {							\
	FCP_STAT_NODE(__fcp, tgt_scsi_cmds);		\
	FCP_STAT_NODE(__fcp, tgt_scsi_busy);		\
	FCP_STAT_NODE(__fcp, tgt_scsi_tset_full);	\
	FCP_STAT_NODE(__fcp, tgt_abts);			\
	FCP_STAT_NODE(__fcp, tgt_tm_clear_aca);		\
	FCP_STAT_NODE(__fcp, tgt_tm_target_reset);	\
	FCP_STAT_NODE(__fcp, tgt_tm_lun_reset);		\
	FCP_STAT_NODE(__fcp, tgt_tm_clear_ts);		\
	FCP_STAT_NODE(__fcp, tgt_tm_abort_ts);		\
	FCP_STAT_NODE(__fcp, tgt_tm_abort_all);		\
	FCP_STAT_NODE(__fcp, tgt_tm_abort_all_sess);	\
	FCP_STAT_NODE(__fcp, tgt_tm_nexus_loss_sess);	\
	FCP_STAT_NODE(__fcp, tgt_tm_nexus_loss);	\
} while(0);

/*
 * These macros gets invoked during a reset, so clear stats that does not
 * make sense across resets.
 */
#define DFS_CLEAR_RUN_TIME_HA_STATS(__fcp)		\
do {							\
	HA_CLEAR_STAT(__fcp, tgt_atio_pkt);		\
	HA_CLEAR_STAT(__fcp, tgt_qfull_cmd);		\
} while(0);
#define DFS_CLEAR_RUN_TIME_VHA_STATS(__fcp)		\
do {							\
	VHA_CLEAR_STAT(__fcp, tgt_task_mgmt);		\
} while(0);
#define DFS_CLEAR_RUN_TIME_FCP_STATS(__fcp)		\
do {							\
	FCP_CLEAR_STAT(__fcp, tgt_scsi_cmds);		\
} while(0);
#endif /* __QLA_DFS_H */
