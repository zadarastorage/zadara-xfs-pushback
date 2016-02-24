/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2015 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#ifdef QLA_ENABLE_SRIOV
#include <linux/delay.h>
#include <asm/unaligned.h>
#include <linux/seq_file.h>
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
#include "qla2x_tgt.h"
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */
/*
 * Function prefix conventions:
 * 	qla_sriov_	: Exported functions
 * 	qla_[sriov_]pf_	: Executed by PF
 * 	qla_[sriov_]vf_	: Executed by VF
 * 	qla_[sriov_]xf_	: Executed by PF/VF
 * 	qla83xx_	: Firmware specific
 * 	qla_		: Generic f/w independent functions
 */

/* Prototypes */
/* Prototypes */

/*********************** Firmware specific functions *************************/
/*
 *  Command used establish parameters to enable fw to allocate resources for
 *  VFs, and is therefore only valid from the PF driver in a "write" mode. The
 *  command may also be used to determine current configuration parameters
 *  after fw has been initialised.
 *
 */
static int
qla83xx_configure_vfs(struct qla_hw_data *ha)
{
	int rval;
	struct scsi_qla_host *vha = pci_get_drvdata(ha->pdev);
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	uint16_t	options;
	uint32_t	vf_cfgblk_size;
	dma_addr_t	buf_dma;
	uint8_t		*buf;
	struct qla_vf_cfg_ctrl_block *vf_blk;
	uint32_t pg_decode;

	options = BIT_0; /* Write Enable, set to write cfg values */

	vf_cfgblk_size = sizeof(struct qla_vf_cfg_ctrl_block);
	buf = dma_alloc_coherent(&ha->pdev->dev, vf_cfgblk_size, &buf_dma,
			GFP_KERNEL);
	if (buf == NULL) {
		ql_log(ql_log_warn, vha, 0x11000,
		    "%s: SR-IOV: can't allocate memory.\n", __func__);
		return QLA_FUNCTION_FAILED;
	}

	memset(buf, 0, vf_cfgblk_size);
	vf_blk = (struct qla_vf_cfg_ctrl_block *)buf;

	/* No trusted VFs. */
	vf_blk->total_vp_per_f = cpu_to_le16(QLA_TOTAL_VP_PER_F);
	vf_blk->max_vp_per_f = cpu_to_le16(QLA_MAX_VP_PER_F);
	vf_blk->max_nport_per_f = cpu_to_le16(QLA_MAX_NPORT_PER_F);
	vf_blk->max_qset_per_f = cpu_to_le16(QLA_MAX_QSET_PER_F);
	pg_decode = (1 << PG_LOCAL_ENABLE_BIT)
		| SET_MASK_VAL32(PG_NUM_SYS_PAGE, PG_DECODE_SYS_PAGE_MASK,
				PG_DECODE_SYS_PAGE_SHIFT)
		| SET_MASK_VAL32(PG_LOCAL_SIZE, PG_DECODE_LOC_PAGE_MASK,
				PG_DECODE_LOC_PAGE_SHIFT);
	vf_blk->page_decode = cpu_to_le32(pg_decode);

	mcp->mb[7] = LSW(MSD(buf_dma));
	mcp->mb[6] = MSW(MSD(buf_dma));
	mcp->mb[3] = LSW(buf_dma);
	mcp->mb[2] = MSW(buf_dma);
	mcp->mb[1] = options;
	mcp->mb[0] = MBC_CONFIGURE_VF;

	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|
	    MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS)
		ql_dbg(ql_dbg_sriov, vha, 0x11001,
		    "%s: SR-IOV: Failed=%x mb[0]=%x.\n",
		    __func__, rval, mcp->mb[0]);

        dma_free_coherent(&ha->pdev->dev, vf_cfgblk_size, buf, buf_dma);
	return rval;
}

static int
qla83xx_vdc_message(scsi_qla_host_t *vha, struct qla_vdc_message *xfm,
			uint8_t dest_func, uint16_t *in_mb_save)
{
	int rval, i;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	uint32_t len, timeout = 3;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11002,
					"%s: SR-IOV: Entered.\n", __func__);

	len = sizeof(*xfm) >> 2; /* in 32 bit words. */

	memset(mcp->mb, 0, sizeof(mcp->mb));
	mcp->mb[0] = MBC_VDC_MESSAGE;
	mcp->mb[1] = len << 12 | timeout << 8 | dest_func;
	memcpy(&mcp->mb[2], xfm, QLA_XM_MAX_POSSIBLE);
	/* MB 2 to 21 carries the payload. */
	for (i = 0; i < 21; i++)
		mcp->out_mb |= 1 << i;

	mcp->in_mb = MBX_0;
	if (in_mb_save)
		mcp->in_mb |= MBX_0 | MBX_1 | MBX_2 | MBX_3 |
				MBX_6 | MBX_7 | MBX_8 | MBX_9 | MBX_10;
	mcp->tov = timeout + 1;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_sriov, vha, 0x11003,
		    "%s: SR-IOV: Failed=%x mb[0]=%x.\n",
		    __func__, rval, mcp->mb[0]);
	} else {
		if (in_mb_save) {
			for (i = 0; i < 32; i++) {
				if (!(mcp->in_mb & (1 << i)))
					continue;
				in_mb_save[i] = mcp->mb[i];
			}
		}
		ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11004,
		    "%s: SR-IOV: Done.\n", __func__);
	}

	return rval;
}

static int
qla83xx_enable_vf(struct qla_hw_data *ha, struct qla_sriov_vf *vf)
{
	int ret;
	struct vp_config_entry_24xx vpm, *vpmod = &vpm;
	struct scsi_qla_host *vha = pci_get_drvdata(ha->pdev);

	memset(vpmod, 0, sizeof(*vpmod));
	vpmod->entry_type = VP_CONFIG_IOCB_TYPE;
	vpmod->entry_count = 1;
	vpmod->command = VCT_COMMAND_MOD_MDFY_VP_VF;
	vpmod->flags = cpu_to_le16(CS_VF_FORMAT_1);
	vpmod->vp_count = 1;
	vpmod->vp_index1 = 0;
	vpmod->options_idx1 = VCT_OPTIONS_ACQUIRE_ID |
		VCT_OPTIONS_EN_SNS_SCR_FOR_VP;
	if (!SRIOV_VF_DISABLE_INI_MODE())
		vpmod->options_idx1 |= VCT_OPTIONS_ENABLE_INI_MODE;
	if (SRIOV_VF_DISABLE_TGT_MODE())
		vpmod->options_idx1 |= VCT_OPTIONS_DISABLE_TGT_MODE;
	vpmod->vf_num = vf->index;
	put_unaligned_be64(vf->node_wwn, vpmod->node_name_idx1);
	put_unaligned_be64(vf->port_wwn, vpmod->port_name_idx1);

	vpmod->entry_count = 1;

	ret = qla83xx_modify_vp_config(vha, vpmod);
	vf->is_enabled = !ret;
	if (ret) {
		ql_log(ql_log_warn, vha, 0x11005,
			"SR-IOV: Failed to enable VF %u:%lx:%lx config in firmware (%d).\n",
			vf->index, (unsigned long)vf->node_wwn,
			(unsigned long)vf->port_wwn, ret);
		return -EIO;
	}

	return ret;
}

static int
qla2x00_send_no_op(scsi_qla_host_t *vha, mbx_cmd_t *mcp)
{
	int rval;

	memset(mcp->mb, 0, sizeof(mcp->mb));

	mcp->mb[0] = MBC_NO_OP;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = 5;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_sriov, vha, 0x11006,
			"SR-IOV: NO-OP Send Failure (%d), mb0=%x mb1=%x mb2=%x.\n",
			rval, mcp->mb[0], mcp->mb[1], mcp->mb[2]);
		return rval;
	}

	return 0;
}
/*********************** Firmware specific functions *************************/

/*********************** Support routines ********************************/
/*
 * Interface to send a message to a function (PF/VF) and receive response.
 * All messages are acknowledged.
 */
static int
qla_xf_message(struct scsi_qla_host *vha,
		struct qla_vdc_message_entry *vme,
		uint8_t dest_func)
{
	struct qla_hw_data *ha = vha->hw;
	int rval;
	unsigned long flags;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11007,
					"%s: SR-IOV: Entered.\n", __func__);

	vme->is_comp_type = 1;
	init_completion(&vme->u.comp);

	spin_lock_irqsave(&ha->sriov.lock, flags);
	list_add_tail(&vme->vdc_next, &ha->sriov.vdc_head);
	spin_unlock_irqrestore(&ha->sriov.lock, flags);

	rval = qla83xx_vdc_message(vha, &vme->msg, dest_func, NULL);
	if (rval)
		goto done;

	/* Wait for response. */
	if (!vha->flags.init_done) {
		unsigned long	wait_time;
		wait_time = jiffies + QLA_XM_MSG_WAIT;
		while (!vme->is_unread &&
				!test_bit(UNLOADING, &vha->dpc_flags)) {
			if (time_after(jiffies, wait_time))
				break;

			/* Check for pending interrupts. */
			qla2x00_poll(ha->rsp_q_map[0]);

			if (!vme->is_unread)
				msleep(10);
		} /* while */
		rval = vme->is_unread ? QLA_SUCCESS : QLA_FUNCTION_FAILED;
	} else {
		rval = wait_for_completion_interruptible_timeout(&vme->u.comp,
						QLA_XM_MSG_WAIT);
		if (rval == -ERESTARTSYS) /* Interrupted */
			rval = QLA_ABORTED;
		else if (!rval) /* Timed out */
			rval = QLA_FUNCTION_FAILED;
		else
			rval = QLA_SUCCESS;
	}

done:
	spin_lock_irqsave(&ha->sriov.lock, flags);
	list_del(&vme->vdc_next);
	spin_unlock_irqrestore(&ha->sriov.lock, flags);

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11008,
			"%s: SR-IOV: Done (%d).\n", __func__, rval);
	return rval;
}

/*
 * if index_in is 0, then PWWN lookup, otherwise index look up
 */
static struct qla_sriov_vf *
qla_pf_get_vf(struct qla_hw_data *ha, uint8_t index_in, uint64_t pwwn)
{
	unsigned long flags;
	struct qla_sriov_vf *vf;
	int found = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_for_each_entry(vf, &ha->sriov.vf_head, vf_next) {
		if ((index_in && index_in == vf->index) ||
			(!index_in && vf->port_wwn == pwwn)) {
			found = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return found ? vf : NULL;
}

static int
qla_pf_get_num_configured_vf(struct qla_hw_data *ha, uint8_t vfi)
{
	unsigned long flags;
	struct qla_sriov_vf *vf;
	int count = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_for_each_entry(vf, &ha->sriov.vf_head, vf_next) {
		if (vf->index == vfi)
			count++;
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return count;
}

static struct qla_vdc_message_entry *
qla_xf_get_entry(struct scsi_qla_host *vha, uint8_t src_func, uint8_t code)
{
	unsigned long flags;
	struct qla_vdc_message_entry *vme;
	struct qla_hw_data *ha = vha->hw;
	int found = 0;

	spin_lock_irqsave(&ha->sriov.lock, flags);
	list_for_each_entry(vme, &ha->sriov.vdc_head, vdc_next) {
		if (vme->source_func == src_func &&
			vme->msg.code == code) {
			kref_get(&vme->kref);
			found = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&ha->sriov.lock, flags);

	return found ? vme : NULL;
}

static void
qla_xf_free_vme(struct kref *kref)
{
	struct qla_vdc_message_entry *vme =
		container_of(kref, struct qla_vdc_message_entry, kref);

	kfree(vme);
}

/*********************** Support routines ********************************/

static int
qla_pf_add_vf(struct qla_hw_data *ha, uint8_t vfi, uint64_t nwwn,
		uint64_t pwwn)
{
	struct qla_sriov_vf *vf;
	unsigned long flags;
	int num_cfgd, rval;
	struct scsi_qla_host *vha = pci_get_drvdata(ha->pdev);

	if (!ha->flags.sriov_enabled) {
		ql_log(ql_log_warn, vha, 0x11009,
			"SR-IOV: Ths adapter has SR-IOV capability disabled.\n");
		return -EPERM;
	}

	num_cfgd = qla_pf_get_num_configured_vf(ha, vfi);
	if (num_cfgd + 1 > QLA_MAX_VP_PER_F) {
		ql_log(ql_log_warn, vha, 0x1100a,
			"SR-IOV: Reached limit (%u) of maximum VFs, deconfigure to reuse.\n",
			QLA_MAX_VP_PER_F);
		return -ENOSPC;
	}

	vf = qla_pf_get_vf(ha, 0, pwwn);
	if (vf) {
		ql_log(ql_log_warn, vha, 0x1100b,
			"SR-IOV: VF already exists at index %d.\n", vf->index);
		return -EEXIST;
	}

	vf = kcalloc(1, sizeof(*vf), GFP_KERNEL);
	if (!vf) {
		ql_log(ql_log_warn, vha, 0x1100c,
			"SR-IOV: Out of memory while allocating %lu bytes.\n",
			sizeof(*vf));
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&vf->vf_next);
	vf->index = vfi;
	vf->port_wwn = pwwn;
	vf->node_wwn = nwwn;

	rval = qla83xx_enable_vf(ha, vf);
	if (rval) {
		kfree(vf);
		return rval;
	}

	mutex_lock(&ha->sriov.vf_mutex);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_add_tail(&vf->vf_next, &ha->sriov.vf_head);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	mutex_unlock(&ha->sriov.vf_mutex);

	return 0;
}

static int
qla_pf_remove_vf(struct qla_hw_data *ha, uint64_t pwwn)
{
	struct qla_sriov_vf *vf;
	unsigned long flags;

	vf = qla_pf_get_vf(ha, 0, pwwn);
	if (!vf)
		return -EEXIST;

	/* TODO: Disable the VF entry in f/w. */

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_del_init(&vf->vf_next);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	kfree(vf);

	return 0;
}

/**
 * qla_pf_sriov_configure - SRIOV configure interface
 *
 * This gets called during PCI call back for SR-IOV configure.
 */
static void
qla_pf_sriov_configure(struct qla_hw_data *ha, int numvfs)
{
	ha->sriov.num_enabled_vfs += numvfs;
}

/**
 * qla_pf_sriov_deconfigure - SRIOV deconfigure interface
 *
 * This gets called during PCI call back for SR-IOV deconfigure.
 */
static void
qla_pf_sriov_deconfigure(struct qla_hw_data *ha)
{
	struct qla_sriov_vf *vf, *tmp_vf;
	unsigned long flags;

	if (!ha->flags.sriov_enabled)
		return;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_for_each_entry_safe(vf, tmp_vf, &ha->sriov.vf_head, vf_next) {
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		qla_pf_remove_vf(ha, vf->port_wwn);

		spin_lock_irqsave(&ha->hardware_lock, flags);
	}
	ha->sriov.num_enabled_vfs = 0;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

static int
qla_pf_reset_notify(struct qla_hw_data *ha, struct qla_sriov_vf *vf)
{
	int rval;
	struct qla_vdc_message v_msg, *vm = &v_msg;
	struct scsi_qla_host *vha = pci_get_drvdata(ha->pdev);

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x1100d,
			"%s: SR-IOV: VF=%d\n", __func__, vf->index);

	memset(vm, 0, sizeof(*vm));

	vm->version = QLA_XM_VERSION;
	vm->code = QLA_XMC_PF_RESET_NOTIFY;
	vm->seq_num = QLA_XM_SEQ_NUM(ha);
	vm->u.rst_notify.reset_count = ha->chip_reset;
	rval = qla83xx_vdc_message(vha, vm, vf->index, NULL);

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x1100e,
			"%s: SR-IOV: VF=%d Done(%d)\n",
			__func__, vf->index, rval);
	return rval;
}

static void
qla_pf_reset_notify_all_vfs(struct qla_hw_data *ha)
{
	unsigned long flags;
	struct qla_sriov_vf *vf;
	int rval;

	mutex_lock(&ha->sriov.vf_mutex);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_for_each_entry(vf, &ha->sriov.vf_head, vf_next) {
		if (!vf->is_initialized)
			continue;
		vf->is_initialized = 0;
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		/* REVISIT: Retrys, maybe */
		rval = qla_pf_reset_notify(ha, vf);

		spin_lock_irqsave(&ha->hardware_lock, flags);
		if (rval) /* Restore previous value */
			vf->is_initialized = 1;
		if (rval == QLA_FUNCTION_TIMEOUT)
			break;
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	mutex_unlock(&ha->sriov.vf_mutex);

	return;
}

static void
qla_pf_enable_all_vfs(struct qla_hw_data *ha)
{
	unsigned long flags;
	struct qla_sriov_vf *vf;

	mutex_lock(&ha->sriov.vf_mutex);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_for_each_entry(vf, &ha->sriov.vf_head, vf_next) {
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		/* Ignore return status, cant do much. */
		(void)qla83xx_enable_vf(ha, vf); /* REVISIT: Retrys, maybe */

		spin_lock_irqsave(&ha->hardware_lock, flags);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	mutex_unlock(&ha->sriov.vf_mutex);

	return;
}

static void
qla_pf_handle_vf_info(struct qla_vdc_message_entry *vme)
{
	struct qla_sriov_vf *vf;
	scsi_qla_host_t *vha = vme->vha;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x1100f,
					"%s: SR-IOV: Entered.\n", __func__);

	WARN(!vme->source_func,
		"%s: SR-IOV: PF is an invalid source func for VF info.\n",
		__func__);

	vf = qla_pf_get_vf(ha, vme->source_func, 0);
	if (!vf) {
		vme->msg.status = QLA_XMS_FAILED;
		ql_log(ql_log_warn, vha, 0x11010,
			"%s: SR-IOV: Cannot find VF to send VF info.\n",
			__func__);
		return;
	}
	put_unaligned_be64(vf->node_wwn, vme->msg.u.vf_info.node_name);
	put_unaligned_be64(vf->port_wwn, vme->msg.u.vf_info.port_name);
	vme->msg.status = QLA_XMS_GOOD;

	vf->is_initialized = 1;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11011,
					"%s: SR-IOV: Done.\n", __func__);
}

static int
qla_vf_get_info(struct scsi_qla_host *vha)
{
	struct qla_hw_data *ha = vha->hw;
	struct qla_vdc_message_entry *vme = NULL;
	int i, rval = QLA_FUNCTION_FAILED, num_retries = 1;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11012,
				"%s: SR-IOV: Entered.\n", __func__);

	for (i = 0; i < num_retries; msleep(1000), i++) {
		if (!vme)
			vme = kzalloc(sizeof(*vme), GFP_KERNEL);
		if (!vme)
			continue;
		if (!vme->msg.version) {
			vme->msg.version = QLA_XM_VERSION;
			vme->msg.code = QLA_XMC_VF_INFO;
			vme->msg.seq_num = QLA_XM_SEQ_NUM(ha);
			vme->is_solicited = 1;
			vme->vha = vha;
			kref_init(&vme->kref);
		}
		rval = qla_xf_message(vha, vme, 0);
		if (rval == QLA_SUCCESS) {
			memcpy(vha->node_name, vme->msg.u.vf_info.node_name, 8);
			memcpy(vha->port_name, vme->msg.u.vf_info.port_name, 8);
		}

		if (rval != QLA_FUNCTION_FAILED)
			break;

		/* Retry only for QLA_FUNCTION_FAILED cases. */
		ql_dbg(ql_dbg_sriov, vha, 0x11013,
			"%s: SR-IOV: Retrying (%d).\n", __func__, i);
	}

	kref_put(&vme->kref, qla_xf_free_vme);

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11014,
				"%s: SR-IOV: Done (%d).\n", __func__, rval);
	return rval;
}

#define NUM_PF_WAIT_RETRY	10
static int
qla_vf_wait_for_pf_ready(scsi_qla_host_t *vha)
{
	mbx_cmd_t mc, *mcp = &mc;
	int i, rval = QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11015,
				"%s: SR-IOV: Entered.\n", __func__);

	for (i = 0; i < NUM_PF_WAIT_RETRY &&
			!test_bit(UNLOADING, &vha->dpc_flags); i++) {
		rval = qla2x00_send_no_op(vha, mcp);
		if (!rval || rval == QLA_FUNCTION_TIMEOUT)
			break;
		msleep(1000);
	}

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11016,
				"%s: SR-IOV: Done (%d).\n", __func__, rval);

	return rval;
}

static void
qla_vf_handle_reset_notify(struct qla_vdc_message_entry *vme)
{
	scsi_qla_host_t *vha = vme->vha;
	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11017,
				"%s: SR-IOV: Entered.\n", __func__);

	WARN(!vha->hw->dev_type.virt_func,
			"%s: SR-IOV: Unpexpected for PF.\n", __func__);

	ql_log(ql_log_warn, vha, 0x11018,
		"SR-IOV: Reset notification from host - scheduling reset.\n");

	vha->flags.online = 1; /* Force a re-init. */
	set_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
}

static void
qla_xf_message_work(struct work_struct *work)
{
	struct qla_vdc_message_entry *vme = container_of(work,
			struct qla_vdc_message_entry, u.work);
	scsi_qla_host_t *vha = vme->vha;
	struct qla_hw_data *ha = vme->vha->hw;
	unsigned long flags;
	int rval;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11019,
				"%s: SR-IOV: Entered.\n", __func__);

	if (vme->msg.status) {
		/*
		 * This is a response we received for a message we sent.
		 * We get here if the waiting thread exits sooner.
		 */
		ql_dbg(ql_dbg_sriov, vha, 0x1101a,
			"SR-IOV: Ignoring response VDC (code=%u, status=%u).\n",
			vme->msg.code, vme->msg.status);
		goto skip_response;
	}

	switch (vme->msg.code) {
	case QLA_XMC_VF_INFO:
		qla_pf_handle_vf_info(vme);
		break;
	case QLA_XMC_PF_INFO:
		/* Version updated after this block. */
		vme->msg.status = QLA_XMS_GOOD;
		break;
	case QLA_XMC_PF_RESET_NOTIFY:
		qla_vf_handle_reset_notify(vme);
		goto skip_response;
	default:
		vme->msg.status = QLA_XMS_UKNOWN_CODE;
		vme->msg.code = vme->saved_code; /* Restore original code. */
		break;
	}

	WARN(!vme->msg.status, "%s: SR-IOV: Status not set for code %u.\n",
			__func__, vme->msg.code);

	/* Respond back with our version. */
	vme->msg.version = QLA_XM_VERSION;

	rval = qla83xx_vdc_message(vha, &vme->msg, vme->source_func, NULL);
	if (rval)
		ql_log(ql_log_warn, vha, 0x1101b,
			"SR-IOV: Unsolicited message (%u): Failed to send response (%d).\n",
			vme->msg.code, rval);

skip_response:
	spin_lock_irqsave(&ha->sriov.lock, flags);
	list_del(&vme->vdc_next);
	spin_unlock_irqrestore(&ha->sriov.lock, flags);

	kref_put(&vme->kref, qla_xf_free_vme);

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x1101c,
				"%s: SR-IOV: Done.\n", __func__);
}

static int
qla_dfs_vf_cfg_show(struct seq_file *s, void *unused)
{
	struct scsi_qla_host *vha = s->private;
	struct qla_hw_data *ha = vha->hw;
	struct qla_sriov_vf *vf;
	unsigned long flags;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	list_for_each_entry(vf, &ha->sriov.vf_head, vf_next) {
		seq_printf(s, "%u %llx %llx\n", vf->index,
				vf->node_wwn, vf->port_wwn);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return 0;
}

static int
qla_dfs_vf_cfg_open(struct inode *inode, struct file *file)
{
	struct scsi_qla_host *vha = inode->i_private;
	return single_open(file, qla_dfs_vf_cfg_show, vha);
}
static const struct file_operations dfs_vf_cfg_ops = {
	.open		= qla_dfs_vf_cfg_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void
qla_dfs_vf_cfg_create(struct scsi_qla_host *vha)
{
	struct qla_hw_data *ha = vha->hw;
	struct dentry *dfs_vf_cfg;

	dfs_vf_cfg = debugfs_create_file("vf_cfg_entries",
				S_IRUSR, ha->dfs.ha, vha, &dfs_vf_cfg_ops);
	if (!dfs_vf_cfg) {
		ql_log(ql_log_warn, vha, 0x1101d,
			"ERROR: SR-IOV: Could not create vf_cfg_entries in debugfs.\n");
	}
}

/**
 * qla2xxx_sriov_configure - SRIOV configure/deconfigure interface.
 *
 * This gets invoked when user writes a value to:
 * 	/sys/bus/pci/devices/<pci-func>/sriov_numvfs
 *
 * There is always a deconfigure (numvfs == 0) call after a configure
 * (numvfs != 0) call. A configure call, followed by another configure
 * call (with higher numvfs) is prevented by the layer above.
 */
int
qla2xxx_sriov_configure(struct pci_dev *dev, int numvfs)
{
	scsi_qla_host_t *vha = pci_get_drvdata(dev);
	struct qla_hw_data *ha = vha->hw;
	int ret;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x1101e,
			"%s: SR-IOV: numvfs=%d\n", __func__, numvfs);

	if (numvfs > 0) {
		ret = pci_enable_sriov(dev, numvfs);
		if (ret) {
			ql_log_pci(ql_log_fatal, ha->pdev, 0x1101f,
				"SR-IOV: Failed to create VFs (%d).\n", ret);
			return ret;
		}
		if (!ret)
			qla_pf_sriov_configure(ha, numvfs);
		ql_dbg(ql_dbg_sriov, vha, 0x11020,
			"SR-IOV: Enabled %d VFs.\n", numvfs);
		return numvfs;
	}

	if (numvfs == 0) {
		pci_disable_sriov(dev);
		qla_pf_sriov_deconfigure(ha);
		ql_dbg(ql_dbg_sriov, vha, 0x11021,
				"SR-IOV: Disabled all VFs.\n");
		return 0;
	}

	return -EINVAL;
}

/************** Exported interfaces: All starts with qla_sriov_ **************/
int
qla_sriov_vf_nvram_config(scsi_qla_host_t *vha)
{
	struct qla_hw_data *ha = vha->hw;
	struct init_cb_81xx *icb;
	int ret;

#define VF83XX_FO1_NAME_OPT	BIT_14
#define VF83XX_FO1_INIT_DISABLE	BIT_5
#define VF83XX_FO1_TGT_ENABLE	BIT_4

#define VF83XX_FO2_TGT_PRLI_CTRL	BIT_14
#define VF83XX_FO2_CONN_OPT_SHIFT	4
#define VF83XX_FO2_P2P_ONLY		(1 << VF83XX_FO2_CONN_OPT_SHIFT)
#define VF83XX_FO2_OP_MODE_SHIFT	0
#define VF83XX_FO2_ZIO_6 \
	(QLA_ZIO_MODE_6 << VF83XX_FO2_OP_MODE_SHIFT)

#define VF83XX_FO3_DATA_RATE_SHIFT	13
#define VF83XX_FO3_AUTO_NEGO		(2 << VF83XX_FO3_DATA_RATE_SHIFT)

	icb = (struct init_cb_81xx *)ha->init_cb;

	memset(icb, 0, sizeof(*icb));
	icb->version = cpu_to_le16(1);
	icb->frame_payload_size = cpu_to_le16(2048);
	icb->login_retry_count = cpu_to_le16(3);
	icb->interrupt_delay_timer = cpu_to_le16(0); /* Let f/w choose */
	icb->login_timeout = cpu_to_le16(0); /* Let f/w choose */
	icb->firmware_options_1 = cpu_to_le32(0);
	icb->firmware_options_2 = cpu_to_le32(VF83XX_FO2_P2P_ONLY |
			VF83XX_FO2_ZIO_6);
	icb->firmware_options_3 = cpu_to_le32(VF83XX_FO3_AUTO_NEGO);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (qla_tgt_mode_enabled(vha)) {
		icb->exchange_count = cpu_to_le16(0xffff);
		icb->firmware_options_1 |= __constant_cpu_to_le32(BIT_4);
		/* Disable ini mode, if requested */
		if (!qla_ini_mode_enabled(vha))
			icb->firmware_options_1 |=
					__constant_cpu_to_le32(BIT_5);
#ifdef QLT_FC_TAPE
		/* Enable FC tapes support */
		icb->firmware_options_2 |= __constant_cpu_to_le32(BIT_12);
#else /* QLT_FC_TAPE */
		icb->firmware_options_2 &= __constant_cpu_to_le32(~BIT_12);
#endif /* QLT_FC_TAPE */
	}
	/* out-of-order frames reassembly */
	icb->firmware_options_3 |= __constant_cpu_to_le32(BIT_6|BIT_9);
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

	ha->zio_mode = QLA_ZIO_MODE_6;
	ha->retry_count = 3;
	ha->login_timeout = 20;
	ha->r_a_tov = 100;
	ha->loop_reset_delay = 5;
	ha->link_down_timeout = 30;
	ha->loop_down_abort_time = (LOOP_DOWN_TIME - LOOP_DOWN_TIMEOUT);
	ha->port_down_retry_count = 30;
	if (qlport_down_retry)
		ha->port_down_retry_count = qlport_down_retry;
	ha->login_retry_count  = 30;
	if (ql2xloginretrycount)
		ha->login_retry_count = ql2xloginretrycount;

	ret = qla_vf_wait_for_pf_ready(vha);
	if (ret) {
		ql_log(ql_log_warn, vha, 0x11022,
			"SR-IOV: PF appear offline (%d), unable to proceed.\n",
			ret);
		return QLA_FUNCTION_FAILED;
	}

	/* Get Node and Port Names from the PF. */
	ret = qla_vf_get_info(vha);
	if (ret) {
		ql_log(ql_log_warn, vha, 0x11023,
			"SR-IOV: Unable to get host information (%d).\n", ret);
		return QLA_FUNCTION_FAILED;
	}

	/* Copy names to init_cb as well so that FA-WWN code does not trip. */
	memcpy(icb->node_name, vha->node_name, 8);
	memcpy(icb->port_name, vha->port_name, 8);

	ql_dbg(ql_dbg_sriov, vha, 0x11024,
		"SR-IOV: Acquired Node/Port names: %8phN/%8phN.\n",
		vha->node_name, vha->port_name);

	return QLA_SUCCESS;
}

static void
qla_vf_init_fwdump_template(scsi_qla_host_t *vha)
{
	struct qla_hw_data *ha = vha->hw;
	uint32_t i, *dcode, dlen, risc_size;

	if (ha->fw_dump_template)
		vfree(ha->fw_dump_template);
	ha->fw_dump_template = NULL;
	ha->fw_dump_template_len = 0;

	dlen = qla27xx_fwdt_template_default_size();
	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11025,
	    "SR-IOV: -> template allocating %x bytes...\n", dlen);
	ha->fw_dump_template = vmalloc(dlen);
	if (!ha->fw_dump_template) {
		ql_log(ql_log_warn, vha, 0x11026,
		    "SR-IOV: Failed fwdump template allocate %x bytes.\n",
		    dlen);
		goto failed_template;
	}

	dcode = ha->fw_dump_template;
	risc_size = dlen / sizeof(*dcode);
	memcpy(dcode, qla27xx_fwdt_template_default(), dlen);
	for (i = 0; i < risc_size; i++)
		dcode[i] = be32_to_cpu(dcode[i]);

	if (!qla27xx_fwdt_template_valid(ha->fw_dump_template)) {
		ql_log(ql_log_warn, vha, 0x11027,
		    "SR-IOV: Failed fwdump template validate\n");
		goto failed_template;
	}

	dlen = qla27xx_fwdt_template_size(ha->fw_dump_template);
	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11028,
	    "SR-IOV: -> template size %x bytes\n", dlen);
	ha->fw_dump_template_len = dlen;
	return;

failed_template:
	ql_log(ql_log_warn, vha, 0x11029,
			"SR-IOV: Failed default fwdump template\n");
	if (ha->fw_dump_template)
		vfree(ha->fw_dump_template);
	ha->fw_dump_template = NULL;
	ha->fw_dump_template_len = 0;
}

int
qla_sriov_vf_setup_chip(scsi_qla_host_t *vha)
{
	struct qla_hw_data *ha = vha->hw;
	uint16_t fw_major_version;
	int rval;

	fw_major_version = ha->fw_major_version;
	rval = qla2x00_get_fw_version(vha);

	/* No NPIV support for now. */
	ha->flags.npiv_supported = 0;
	qla2x00_get_resource_cnts(vha, NULL, &ha->fw_xcb_count, NULL,
			&ha->fw_iocb_count, NULL, NULL);
	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x1102a,
		"SR-IOV: fw_xcb_count=%u, fw_iocb_count=%u.\n",
		ha->fw_xcb_count, ha->fw_iocb_count);

	if (!ha->fw_xcb_count || !ha->fw_iocb_count)
		ha->fw_xcb_count = ha->fw_iocb_count = 1024;

	rval = qla2x00_alloc_outstanding_cmds(ha, vha->req);
	if (rval != QLA_SUCCESS)
		goto failed;

	qla_vf_init_fwdump_template(vha);

	if (!fw_major_version && ql2xallocfwdump)
		qla2x00_alloc_fw_dump(vha);

	/* ql2xsmartsan? */
failed:
	if (rval) {
		ql_log(ql_log_fatal, vha, 0x1102b,
		    "SR-IOV: Setup chip ****FAILED****.\n");
	}
	return rval;
}

void
qla_sriov_vf_reset_chip(scsi_qla_host_t *vha)
{
	int ret = 0;
	struct qla_hw_data *ha = vha->hw;

	/* Issue a FLR. */
	ret = qla_vf_reset(ha->pdev);
	if (ret)
		ql_dbg(ql_dbg_sriov, vha, 0x1102c,
			"%s: SR-IOV: FLR returns (%d) -EAGAIN(11) ok during probe.\n",
			__func__, ret);
}

/* Interface that gets called during adapter initialization prior to init-fw. */
int
qla_sriov_pf_adapter_init(struct qla_hw_data *ha, uint8_t context)
{
	int rval;
	scsi_qla_host_t *vha = pci_get_drvdata(ha->pdev);

	if (!ha->flags.sriov_enabled)
		return 0;

	switch (context) {
	case 0: /* Prior to init-fw */
		rval = qla83xx_configure_vfs(ha);
		if (rval) {
			ql_log(ql_log_warn, vha, 0x1102d,
				"SR-IOV: Configure VF failed (%d).\n", rval);
			return rval;
		} else {
			ql_dbg(ql_dbg_sriov, vha, 0x1102e,
				"SR-IOV: Configure VF done.\n");
		}
		break;

	case 1: /* After init-fw */
		qla_pf_enable_all_vfs(ha);
		qla_pf_reset_notify_all_vfs(ha);
		break;

	default:
		WARN(1, "SR-IOV: %s: Unhandled case %u.\n", __func__, context);
		break;
	}

	return 0;
}

/* mb_in has values of mailboxes 0-3 */
void
qla_sriov_pf_handle_vdc_aen(scsi_qla_host_t *vha, uint16_t *mb_in)
{
	struct qla_hw_data *ha = vha->hw;
	struct device_reg_24xx __iomem *reg24 = &ha->iobase->isp24;
	uint16_t *mb_regs = &reg24->mailbox0, *mb_dst;
	struct qla_vdc_message *xfm = (struct qla_vdc_message*)&mb_in[2];
	struct qla_vdc_message_entry *vme;
	uint8_t i, src_func, len, code, orig_code;
	unsigned long flags;

	src_func = GET_MASK_VAL32(mb_in[1], 0xff, 0);
	len = GET_MASK_VAL32(mb_in[1], 0xf, 12) << 2; /* Words to bytes */
	code = orig_code = xfm->code;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x1102f,
		"SR-IOV: VDC AEN: source-function=%u len=%u.\n", src_func, len);

	/*
	 * If you hit compile error here, you have used a message code
	 * too big (> 0xff)
	 */
	BUILD_BUG_ON(QLA_XMC_BAD_CODE > U8_MAX);

	/*
	 * Check for valid code range. Do not bother forcing a VF/PF check, as
	 * we can get a response from the other party for the same code.
	 */
	if ( (code < QLA_XMC_VF_START || code >= QLA_XMC_VF_LAST) &&
		(code < QLA_XMC_PF_START || code >= QLA_XMC_PF_LAST) ) {
		ql_dbg(ql_dbg_sriov, vha, 0x11030,
			"SR-IOV: !! Unknown message %u.\n", code);
		/* This way, repeated bad codes do not inundate the driver */
		code = QLA_XMC_BAD_CODE;
	}

	vme = qla_xf_get_entry(vha, src_func, code);
	if (!vme) { /* Unsolicited message */
		vme = kzalloc(sizeof(*vme), GFP_ATOMIC);
		if (!vme) {
			ql_dbg(ql_dbg_sriov, vha, 0x11031,
				"%s: SR-IOV: !! Out of memory.\n", __func__);
			return;
		}
		vme->is_comp_type = 0;
		vme->is_solicited = 0;
		vme->source_func = src_func;
		vme->vha = vha;
		kref_init(&vme->kref);
		INIT_WORK(&vme->u.work, qla_xf_message_work);
	} else { /* Solicited or scheduled-unsolicited */
		if (vme->is_unread) {
			kref_put(&vme->kref, qla_xf_free_vme);
			ql_dbg(ql_dbg_sriov, vha, 0x11032,
				"SR-IOV: !! Dropping repeated message %u from function %u.\n",
				orig_code, src_func);
			return;
		}
	}
	mb_dst = (uint16_t*)&vme->msg;
	/* Copy the message. */
	*mb_dst++ = mb_in[2];
	*mb_dst++ = mb_in[3];
	for (i = 4; i < 21; i++)
		*mb_dst++ = RD_REG_WORD(&mb_regs[i]);
	if (code == QLA_XMC_BAD_CODE) {
		/* override message code */
		vme->msg.code = code;
		vme->saved_code = orig_code;
	}
	vme->is_unread = 1;
	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11033,
		"SR-IOV: VDC - scheduling message, code=%u (orig=%u), version=%u, status=%u.\n",
		code, orig_code, vme->msg.version, vme->msg.status);

	if (!vme->is_solicited) {
		spin_lock_irqsave(&ha->sriov.lock, flags);
		list_add_tail(&vme->vdc_next, &ha->sriov.vdc_head);
		spin_unlock_irqrestore(&ha->sriov.lock, flags);
		queue_work(qla_work_q, &vme->u.work);
	} else {
		complete(&vme->u.comp);
		kref_put(&vme->kref, qla_xf_free_vme);
	}

}

ssize_t
qla_sriov_pf_sys_vf_usage(struct device *dev, struct device_attribute *attr,
	char *buf)
{
	/* scsi_qla_host_t *vha = shost_priv(class_to_shost(dev)); */
	/* struct qla_hw_data *ha = vha->hw; */

	return scnprintf(buf, PAGE_SIZE,
			"Content format: VF_Index:Node_WWN:Port_WWN\n");
}

ssize_t
qla_sriov_pf_sys_vf_cfg_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	scsi_qla_host_t *vha = shost_priv(class_to_shost(dev));
	struct qla_hw_data *ha = vha->hw;
	int vfi;
	unsigned long int nwwn, pwwn;
	int ret;

	if (sscanf(buf, "%d:%lx:%lx", &vfi, &nwwn, &pwwn) < 1)
		return -EINVAL;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11034,
		"SR-IOV: vfi=%u nwwn=0x%lx pwwn=0x%lx.\n", vfi, nwwn, pwwn);

	if (vfi <= 0 || vfi > ha->sriov.num_enabled_vfs) {
		if (ha->sriov.num_enabled_vfs)
			ql_log(ql_log_warn, vha, 0x11035,
				"ERROR: SR-IOV: Index %u is out of range. Index (a positive value) of the highest enabled VF is %u.\n",
				vfi, ha->sriov.num_enabled_vfs);
		else
			ql_log(ql_log_warn, vha, 0x11036,
				"ERROR: SR-IOV: No VFs are enabled.\n");
		return -EINVAL;
	}

	ret = qla_pf_add_vf(ha, (uint8_t)vfi, nwwn, pwwn);
	if (ret)
		return ret;

	ql_dbg(ql_dbg_sriov, vha, 0x11037,
		"SR-IOV: Configured VF: %u/0x%lx/0x%lx.\n", vfi, nwwn, pwwn);

	return count;
}

ssize_t
qla_sriov_pf_sys_vf_decfg_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	scsi_qla_host_t *vha = shost_priv(class_to_shost(dev));
	struct qla_hw_data *ha = vha->hw;
	int vfi;
	unsigned long int nwwn, pwwn;
	int ret;
	struct qla_sriov_vf *vf;

	if (sscanf(buf, "%d:%lx:%lx", &vfi, &nwwn, &pwwn) < 1)
		return -EINVAL;

	ql_dbg(ql_dbg_sriov + ql_dbg_verbose, vha, 0x11038,
		"SR-IOV: vfi=%u nwwn=0x%lx pwwn=0x%lx.\n", vfi, nwwn, pwwn);

	vf = qla_pf_get_vf(ha, 0, pwwn);
	if (!vf || vf->index != (uint8_t)vfi || vf->node_wwn != nwwn ||
		vf->port_wwn != pwwn) {
		ql_log(ql_log_warn, vha, 0x11039,
			"ERROR: SR-IOV: Could not find record for %u:%lx:%lx info.\n",
			vfi, nwwn, pwwn);
		return -ENOENT;
	}

	ret = qla_pf_remove_vf(ha, pwwn);
	WARN(ret, "%s: SR-IOV: Unexpected error code %d during remove.\n",
					__func__, -ret);
	if (ret)
		return ret;

	ql_dbg(ql_dbg_sriov, vha, 0x1103a,
		"SR-IOV: Deconfigured VF: %u/0x%lx/0x%lx.\n", vfi, nwwn, pwwn);

	return count;
}

/*
 * Interface that gets called during pci probe time.
 *
 */
int
qla_sriov_xf_probe(void *data, uint8_t context)
{
	int ret, pos;
	uint16_t num_vf;
	struct qla_hw_data *ha = data;	/* context > 0 */
	struct pci_dev *pdev = data;	/* context = 0 */

	if (context > 1 && !ha->flags.sriov_enabled)
		return 0;

	switch (context) {
	case 0:
		/* Do not claim VF unless ql2xsriov_vf is set. */
		if (!ql2xsriov_vf && IS_VF_DEVICE_ID(pdev->device)) {
			ql_log_pci(ql_log_info, pdev, 0x1103b,
				"SR-IOV: ql2xsriov_vf=0, Not claiming VF id %x.\n",
				pdev->device);
			return -ENODEV;
		}

		return 0;

	case 1: /* Early during probe, after set_isp_flags */
		INIT_LIST_HEAD(&ha->sriov.vf_head);
		INIT_LIST_HEAD(&ha->sriov.vdc_head);
		spin_lock_init(&ha->sriov.lock);
		mutex_init(&ha->sriov.vf_mutex);

		/*
		 * if you hit compile error here, that means you have
		 * exceeded the max permitted size for qla_vdc_message_entry,
		 * fix it to proceed.
		 */
		BUILD_BUG_ON(
			sizeof(struct qla_vdc_message) > QLA_XM_MAX_POSSIBLE);

		if (!ha->dev_type.sriov)
			return 0;

		pdev = ha->pdev;
		pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
		ql_log_pci(ql_log_info, ha->pdev, 0x1103c,
			"SR-IOV capability: %s.\n", pos ? "on" : "off");
		if (pos == 0)
			return 0;

		pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &num_vf);
		if (ql2xnum_vfs > num_vf) {
			ql_log_pci(ql_log_warn, pdev, 0x1103d,
				"SR-IOV: ** HBA is not capable of supporting ql2xnum_vfs VFs, max possible = %d, ignoring ql2xnum_vfs value.\n",
				num_vf);
			return 0;
		}
		ha->flags.sriov_enabled = 1;
		ha->flags.multi_atio = 1;
		break;

	case 2: /* Still early, but after pci_set_drvdata() */
		if (ql2xnum_vfs) {
			ret = qla2xxx_sriov_configure(ha->pdev, ql2xnum_vfs);
			if (ret < 0)
				return ret;
		}
		break;

	default:
		WARN(1, "SR-IOV: %s: Unhandled case %u.\n", __func__, context);
		break;
	}

	return 0;
}

void
qla_sriov_xf_remove(struct qla_hw_data *ha)
{
	if (ha->sriov.num_enabled_vfs)
		qla2xxx_sriov_configure(ha->pdev, 0);
}

/* Interface to create debugfs entries for SR-IOV. */
void
qla_sriov_xf_dfs_entries(struct scsi_qla_host *vha)
{
	struct qla_hw_data *ha = vha->hw;

	if (!ha->flags.sriov_enabled)
		return;

	qla_dfs_vf_cfg_create(vha);
}

int
qla_sriov_mb_pre_check(struct qla_hw_data *ha, uint16_t mb_cmd)
{
	switch (mb_cmd) {
	case MBC_WRITE_REMOTE_REG:
	case MBC_EXECUTE_FIRMWARE:
	case MBC_LOAD_FLASH_FW: /* same as MBC_WRITE_SERDES */
	case MBC_READ_SERDES:
	case MBC_MAILBOX_REGISTER_TEST:
	case MBC_READ_REMOTE_REG:
	case MBC_LOAD_RISC_RAM_EXTENDED:
	case MBC_DUMP_RISC_RAM_EXTENDED:
	case MBC_WRITE_RAM_WORD_EXTENDED:
	case MBC_READ_RAM_EXTENDED:
	case MBC_LOAD_FW_PARAMS:
	case MBC_GEN_SYSTEM_ERROR:
	case MBC_WRITE_SFP:
	case MBC_SOFT_RESET:
	case MBC_RESTART_NIC_FIRMWARE:
	case MBC_FLASH_ACCESS_CTRL:
	case MBC_LOOP_PORT_BYPASS:
	case MBC_LOOP_PORT_ENABLE:
	case MBC_NON_PARTICIPATE:
	case MBC_DIAGNOSTIC_LOOP_BACK:
	case MBC_CONFIGURE_VF:
	case MBC_CONFIGURE_VF_STRIDE:
	case MBC_SET_RNID_PARAMS:
	case MBC_GET_INIT_CB:
	case MBC_LINK_INITIALIZATION:
	case MBC_IDC_REQUEST:
	case MBC_IDC_ACK:
	case MBC_IDC_TIME_EXTEND:
	case MBC_PORT_RESET:
	case MBC_SET_PORT_CONFIG:
	case MBC_SET_LED_CONFIG:
	case MBC_SET_EPORT_INIT_CB_FIELD:
		/* Privileged MBCs only PF/trusted VF can execute. */
		return -EPERM;
	default:
		return 0;
	}
}

void
qla_sriov_xf_module_init()
{
	/* Nothing done now. */
	return;
}

void
qla_sriov_xf_module_exit()
{
	/* Nothing done now. */
	return;
}
/************** Exported interfaces: All starts with qla_sriov_ **************/
#endif /* QLA_ENABLE_SRIOV */
