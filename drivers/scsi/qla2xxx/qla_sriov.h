/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2015 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#ifndef __QLA_SRIOV_H
#define __QLA_SRIOV_H
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/pci.h>

struct scsi_qla_host;
struct qla_hw_data;

#ifdef QLA_ENABLE_SRIOV
struct qla_sriov_vf {
	struct list_head vf_next;
	uint32_t is_enabled:1;
	uint32_t is_initialized:1;
	int index;
	uint64_t node_wwn;
	uint64_t port_wwn;
};

struct qla_sriov_data {
	spinlock_t lock;
	struct mutex vf_mutex;
	uint32_t num_enabled_vfs;
	atomic_t msg_seq_num;
	struct list_head vf_head; /* struct struct qla_sriov_vf */
	struct list_head vdc_head; /* struct qla_vdc_message_entry */
};

/* Control of what modes VF should have. */
#define SRIOV_VF_DISABLE_INI_MODE()	0
#define SRIOV_VF_DISABLE_TGT_MODE()	0
#define QLA_XM_MAX_POSSIBLE		40
#define QLA_XM_MAX_DATA			(QLA_XM_MAX_POSSIBLE - 4)
struct qla_xm_vf_info {
	uint8_t node_name[8];
	uint8_t port_name[8];
};

struct qla_xm_vf_rst_notify {
	uint32_t reset_count;
};

#define QLA_XM_MSG_WAIT		(10 * HZ)
#define QLA_XM_SEQ_NUM(_ha) \
		((uint8_t)atomic_inc_return(&_ha->sriov.msg_seq_num))

/*
 * Separate code shall be used for message originating from PFs and VFs.
 */
#define QLA_XMC_RESPONSE_BIT	0x80
enum qla_xmc {
	/* All VF originating message codes here. */
	QLA_XMC_VF_START = 1,
	QLA_XMC_VF_INFO = QLA_XMC_VF_START,	/* Gets VF's WWNs */

	QLA_XMC_VF_LAST, /* Keep this the last VF code. */

	/* All PF originating message codes here. */
	QLA_XMC_PF_START = 100,
	QLA_XMC_PF_INFO = QLA_XMC_PF_START,	/* Gets VF's version; could
						   change after VF driver
						   unload, use with caution!;
						   maybe ok after VF_INFO
						   call */
	QLA_XMC_PF_RESET_NOTIFY,

	QLA_XMC_PF_LAST, /* Keep this the last PF code. */
	QLA_XMC_BAD_CODE,
};
#ifndef U8_MAX
#define U8_MAX		((u8)~0U)
#endif
struct qla_vdc_message {
#define QLA_XM_VERSION		1
	uint8_t version;
	uint8_t code;
	uint8_t seq_num;

#define QLA_XMS_GOOD		1
#define QLA_XMS_FAILED		2
#define QLA_XMS_UKNOWN_CODE	0xff
	uint8_t status;

	union {
		struct qla_xm_vf_info vf_info;
		struct qla_xm_vf_rst_notify rst_notify;
		uint8_t data[QLA_XM_MAX_DATA];
	} u;
};

/*
 * Structure to cache received VDC AENs. Only one entry per source
 * function + msg.code is allowed. Multiple messages with the same source
 * function and code get dropped.
 */
struct qla_vdc_message_entry {
	struct scsi_qla_host *vha;
	struct kref kref; /* Used for solicited */
	struct list_head vdc_next;
	uint8_t is_unread:1;	/* Unread message, used for solicited msgs. */
	uint8_t is_comp_type:1; /* 1:comp, 0:work to be used in the union. */
	uint8_t is_solicited:1;
	uint8_t source_func;	/* Source of this message - for unsolicited.
				 * Expected source - for solicited.
				 */
	uint8_t saved_code;	/* For bad message code handling. */
	union {
		struct completion comp;		/* is_comp_type = 1 */
		struct work_struct work;	/* is_comp_type = 0 */ 
	} u;
	struct qla_vdc_message msg;
};
/* External functions. */
extern void qla_sriov_xf_module_init(void);
extern void qla_sriov_xf_module_exit(void);
extern int qla2xxx_sriov_configure(struct pci_dev *dev, int numvfs);
extern int qla_sriov_xf_probe(void *data, uint8_t context);
extern void qla_sriov_xf_remove(struct qla_hw_data *ha);
extern int qla_sriov_pf_adapter_init(struct qla_hw_data *ha, uint8_t context);
extern void qla_sriov_pf_handle_vdc_aen(struct scsi_qla_host *vha,
	uint16_t *mb_in);
extern int qla_sriov_vf_nvram_config(struct scsi_qla_host *vha);
extern int qla_sriov_vf_setup_chip(struct scsi_qla_host *vha);
extern void qla_sriov_vf_reset_chip(struct scsi_qla_host *vha);
extern ssize_t qla_sriov_pf_sys_vf_usage(struct device *dev,
	struct device_attribute *attr, char *buf);
extern ssize_t qla_sriov_pf_sys_vf_cfg_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count);
extern ssize_t qla_sriov_pf_sys_vf_decfg_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count);
extern int qla_sriov_mb_pre_check(struct qla_hw_data *ha, uint16_t mb_cmd);
extern void qla_sriov_xf_dfs_entries(struct scsi_qla_host *vha);
/* External functions. */

#ifndef CONFIG_QLA2XXX_ZADARA
#define DEFINE_QLA_SRIOV_DEVICE_ATTR \
	static DEVICE_ATTR(vf_configure, S_IRUGO|S_IWUSR, \
		qla_sriov_pf_sys_vf_usage, qla_sriov_pf_sys_vf_cfg_store); \
	static DEVICE_ATTR(vf_deconfigure, S_IRUGO|S_IWUSR, \
		qla_sriov_pf_sys_vf_usage, qla_sriov_pf_sys_vf_decfg_store);
#else /*CONFIG_QLA2XXX_ZADARA*/
/*
 * We need to access vf_configure/deconfigure from "nova" user,
 * so cannot use DEVICE_ATTR, which uses __ATTR, which uses
 * VERIFY_OCTAL_PERMISSIONS, which doesn't allow to give writable
 * access to "OTHER".
 */
#define DEFINE_QLA_SRIOV_DEVICE_ATTR                                       \
	static struct device_attribute dev_attr_vf_configure = {               \
		.attr = {.name = "vf_configure", .mode = S_IRUGO|S_IWUGO},         \
		.show = qla_sriov_pf_sys_vf_usage,                                 \
		.store = qla_sriov_pf_sys_vf_cfg_store                             \
	};                                                                     \
	static struct device_attribute dev_attr_vf_deconfigure = {             \
		.attr = {.name = "vf_deconfigure", .mode = S_IRUGO|S_IWUGO},       \
		.show = qla_sriov_pf_sys_vf_usage,                                 \
		.store = qla_sriov_pf_sys_vf_decfg_store                           \
	};
#endif /*CONFIG_QLA2XXX_ZADARA*/

#define DEFINE_QLA_SRIOV_DEVICE_ATTR_STRUCT	\
	&dev_attr_vf_configure,		\
	&dev_attr_vf_deconfigure,

extern int ql2xsriov_vf;
extern int ql2xsriov;
extern int ql2xnum_vfs;
#define DEFINE_QLA_SRIOV_MODULE_PARAMS \
	int ql2xsriov_vf; \
	module_param(ql2xsriov_vf, int, S_IRUGO|S_IWUSR); \
	MODULE_PARM_DESC(ql2xsriov_vf, "SR-IOV Function claim switch.\n" \
			"\t0 => Claim only FC Physical Functions (default)." \
			"\t1 => Claim only FC Virtual Functions."); \
	int ql2xsriov; \
	module_param(ql2xsriov, int, S_IRUGO|S_IWUSR); \
	MODULE_PARM_DESC(ql2xsriov, "SR-IOV Debug Flags."); \
	int ql2xnum_vfs; \
	module_param(ql2xnum_vfs, int, S_IRUGO|S_IWUSR); \
	MODULE_PARM_DESC(ql2num_vfs, \
			"Number of VFs to be created (default=0).");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
/* Y&P of pcie_flr code. */
static inline int
qla_pcie_flr(struct pci_dev *dev)
{
        int i;
        int pos;
        u32 cap;
        u16 status, control;

        pos = pci_pcie_cap(dev);
        if (!pos)
                return -ENOTTY;

        pci_read_config_dword(dev, pos + PCI_EXP_DEVCAP, &cap);
        if (!(cap & PCI_EXP_DEVCAP_FLR))
                return -ENOTTY;

	pci_save_state(dev);

        /* Wait for Transaction Pending bit clean */
        for (i = 0; i < 4; i++) {
                if (i)
                        msleep((1 << (i - 1)) * 100);

                pci_read_config_word(dev, pos + PCI_EXP_DEVSTA, &status);
                if (!(status & PCI_EXP_DEVSTA_TRPND))
                        goto clear;
        }

        dev_err(&dev->dev, "qla2xxx: transaction is not cleared; "
                        "proceeding with reset anyway\n");

clear:
        pci_read_config_word(dev, pos + PCI_EXP_DEVCTL, &control);
        control |= PCI_EXP_DEVCTL_BCR_FLR;
        pci_write_config_word(dev, pos + PCI_EXP_DEVCTL, control);

        msleep(100);

	pci_restore_state(dev);
        return 0;
}

#endif

static inline int
qla_vf_reset(struct pci_dev *pdev)
{
	int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
	ret = qla_pcie_flr(pdev);
#else
	ret = pci_try_reset_function(pdev);
#endif /* LINUX_VERSION_CODE .. */
	return ret;
}

#else /* QLA_ENABLE_SRIOV */

#define QLA_SRIOV_PF_CLAIMED_VF_IDS
#define DEFINE_QLA_SRIOV_DEVICE_ATTR
#define DEFINE_QLA_SRIOV_DEVICE_ATTR_STRUCT
#define DEFINE_QLA_SRIOV_MODULE_PARAMS
#define DEFINE_QLA_SRIOV_PCI_TABLE_VF

static inline void
qla_sriov_xf_module_init(void) { return; }
static inline void
qla_sriov_xf_module_exit(void) { return; }
static inline int
qla2xxx_sriov_configure(struct pci_dev *dev, int numvfs) { return -ENOTSUPP; }
static inline int
qla_sriov_xf_probe(void *data, uint8_t context) { return 0; }
static inline void
qla_sriov_xf_remove(struct qla_hw_data *ha) { return; }
static inline int
qla_sriov_pf_adapter_init(struct qla_hw_data *ha, uint8_t context) { return 0; }
static inline void
qla_sriov_pf_handle_vdc_aen(struct scsi_qla_host *vha, uint16_t *mb_in)
	{ return; }
static inline int
qla_sriov_vf_nvram_config(struct scsi_qla_host *vha) { return 0; }
static inline int
qla_sriov_vf_setup_chip(struct scsi_qla_host *vha) { return 0; }
static inline void
qla_sriov_vf_reset_chip(struct scsi_qla_host *vha) { return; }
static inline int
qla_sriov_mb_pre_check(struct qla_hw_data *ha, uint16_t mb_cmd) { return 0; }
static inline void
qla_sriov_xf_dfs_entries(struct scsi_qla_host *vha) { return; }

#endif /* QLA_ENABLE_SRIOV */
#endif /* __QLA_SRIOV_H */
