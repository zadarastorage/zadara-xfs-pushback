#ifndef ZADARA_ISCSI_H
#define ZADARA_ISCSI_H

#ifndef CONFIG_SCSI_ZADARA
#error
#endif

#undef iscsi_conn_printk
#define iscsi_conn_printk(prefix, _c, fmt, a...) \
	iscsi_cls_conn_printk(prefix, ((struct iscsi_conn *)_c)->cls_conn, \
			      "target %s: "fmt, ((struct iscsi_conn *)_c)->session->targetname, ##a)

#undef iscsi_session_printk
#define iscsi_session_printk(prefix, _sess, fmt, a...)	\
	iscsi_cls_session_printk(prefix, _sess->cls_session, "target %s: "fmt, _sess->targetname, ##a)

#endif /* ZADARA_ISCSI_H */