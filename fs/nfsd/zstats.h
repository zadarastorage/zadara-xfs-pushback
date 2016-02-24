#ifndef LINUX_NFSD_ZSTATS_H
#define LINUX_NFSD_ZSTATS_H

int zstats_init(void);
void zstats_fini(void);
int zstats_proc_create(void);
void zstats_proc_remove(void);

unsigned long zstats_svc_rqst_start(const struct svc_rqst *rqst);
void zstats_svc_rqst_set_export(const struct svc_rqst *rqst, const struct svc_export *fh_export);
void zstats_svc_rqst_end(const struct svc_rqst *rqst, __be32 nfserr, unsigned long start_time);

int zstats_export_get_zshareid(const struct svc_export *fh_export, u64 *share_id);

#endif // LINUX_NFSD_ZSTATS_H
