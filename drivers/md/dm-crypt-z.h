#ifndef	DM_CRYPT_ZADARA_H
#define	DM_CRYPT_ZADARA_H

struct dm_crypt_read_arg {
	void __user *ubuff;	/* [out] user-space data buffer */
	__u64 read_sector;	/* [in] start sector number, used for read */
	__u64 crypt_sector;	/* [in] start sector number, used for decryption */
	__u32 len_bytes;	/* [in] buffer size */
};

struct dm_crypt_write_arg {
	void __user *ubuff;		/* [in] user-space data buffer */
	void __user *cbuff;		/* [out] user-space encrypted buffer */
	__u64 crypt_sector;		/* [in] start sector number, used for encryption */
	__u32 len_bytes;		/* [in] buffer size */
};

#define DMCRYPT_IOC_MAGIC   0xC2
#define DMCRYPT_IOC_READ	_IOW(DMCRYPT_IOC_MAGIC,	0, struct dm_crypt_read_arg)
#define DMCRYPT_IOC_WRITE	_IOW(DMCRYPT_IOC_MAGIC,	1, struct dm_crypt_write_arg)


#endif
