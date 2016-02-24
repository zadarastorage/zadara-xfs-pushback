#ifdef CONFIG_BTRFS_ZADARA
#ifndef __ZMISC_HDR__
#define __ZMISC_HDR__

/*********** MISC ************************************/
#define ENUM_TO_STR(a, e, base)							           \
({																   \
	int __idx = (int)(e - base);								   \
	bool __in_range = (__idx >= 0 && __idx < (int)ARRAY_SIZE(a));  \
	__in_range ? (a)[__idx] : "?";								   \
})

#define SAME_OFFSET_AND_SIZE(type1, member1, type2, member2)                         \
	BUILD_BUG_ON(sizeof(((type1 *)0)->member1) != sizeof(((type2 *)0)->member2) ||   \
	             offsetof(type1, member1) != offsetof(type2, member2))

/*********** capacity conversions etc ****************/
#define	ONE_KB	(1024)
#define	ONE_MB	(1024*1024)
#define	ONE_GB	(1024*1024*1024)
#define BYTES_TO_KB(b)		((b) >> 10)
#define BYTES_TO_MB(b)		((b) >> 20)
#define BYTES_TO_GB(b)		((b) >> 30)

/* returns amount of bytes truncated to block size */
#define BYTES_TRUNCATE_TO_BLK(type, b)     \
({                                         \
	type __res = BYTES_TO_BLK(b);          \
	__res = BLK_TO_BYTES(__res);           \
	__res;                                 \
})

/************ time measurements ****************************/
#define ZTIME_START() ktime_get()
#define ZTIME_NS_ELAPSED_BETWEEN(_start_time, _end_time)   ktime_to_ns(ktime_sub((_end_time), (_start_time)))
#define ZTIME_US_ELAPSED_BETWEEN(_start_time, _end_time)   ktime_to_us(ktime_sub((_end_time), (_start_time)))
#define ZTIME_MS_ELAPSED_BETWEEN(_start_time, _end_time)   ktime_to_ms(ktime_sub((_end_time), (_start_time)))

#define ZTIME_NS_ELAPSED(_start_time)                                     \
({																		  \
	ktime_t _end_time = ktime_get();                                      \
	u64 _elapsed_ns = ZTIME_NS_ELAPSED_BETWEEN((_start_time), _end_time); \
	_elapsed_ns;                                                          \
})

#define ZTIME_US_ELAPSED(_start_time)                                     \
({																		  \
	ktime_t _end_time = ktime_get();                                      \
	u64 _elapsed_us = ZTIME_US_ELAPSED_BETWEEN((_start_time), _end_time); \
	_elapsed_us;                                                          \
})

#define ZTIME_MS_ELAPSED(_start_time)                                     \
({																		  \
	ktime_t _end_time = ktime_get();                                      \
	u64 _elapsed_ms = ZTIME_MS_ELAPSED_BETWEEN((_start_time), _end_time); \
	_elapsed_ms;                                                          \
})

#endif /*__ZMISC_HDR__*/
#endif /*CONFIG_BTRFS_ZADARA*/

