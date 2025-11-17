#ifndef _AIO_H
#define _AIO_H

struct inflight_value;
struct to_update_key;
struct granularity;
struct stats;


struct inflight_key {
	__u64 tgid_pid;
};

struct inflight_value {
	__u64 ts;
    void *aioctx;
};

struct granularity {
	__u32 tgid;
    __u32 pid;
	void *aioctx;
    __u8 op;
};

struct stats {
	__u64 ts_s;
	__u64 total_time;
	__u32 total_requests;
};

struct to_update_key {
	__u64 ts;
	struct granularity granularity;
};

struct to_update_value {
    __u64 additional_time;
};

struct file_prep_value {
    __u64 ts;
    __u8  mode;
};

struct vfs_bri {
	__u32 fs_magic;
	__u32 i_rdev;
	__u64 i_ino;
};

struct blockdev {
	__u64 part0;
	__u64 dev;
};

struct file_granularity {
    u64            aioctx;
    union {
        struct vfs_bri  bri;
        struct blockdev bdev;
    };
    __u8            isreg;
    __u8            mode;
};

struct file_stats {
	__u64 ts_s;
	__u32 hist[8];
};
#endif /* _AIO_H */
