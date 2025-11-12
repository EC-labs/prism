#ifndef _MUX_H
#define _MUX_H

struct inflight_value;
struct to_update_key;
struct granularity;
struct stats;

struct vfs_bri {
	__u32 fs_magic;
	__u32 i_rdev;
	__u64 i_ino;
};

struct file_wake_ts_key {
    struct vfs_bri  bri;
    __u64           id;
    __u8            mode;
};

struct file_granularity {
    struct vfs_bri  bri;
    __u64           id;
    __u8            mode;
};

struct file_stats {
	__u64 ts_s;
	__u32 hist[8];
};

struct inflight_key {
	__u64 tgid_pid;
};

struct inflight_value {
	__u64 ts;
    void *ep;
};

struct granularity {
	__u32 tgid;
    __u32 pid;
	void *ep;
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
#endif /* _MUX_H */
