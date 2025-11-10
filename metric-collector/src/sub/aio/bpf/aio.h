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
#endif /* _AIO_H */
