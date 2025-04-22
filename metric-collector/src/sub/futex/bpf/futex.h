#ifndef __FUTEX_H
#define __FUTEX_H

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256

struct inflight_key {
	__u64 tgid_pid;
};

struct inflight_value {
	__u64 ts;
	union futex_key fkey;
    u8 op;
};

struct granularity {
	__u32 tgid;
    __u32 pid;
	union futex_key fkey;
	__u8 op;
} granularity;
 
struct wait_stats {
	__u64 ts_s;
	__u64 total_requests;
	__u64 total_time;
	__u32 hist[8];
} wait_stats;

struct wake_stats {
    __u64 ts_s;
	__u64 total_requests;
	__u64 successful_count;
};

union stats {
    struct wake_stats wake;
    struct wait_stats wait;
    struct {
        __u64 ts_s;
	    __u64 total_requests;
    } both;
} stats;

struct to_update_key {
	__u64 ts;
	struct granularity granularity;
};

#endif /* __FUTEX_H */

