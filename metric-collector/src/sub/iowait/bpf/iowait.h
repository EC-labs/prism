#ifndef __IOWAIT_H
#define __IOWAIT_H

struct inflight {
    __u32 part0;
    __u64 sector;
    __u32 op;
} inflight;

struct inflight_val {
    __u64 ts;
    __u64 pid_tgid;
    __u32 bdev;
    __u64 size;
} inflight_val;

struct granularity {
    __u32 tgid;
    __u32 pid;
    __u64 part0;
    __u64 bdev;
} granularity;

struct stats {
    __u64 ts_s;
    __u64 total_time;
    __u32 sector_cnt;
    __u32 total_requests;
    __u32 hist[8];
} stats;


#endif /* __IOWAIT_H */
