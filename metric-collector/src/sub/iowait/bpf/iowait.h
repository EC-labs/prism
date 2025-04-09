#ifndef __IOWAIT_H
#define __IOWAIT_H

struct inflight {
    __u64 sector;
    __u32 part0;
    __u32 bdev;
    __u32 op;
    __u32 status;
};

struct inflight_val {
    __u64 ts;
    __u64 size;
    __u64 pid_tgid;
};

struct granularity {
    __u32 tgid;
    __u32 pid;
    __u64 part0;
    __u64 bdev;
};

struct stats {
    __u64 ts_s;
    __u64 total_time;
    __u32 sector_cnt;
    __u32 total_requests;
    __u32 hist[8];
};


#endif /* __IOWAIT_H */
