#ifndef _COMMON_H
#define _COMMON_H

#include <consts.h>

__always_inline static void discover_tgid(void *pids, void *pid_rb, __u32 tgid) 
{
    bpf_map_update_elem(pids, &tgid, &truth, BPF_ANY);
    bpf_ringbuf_output(pid_rb, &tgid, sizeof(tgid), 0);
}

__always_inline __u32 get_tgid(__u64 tgid_pid) 
{
    return (u32) (tgid_pid >> 32);
}

__always_inline __u32 get_pid(__u64 tgid_pid) 
{
    return tgid_pid & (((u64) 1<<32) - 1);
}

__always_inline u64 min(u64 x, u64 y) 
{
    return x < y ? x : y;
}

__always_inline __u32 log_base10_bucket(__u64 ns_diff) 
{
    __u32 bucket = 7;
    if(ns_diff <= 1000) {
        bucket = 0;
    } else if ( ns_diff <= 10000) {
        bucket = 1;
    } else if ( ns_diff <= 100000) {
        bucket = 2;
    } else if ( ns_diff <= 1000000) {
        bucket = 3;
    } else if ( ns_diff <= 10000000) {
        bucket = 4;
    } else if ( ns_diff <= 100000000) {
        bucket = 5;
    } else if ( ns_diff <= 1000000000) {
        bucket = 6;
    } else {
        bucket = 7;
    }
    return bucket;
}

#endif /* _COMMON_H */
