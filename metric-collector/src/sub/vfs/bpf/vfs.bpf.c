// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vfs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_MAX_ENTRIES);
    __type(key, struct inflight_key);
    __type(value, struct inflight_value);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_MAX_ENTRIES);
    __type(key, struct to_update_key);
    __type(value, u64);
} to_update SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct bri);
    __type(value, bool);
} bris SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, bool);
} pids SEC(".maps");

struct inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SAMPLE_MAX_ENTRIES);
    __type(key, struct granularity);
    __type(value, struct stats);
} completed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, SAMPLES);
    __uint(key_size, sizeof(u64));
    __array(values, struct inner);
} samples SEC(".maps");

inline u32 pid(u64 tgid_pid) {
    return tgid_pid & (((u64) 1<<32) - 1);
}

inline u32 tgid(u64 tgid_pid) {
    return tgid_pid >> 32;
}

__u32 log_base10_bucket(__u64 ns_diff) {
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

u64 min(u64 x, u64 y) {
    return x < y ? x : y;
}


SEC("fentry/vfs_read")
int BPF_PROG(vfs_read, struct file *file)
{
    struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    umode_t i_mode = BPF_CORE_READ(f_inode, i_mode);
    if (((i_mode & S_IFMT) == S_IFIFO) || ((i_mode & S_IFMT) == S_IFCHR)) {
        u64 tgid_pid = (u64) bpf_get_current_pid_tgid();
        u32 tgid = (u32) (tgid_pid >> 32);
        struct bri file;
        file.i_ino = BPF_CORE_READ(f_inode, i_ino);
        file.i_rdev = BPF_CORE_READ(f_inode, i_rdev);
        file.fs_magic = BPF_CORE_READ(f_inode, i_sb, s_magic);
        // BPF_CORE_READ_INTO(&file.s_id, f_inode, i_sb, s_id);
        bool truth = true;
        bool *filep = bpf_map_lookup_elem(&bris, &file);
        bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
        if (!filep) {
            if (!pidp)
                return 0;
            bpf_map_update_elem(&bris, &file, &truth, BPF_ANY);
        }

        if (!pidp) {
            bpf_map_update_elem(&pids, &tgid, &truth, BPF_ANY);
            bpf_printk("[vfs] discovered tgid: %u %s %u %llu", tgid, file.fs_magic, file.i_rdev, file.i_ino);
        }

        struct inflight_key key = {
            .tgid_pid = tgid_pid,
        };
        struct inflight_value value = {0};
        value.bri = file;
        value.ts = bpf_ktime_get_ns();
        value.is_write = READ;
        bpf_map_update_elem(&pending, &key, &value, BPF_ANY);
        // bpf_printk("st: %d %d %s %d %lld %c => %lld", 
        //        tgid, pid(key.tgid_pid), value.bri.s_id,
        //        value.bri.i_rdev, value.bri.i_ino, value.is_write == READ ? 'R' : 'W', value.ts);
    }
    return 0;
}


void to_update_acct(u64 start, u64 curr, struct granularity gran) {
    u64 sample = (curr / 1000000000) * 1000000000;
    if (start >= sample) {
        return;
    }

    // bpf_printk("Storing in to_update: %lld %lld", start, curr);
    struct to_update_key key = {0};
    key.ts = start;
    key.granularity = gran;
    bpf_map_update_elem(&to_update, &key, &sample, BPF_ANY);
}

SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, ssize_t ret)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct inflight_value *value = bpf_map_lookup_elem(&pending, &tgid_pid);
    if (!value) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 sample = (ts / 1000000000) % SAMPLES;
    struct inner *inner = bpf_map_lookup_elem(&samples, &sample);
    if (!inner) {
        return 0;
    }

    struct granularity gran = {0};
    gran.tgid = tgid(tgid_pid);
    gran.pid = pid(tgid_pid);
    gran.bri.i_ino = value->bri.i_ino;
    gran.bri.i_rdev = value->bri.i_rdev;
    gran.bri.fs_magic = value->bri.fs_magic;
    gran.dir = READ;
    // __builtin_memcpy(&gran.bri.s_id, &(*value).bri.s_id, sizeof(gran.bri.s_id));
    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (stat == NULL) {
        struct stats init = {0};
        init.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_ANY);

        stat = bpf_map_lookup_elem(inner, &gran);
        if (!stat) {
            return 0;
        }
    }

    __u64 sample_latency = min(ts - value->ts, ts - (ts/1000000000) * 1000000000);
    __u64 ns_latency = ts - value->ts;
    __u32 bucket = log_base10_bucket(ns_latency);
    __sync_fetch_and_add(&stat->total_requests, 1);
    __sync_fetch_and_add(&stat->total_time, sample_latency);
    __sync_fetch_and_add(stat->hist + bucket, 1);

    to_update_acct(value->ts, ts, gran);
    
    // bpf_printk("en: %d %d %s %d %lld %c => %lld %lld", 
    //        gran.tgid, gran.pid, gran.bri.s_id,
    //        gran.bri.i_rdev, gran.bri.i_ino, gran.dir == READ ? 'R' : 'W', ts, ts - value->ts);
    bpf_map_delete_elem(&pending, &tgid_pid);
    return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(vfs_write, struct file *file, char *buf, size_t count, loff_t *pos)
{
    struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    umode_t i_mode = BPF_CORE_READ(f_inode, i_mode);
    if (((i_mode & S_IFMT) == S_IFIFO) || ((i_mode & S_IFMT) == S_IFCHR)) {
        u64 tgid_pid = (u64) bpf_get_current_pid_tgid();
        u32 tgid = (u32) (tgid_pid >> 32);
        struct bri file;
        file.i_ino = BPF_CORE_READ(f_inode, i_ino);
        file.i_rdev = BPF_CORE_READ(f_inode, i_rdev);
        file.fs_magic = BPF_CORE_READ(f_inode, i_sb, s_magic);
        // BPF_CORE_READ_INTO(&file.s_id, f_inode, i_sb, s_id);
        bool truth = true;
        bool *filep = bpf_map_lookup_elem(&bris, &file);
        bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
        if (!filep) {
            if (!pidp) {
                return 0;
            }
            bpf_map_update_elem(&bris, &file, &truth, BPF_ANY);
        }

        if (!pidp) {
            bpf_map_update_elem(&pids, &tgid, &truth, BPF_ANY);
            bpf_printk("[vfs] discovered tgid: %u %s %u %llu", tgid, file.fs_magic, file.i_rdev, file.i_ino);
        }

        struct inflight_key key = {
            .tgid_pid = tgid_pid,
        };
        struct inflight_value value = {0};
        value.bri = file;
        value.ts = bpf_ktime_get_ns();
        value.is_write = WRITE;
        bpf_map_update_elem(&pending, &key, &value, BPF_ANY);
        // bpf_printk("st: %d %d %s %d %lld %c => %lld", 
        //        tgid, pid(key.tgid_pid), value.bri.s_id,
        //        value.bri.i_rdev, value.bri.i_ino, value.is_write == READ ? 'R' : 'W', value.ts);
    }
    return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit, ssize_t ret)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct inflight_value *value = bpf_map_lookup_elem(&pending, &tgid_pid);
    if (!value)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    u64 sample = (ts / 1000000000) % SAMPLES;
    struct inner *inner = bpf_map_lookup_elem(&samples, &sample);
    if (!inner)
        return 0;

    struct granularity gran = {0};
    gran.tgid = tgid(tgid_pid);
    gran.pid = pid(tgid_pid);
    gran.bri.i_ino = value->bri.i_ino;
    gran.bri.i_rdev = value->bri.i_rdev;
    gran.bri.fs_magic = value->bri.fs_magic;
    gran.dir = value->is_write;
    // __builtin_memcpy(&gran.bri.s_id, &(*value).bri.s_id, sizeof(gran.bri.s_id));
    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (stat == NULL) {
        struct stats init = {0};
        init.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_ANY);

        stat = bpf_map_lookup_elem(inner, &gran);
        if (!stat)
            return 0;
    }

    __u64 sample_latency = min(ts - value->ts, ts - (ts/1000000000) * 1000000000);
    __u64 ns_latency = ts - value->ts;
    __u32 bucket = log_base10_bucket(ns_latency);
    __sync_fetch_and_add(&stat->total_requests, 1);
    __sync_fetch_and_add(&stat->total_time, sample_latency);
    __sync_fetch_and_add(stat->hist + bucket, 1);

    to_update_acct(value->ts, ts, gran);
    
    // bpf_printk("en: %d %d %s %d %lld %c => %lld %lld", 
    //        gran.tgid, gran.pid, gran.bri.s_id,
    //        gran.bri.i_rdev, gran.bri.i_ino, gran.dir == READ ? 'R' : 'W', ts, ts - value->ts);
    bpf_map_delete_elem(&pending, &tgid_pid);
    return 0;
}
