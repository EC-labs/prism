// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "futex.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, union futex_key);
    __type(value, bool);
} futex_keys SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, bool);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u32) * 8192);
} pid_rb SEC(".maps");

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
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, union futex_key *);
} current_key SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} current_tgid_pid SEC(".maps");

struct inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SAMPLE_MAX_ENTRIES);
    __type(key, struct granularity);
    __type(value, union stats);
} completed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, SAMPLES);
    __uint(key_size, sizeof(u64));
    __array(values, struct inner);
} samples SEC(".maps");

static __u32 zero = 0;
static bool truth = true;

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

SEC("fentry/get_futex_key")
int BPF_PROG(get_futex_key, u32 *uaddr, unsigned int flags, union futex_key *key, enum futex_access rw)
{
    u64 *tgid_pid = bpf_map_lookup_elem(&current_tgid_pid, &zero);
    if (tgid_pid == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&current_tgid_pid, &zero);
    bpf_map_update_elem(&current_key, &zero, &key, BPF_ANY);
    return 0;
}


SEC("fexit/get_futex_key")
int BPF_PROG(get_futex_key_exit, int ret)
{
    struct futex_key_struct **fkey = bpf_map_lookup_elem(&current_key, &zero);
    if (!fkey)
        return 0;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = (u32) (tgid_pid >> 32);
    struct inflight_value *value = bpf_map_lookup_elem(&pending, &tgid_pid);

    union futex_key deref_key;
    bpf_probe_read(&deref_key, sizeof(deref_key), *fkey);
    bool *key_present = bpf_map_lookup_elem(&futex_keys, &deref_key);

    if ((value != NULL) && (key_present == NULL)) {
        bpf_map_update_elem(&futex_keys, &deref_key, &truth, BPF_ANY);
        // bpf_printk("adding key: %llu %llu %u", 
        //            deref_key.both.ptr, deref_key.both.word, deref_key.both.offset);
    } else if ((value == NULL) && (key_present != NULL)) {
        bpf_map_update_elem(&pids, &tgid, &truth, BPF_ANY);
        bpf_ringbuf_output(&pid_rb, &tgid, sizeof(tgid), 0);
        bpf_printk("[futex] discovered tgid: %u %llu %llu %u", tgid, deref_key.both.ptr, deref_key.both.word, deref_key.both.offset);
        return 0;
    }

    if (value == NULL) {
        return 0;
    }

    __builtin_memcpy(&value->fkey, &deref_key, sizeof(deref_key));
    bpf_map_delete_elem(&current_key, &zero);
    return 0;
}

SEC("tp/syscalls/sys_enter_futex")
int futex_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = (u32) (tgid_pid >> 32);

    bool *tgid_present = bpf_map_lookup_elem(&pids, &tgid);
    if (!tgid_present)
        return 0;

    struct inflight_value v = {0};
    v.ts = bpf_ktime_get_ns();

    int op = BPF_CORE_READ(ctx, args[1]);
    op = op & (~FUTEX_PRIVATE_FLAG) & (~FUTEX_CLOCK_REALTIME);

    if ((op == FUTEX_WAIT_BITSET) || (op == FUTEX_WAIT)) {
        v.op = FUTEX_WAIT;
    } else if ((op == FUTEX_WAKE) || (op == FUTEX_WAKE_BITSET)) {
        v.op = FUTEX_WAKE;
    } else {
        bpf_printk("%-15s\t%d", "UnhandledOpcode", op);
        return 0;
    }

    bpf_map_update_elem(&pending, &tgid_pid, &v, BPF_ANY);
    bpf_map_update_elem(&current_tgid_pid, &zero, &tgid_pid, BPF_ANY);
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

SEC("tp/syscalls/sys_exit_futex")
int futex_exit(struct trace_event_raw_sys_enter *ctx) {
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct inflight_value *value = bpf_map_lookup_elem(&pending, &tgid_pid);
    if (value == NULL) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 sample = (ts / 1000000000) % SAMPLES;
    struct inner *inner = bpf_map_lookup_elem(&samples, &sample);
    if (!inner)
        return 0;

    struct granularity gran = {0};
    gran.tgid = tgid(tgid_pid);
    gran.pid = pid(tgid_pid);
    gran.op = value->op;
    __builtin_memcpy(&gran.fkey, &value->fkey, sizeof(gran.fkey));

    union stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (stat == NULL) {
        union stats init = {0};
        init.both.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_ANY);

        stat = bpf_map_lookup_elem(inner, &gran);
        if (!stat)
            return 0;
    }

    __sync_fetch_and_add(&stat->both.total_requests, 1);
    if (gran.op == FUTEX_WAIT) {
        __u64 sample_latency = min(ts - value->ts, ts - (ts/1000000000) * 1000000000);
        __u64 ns_latency = ts - value->ts;
        __u32 bucket = log_base10_bucket(ns_latency);
        __sync_fetch_and_add(&stat->wait.total_time, sample_latency);
        __sync_fetch_and_add(stat->wait.hist + bucket, 1);

        to_update_acct(value->ts, ts, gran);
    } else {
        u32 ret = BPF_CORE_READ(ctx, args[0]);
        __sync_fetch_and_add(&stat->wake.successful_count, ret > 0 ? 1 : 0);
    }


    // bpf_printk("%llu %s %u %llu %llu %u %llu", 
    //            ts, value->op ? "wait" : "wake", tgid_pid >> 32, value->fkey.both.ptr, value->fkey.both.word, value->fkey.both.offset, ts - value->ts);
    bpf_map_delete_elem(&pending, &tgid_pid);
    return 0;
}
