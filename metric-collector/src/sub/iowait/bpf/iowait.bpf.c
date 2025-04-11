// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "iowait.h"

#include <common.h>
#include <consts.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PENDING_MAX_ENTRIES);
	__type(key, struct inflight);
	__type(value, struct inflight_val);
} pending SEC(".maps");

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

SEC("tp_btf/block_io_start")
int block_io_start(u64 *ctx)
{
    // To understand why we extract the data as shown, have a look at the following link
    // https://github.com/torvalds/linux/blob/2eb959eeecc64fa56e9f89a5fc496da297585cbe/include/trace/events/block.h#L190
    struct request *req = (struct request *) ctx[0];

    u32 major = BPF_CORE_READ(req, q, disk, major);
    u32 minor = BPF_CORE_READ(req, q, disk, first_minor);

    struct inflight k = {
        .part0 = major << 20 | minor,
        .sector = BPF_CORE_READ(req, __sector),
        .op = BPF_CORE_READ(req, cmd_flags),
    };

    struct inflight_val v = {
        .ts = bpf_ktime_get_boot_ns(),
        .pid_tgid = bpf_get_current_pid_tgid(),
        .bdev = BPF_CORE_READ(req, bio, bi_bdev, bd_dev),
        .size = BPF_CORE_READ(req, __data_len)/512,
    };

    bpf_map_update_elem(&pending, &k, &v, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_io_done")
int raw_block_io_done(u64 *ctx)
{
    // To understand why we extract the data as shown, have a look at the following link
    // https://github.com/torvalds/linux/blob/2eb959eeecc64fa56e9f89a5fc496da297585cbe/include/trace/events/block.h#L190
    struct request *req = (struct request *) ctx[0];

    u32 major = BPF_CORE_READ(req, q, disk, major);
    u32 minor = BPF_CORE_READ(req, q, disk, first_minor);

    struct inflight k = {
        .part0 = major << 20 | minor,
        .sector = BPF_CORE_READ(req, __sector),
        .op = BPF_CORE_READ(req, cmd_flags),
    };

    struct inflight_val *v = bpf_map_lookup_elem(&pending, &k);
    if (!v)
        return 0;

    struct granularity gran = {
        .tgid = get_tgid(v->pid_tgid),
        .pid = get_pid(v->pid_tgid),
        .part0 = k.part0,
        .bdev = v->bdev,
    };

    u64 ts = bpf_ktime_get_boot_ns();
    u64 sample = (ts/1000000000) % SAMPLES;
    void *inner = bpf_map_lookup_elem(&samples, &sample);
    if (!inner) 
        return 0;

    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (!stat) {
        struct stats init = {0};
        init.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_NOEXIST);
        stat = bpf_map_lookup_elem(inner, &gran);

        if (!stat)
            return 0;
    }
    __u64 ns_latency = ts - v->ts;
    __u32 bucket = log_base10_bucket(ns_latency);
    __sync_fetch_and_add(&stat->total_requests, 1);
    __sync_fetch_and_add(&stat->total_time, ns_latency);
    __sync_fetch_and_add(&stat->sector_cnt, v->size);
    __sync_fetch_and_add(stat->hist + bucket, 1);

    bpf_map_delete_elem(&pending, &k);
    return 0;
}
