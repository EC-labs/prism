// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "iowait.h"

#include <common.h>

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

SEC("kprobe/__submit_bio")
int BPF_KPROBE(__submit_bio, struct bio *bio)
{
    struct block_device *bi_bdev = BPF_CORE_READ(bio, bi_bdev);
    unsigned int bdev = BPF_CORE_READ(bi_bdev, bd_dev);
    unsigned int part0 = BPF_CORE_READ(bi_bdev, bd_disk, part0, bd_dev);
    struct bvec_iter bi_iter = BPF_CORE_READ(bio, bi_iter);
    u64 sector = bi_iter.bi_sector;
    u32 size = bi_iter.bi_size / 512;
    u32 op = BPF_CORE_READ(bio, bi_opf);
    u32 status = BPF_CORE_READ(bio, bi_status);

    struct inflight k = {
        .sector = sector,
        .part0 = part0,
        .bdev = bdev,
        .op = op,
        .status = status,
    };

    struct inflight_val v = {
        .ts = bpf_ktime_get_boot_ns(),
        .size = size,
        .pid_tgid = bpf_get_current_pid_tgid(),
    };

    if (bpf_map_update_elem(&pending, &k, &v, BPF_ANY) < 0) {
        bpf_printk("[__submit_bio] Failed to update elem\n");
        return -1;
    }

    
    return 0;
}

SEC("kprobe/bio_endio")
int BPF_KPROBE(bio_endio, struct bio *bio)
{
    struct block_device *bi_bdev = BPF_CORE_READ(bio, bi_bdev);
    unsigned int bdev = BPF_CORE_READ(bi_bdev, bd_dev);
    unsigned int part0 = BPF_CORE_READ(bi_bdev, bd_disk, part0, bd_dev);
    struct bvec_iter bi_iter = BPF_CORE_READ(bio, bi_iter);
    u64 sector = bi_iter.bi_sector;
    u32 size = bi_iter.bi_size / 512;
    u32 op = BPF_CORE_READ(bio, bi_opf);
    u32 status = BPF_CORE_READ(bio, bi_status);


    struct inflight k = {
        .sector = sector,
        .part0 = part0,
        .bdev = bdev,
        .op = op,
        .status = status,
    };

    struct inflight_val *v = bpf_map_lookup_elem(&pending, &k);
    if (v == NULL) {
        return -1;
    }

    u64 ts = bpf_ktime_get_boot_ns();
    u64 sample = (ts/1000000000) % SAMPLES;
    void *inner = bpf_map_lookup_elem(&samples, &sample);
    if (inner == NULL) {
        bpf_printk("[bio_endio] No inner %d\n", sample);
        return -1;
    }

    struct granularity gran = {
        .tgid = v->pid_tgid >> 32,
        .pid = v->pid_tgid,
        .part0 = k.part0,
        .bdev = k.bdev,
    };

    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (stat == NULL) {
        struct stats init = {0};
        init.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_NOEXIST);
        stat = bpf_map_lookup_elem(inner, &gran);

        if (stat == NULL) {
            return -1;
        }
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
