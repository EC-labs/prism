// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// 
// AIO stats
//
// We are interested in collecting: 
// 1. The time a thread spends in the AIO subsystem, and the threads interacting
//    with a particualr AIO Backing Resource identifier (BRI).
// 2. Which requests are keeping the AIO backing resource identifier (BRI) busy.
//
// To measure the thread's interactions with the AIO subsystem, we monitor the
// `io_getevents` and `io_submit` system calls.
//
// Granularity: thread->aioctx. 
//
// Statistics: 
// 1. `io_getevents`: total_time, total_requests
// 2. `io_submit`: total_requests

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <consts.h>

#include "aio.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, bool);
} pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_MAX_ENTRIES);
    __type(key, u64);
    __type(value, bool);
} in_submit SEC(".maps");

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
    __type(value, struct to_update_value);
} to_update SEC(".maps");

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


__always_inline bool track(u32 tgid) 
{
    bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
    return pidp ? true : false;
}

__always_inline static void aio_acct_start(void *pending_map, u64 tgid_pid, struct kioctx *aioctx) 
{
    struct inflight_key key = {
        .tgid_pid = tgid_pid,
    };

    struct inflight_value value = {0};
    value.ts = bpf_ktime_get_boot_ns();
    value.aioctx = aioctx;
    bpf_map_update_elem(pending_map, &key, &value, BPF_ANY);
}

__always_inline static void to_update_acct(void *to_update_map, u64 start, u64 curr, struct granularity gran) {
    u64 sample = (curr / 1000000000) * 1000000000;
    if (start >= sample) {
        return;
    }

    struct to_update_key key = {0};
    key.ts = start;
    key.granularity = gran;
    struct to_update_value value = { .additional_time = sample };
    bpf_map_update_elem(to_update_map, &key, &value, BPF_ANY);
}

__always_inline static int aio_acct_end(void *pending_map, void *samples, void *to_update_map) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct inflight_value *value = bpf_map_lookup_elem(pending_map, &tgid_pid);
    if (!value)
        return 0;

    u64 ts = bpf_ktime_get_boot_ns();
    u64 sample = (ts / 1000000000) % SAMPLES;
    void *inner = bpf_map_lookup_elem(samples, &sample);
    if (!inner)
        return 0;

    struct granularity gran = {0};
    gran.tgid = get_tgid(tgid_pid);
    gran.pid = get_pid(tgid_pid);
    gran.aioctx = value->aioctx;
    gran.op = AIO_GETEVENTS;

    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (!stat) {
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
    __sync_fetch_and_add(&stat->total_requests, 1);
    __sync_fetch_and_add(&stat->total_time, sample_latency);

    to_update_acct(to_update_map, value->ts, ts, gran);
    
    bpf_map_delete_elem(pending_map, &tgid_pid);
    return 0;
}

// read_events is the core functionality of io_getevents
// https://elixir.bootlin.com/linux/v6.17.7/source/fs/aio.c#L2230
// 
// We can use the time it spends between entry and exit to determine the time 
// a thread spends waiting for aio requests to complete


SEC("fentry/read_events")
int BPF_PROG(fentry__read_events, struct kioctx *aioctx) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    aio_acct_start(&pending, tgid_pid, aioctx);
    return 0;
}

SEC("fexit/read_events")
int BPF_PROG(fexit__read_events, struct kioctx *aioctx) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    aio_acct_end(&pending, &samples, &to_update);
    return 0;
}

// io_submit registers events to be awaited for by io_getevents
// https://elixir.bootlin.com/linux/v6.17.7/source/fs/aio.c#L2112
//
// Unfortunately, we don't have access to the `struct kioctx`. 
// To get around this, we also probe `lookup_ioctx` to get the `struct kioctx`
// for a particular userspace `ctx_id`.

SEC("tp/syscalls/sys_enter_io_submit")
int io_submit_enter(void *ctx) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    bpf_map_update_elem(&in_submit, &tgid_pid, &truth, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_io_submit")
int io_submit_exit(void *ctx) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    bpf_map_delete_elem(&in_submit, &tgid_pid);
    return 0;
}

SEC("fexit/lookup_ioctx")
int BPF_PROG(fexit__lookup_ioctx, aio_context_t ctx_id, struct kioctx *aioctx) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    bool *v = bpf_map_lookup_elem(&in_submit, &tgid_pid);
    if (!v)
        return 0;

    u64 ts = bpf_ktime_get_boot_ns();
    u64 sample = (ts / 1000000000) % SAMPLES;
    void *inner = bpf_map_lookup_elem(&samples, &sample);
    if (!inner)
        return 0;

    struct granularity gran = {0};
    gran.tgid = get_tgid(tgid_pid);
    gran.pid = get_pid(tgid_pid);
    gran.aioctx = aioctx;
    gran.op = AIO_SUBMIT;

    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (!stat) {
        struct stats init = {0};
        init.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_ANY);

        stat = bpf_map_lookup_elem(inner, &gran);
        if (!stat) {
            return 0;
        }
    }

    __sync_fetch_and_add(&stat->total_requests, 1);

    return 0;
}
