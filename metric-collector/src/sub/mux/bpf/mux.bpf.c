// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <consts.h>

#include "mux.h"

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

__always_inline static void mux_acct_start(void *pending_map, u64 tgid_pid, struct eventpoll *ep) 
{
    struct inflight_key key = {
        .tgid_pid = tgid_pid,
    };

    struct inflight_value value = {0};
    value.ts = bpf_ktime_get_boot_ns();
    value.ep = ep;
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

__always_inline static int mux_acct_end(void *pending_map, void *samples, void *to_update_map) 
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
    gran.ep = value->ep;

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


SEC("fentry/do_epoll_wait")
int BPF_PROG(fentry__epoll_wait, int epfd) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    struct task_struct *curr = (struct task_struct *) bpf_get_current_task();
    struct file **file_array = BPF_CORE_READ(curr, files, fdt, fd);
    struct file *f = NULL;
    if (bpf_probe_read_kernel(&f, sizeof(f), file_array + epfd)) {
        bpf_printk("[mux] fentry__epoll_wait: failed to read kernel memory");
        return 0;
    }

    if (!f) {
        bpf_printk("[mux] fentry__epoll_wait: struct file *f is NULL");
        return 0;
    }

    char fname[12]; 
    bpf_probe_read_kernel_str(fname, 12, (char *) BPF_CORE_READ(f, f_path.dentry, d_name.name));
    if(bpf_strncmp(fname, 12, "[eventpoll]")) {
        return 0;
    }

    struct eventpoll *ep = (struct eventpoll *) BPF_CORE_READ(f, private_data);
    mux_acct_start(&pending, tgid_pid, ep);
    bpf_printk("[epoll_wait] enter %d %p", epfd, ep);

    return 0;
}

SEC("fexit/do_epoll_wait")
int BPF_PROG(fexit__epoll_wait, int epfd) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    mux_acct_end(&pending, &samples, &to_update);
    bpf_printk("[epoll_wait] exit %d", epfd);

    return 0;
}

SEC("fentry/do_sys_poll")
int BPF_PROG(do_sys_poll) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    struct eventpoll *ep = NULL;
    mux_acct_start(&pending, tgid_pid, ep);
    bpf_printk("[do_sys_poll] enter %u", get_pid(tgid_pid));
    return 0;
}


SEC("fexit/do_sys_poll")
int BPF_PROG(do_sys_poll_exit) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    mux_acct_end(&pending, &samples, &to_update);
    bpf_printk("[do_sys_poll] exit %u", get_pid(tgid_pid));

    return 0;
}

SEC("fentry/core_sys_select")
int BPF_PROG(core_sys_select) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    struct eventpoll *ep = NULL;
    mux_acct_start(&pending, tgid_pid, ep);
    bpf_printk("[core_sys_select] enter %u", get_pid(tgid_pid));
    return 0;
}

SEC("fexit/core_sys_select")
int BPF_PROG(core_sys_select_exit) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);

    if (!track(tgid))
        return 0;

    mux_acct_end(&pending, &samples, &to_update);
    bpf_printk("[core_sys_select] exit %u", get_pid(tgid_pid));

    return 0;
}
