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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u32) * MAX_ENTRIES);
} pid_rb SEC(".maps");

// ep_poll_callback file accounting
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_MAX_ENTRIES);
    __type(key, u64); // tid
    __type(value, struct ep_callback_depth_value);
} ep_callback_depth SEC(".maps");

// File muxio accounting
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PENDING_MAX_ENTRIES);
    __type(key, struct file_wake_ts_key);
    __type(value, u64);
} file_wake_ts SEC(".maps");

struct file_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SAMPLE_MAX_ENTRIES);
    __type(key, struct file_granularity);
    __type(value, struct file_stats);
} file_completed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, SAMPLES);
    __uint(key_size, sizeof(u64));
    __array(values, struct file_inner);
} file_samples SEC(".maps");

// Thread muxio accounting
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
    __sync_fetch_and_add(&stat->total_requests, 1);
    __sync_fetch_and_add(&stat->total_time, sample_latency);

    to_update_acct(to_update_map, value->ts, ts, gran);
    
    bpf_map_delete_elem(pending_map, &tgid_pid);
    return 0;
}

__always_inline static int file_acct(void *file_samples_map, void *file_wake_ts_map, struct file_wake_ts_key *key, u64 ts) 
{
    u64 *last_ts = bpf_map_lookup_elem(file_wake_ts_map, key);
    if (!last_ts)
        return 0;

    u64 sample = (ts / 1000000000) % SAMPLES;
    void *inner = bpf_map_lookup_elem(file_samples_map, &sample);
    if (!inner)
        return 0;

    struct file_granularity gran = {0};
    gran.bri = key->bri;
    gran.id = key->id;
    gran.mode = key->mode;

    struct file_stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (!stat) {
        struct file_stats init = {0};
        init.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_ANY);

        stat = bpf_map_lookup_elem(inner, &gran);
        if (!stat) {
            return 0;
        }
    }

    __u64 ns_latency = ts - *last_ts;
    __u32 bucket = log_base10_bucket(ns_latency);
    __sync_fetch_and_add(stat->hist + bucket, 1);

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

    return 0;
}

__always_inline static struct vfs_bri inode_to_vfs_bri(struct inode *f_inode) 
{
    struct vfs_bri file = {0};
    file.i_ino = BPF_CORE_READ(f_inode, i_ino);
    file.i_rdev = BPF_CORE_READ(f_inode, i_rdev);
    file.fs_magic = BPF_CORE_READ(f_inode, i_sb, s_magic);
    return file;
}

SEC("fentry/pollwake")
int BPF_PROG(fentry__pollwake, wait_queue_entry_t *wait, unsigned mode, void *pollkey) 
{
    struct poll_wqueues *pwq = (struct poll_wqueues *) BPF_CORE_READ(wait, private);
    struct task_struct *polling_task = BPF_CORE_READ(pwq, polling_task);
    u32 polling_tgid = BPF_CORE_READ(polling_task, tgid);
    void *p = bpf_map_lookup_elem(&pids, &polling_tgid);
    if (!p)
        return 0;

    struct poll_table_entry *entry = container_of(wait, struct poll_table_entry, wait);
    struct inode *f_inode = BPF_CORE_READ(entry, filp, f_inode);
    struct vfs_bri bri = inode_to_vfs_bri(f_inode);

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u32 flags = BPF_CORE_READ(task, flags);
    if (flags & (PF_USER_WORKER | PF_KTHREAD)) 
        return 0;

    u32 tgid = BPF_CORE_READ(task, tgid);
    if (!discover_tgid(&pids, &pid_rb, tgid)) {
        bpf_printk("[mux] discovered tgid: %u %x %u %llu", 
                   tgid, bri.fs_magic, bri.i_rdev, bri.i_ino);
    }

    struct file_wake_ts_key key = {0};
    u64 pollflags = (u64) pollkey;
    u64 mask = pollflags & BPF_CORE_READ(entry, key);
    if (!mask)
        return 0;

    key.bri = bri;
    key.mode = (mask & POLLIN_SET) ? 0 : 1;
    key.id = ((u64) BPF_CORE_READ(polling_task, tgid)) << 32 | BPF_CORE_READ(polling_task, pid);

    u64 ts = bpf_ktime_get_boot_ns();
    file_acct(&file_samples, &file_wake_ts, &key, ts);
    bpf_map_update_elem(&file_wake_ts, &key, &ts, BPF_ANY);

    return 0;
}

// EPOLL FILE TRACKING
//
// The following probes track an epoll's file stats. For each file awaited for
// by an event poll backing resource identifier, we measure the time difference 
// since the last time it awakened a target thread waiting for an event poll
// resource.
//
// With this in mind, ep_poll_callback alone informs us on the file and the 
// events awakening an event poll resource. However, to avoid adding another map
// that serves as a boolean tracker (whether to track an event poll resource), we
// also trace the `ep_autoremove_wake_function`. This is the method that in the 
// end will wake the target process, and therefore has information on the pid of
// the process sleeping on an event poll BRI, which we can use to determine 
// whether its tgid is to be tracked or not from our target process list.

SEC("fentry/ep_poll_callback")
int BPF_PROG(fentry__ep_poll_callback) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct ep_callback_depth_value *v = bpf_map_lookup_elem(&ep_callback_depth, &tgid_pid);
    if (!v) {
        struct ep_callback_depth_value init = {0};
        bpf_map_update_elem(&ep_callback_depth, &tgid_pid, &init, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&ep_callback_depth, &tgid_pid);
        if (!v) {
            bpf_printk("error initializing ep_callback_depth for %u", get_pid(tgid_pid));
            return 0;
        }
    }
    v->depth += 1;
}

SEC("fexit/ep_poll_callback")
int BPF_PROG(fexit__ep_poll_callback, wait_queue_entry_t *wait, unsigned mode, void *pollkey) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct ep_callback_depth_value *v = bpf_map_lookup_elem(&ep_callback_depth, &tgid_pid);

    // This should only be able to happen in the initialisation if the 
    // ep_poll_callback entry probe was not triggered, but the exit probe was
    if (!v) 
        return 0;

    u8 collect = v->track;
    if ((v->depth--) == 0) 
        bpf_map_delete_elem(&ep_callback_depth, &tgid_pid);

    struct epitem *epi = BPF_CORE_READ(container_of(wait, struct eppoll_entry, wait), base);
    u64 events = BPF_CORE_READ(epi, event.events);
    u64 pollflags = (u64) pollkey;
    u64 mask = pollflags & events;
    if (!collect || !mask)
        return 0;

    struct inode *f_inode = BPF_CORE_READ(epi, ffd.file, f_inode);
    struct vfs_bri bri = inode_to_vfs_bri(f_inode);
    struct file_wake_ts_key key = {0};
    key.bri = bri;
    key.mode = (mask & POLLIN_SET) ? 0 : 1;
    key.id = (u64) BPF_CORE_READ(epi, ep);

    u64 ts = bpf_ktime_get_boot_ns();
    file_acct(&file_samples, &file_wake_ts, &key, ts);
    bpf_map_update_elem(&file_wake_ts, &key, &ts, BPF_ANY);

    return 0;
}

SEC("fentry/ep_autoremove_wake_function")
int BPF_PROG(fentry__ep_autoremove_wake_function, wait_queue_entry_t *wq_entry) 
{
    struct task_struct *polling_task = BPF_CORE_READ(wq_entry, private);
    if (!polling_task) {
        return 0;
    }

    u32 polling_tgid = BPF_CORE_READ(polling_task, tgid);
    void *p = bpf_map_lookup_elem(&pids, &polling_tgid);
    if (!p) 
        return 0;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct ep_callback_depth_value *v = bpf_map_lookup_elem(&ep_callback_depth, &tgid_pid);
    if (!v)
        return 0;

    v->track = 1;
    u32 tgid = get_tgid(tgid_pid);
    if (!discover_tgid(&pids, &pid_rb, tgid)) {
        bpf_printk("[mux] epoll discovered tgid: %u", tgid);
    }
    return 0;
}


// SEC("fentry/do_epoll_ctl")
// int BPF_PROG(fentry__do_epoll_ctl, int epfd, int op, int fd, struct epoll_event *epds) 
// {
//     u64 tgid_pid = bpf_get_current_pid_tgid();
//     u64 events = BPF_CORE_READ(epds, events);
//     if ((events & POLLIN_SET) == 0) {
//         bpf_printk("POLLOUT_SET %u", get_tgid(tgid_pid));
//     }
//     return 0;
// }
