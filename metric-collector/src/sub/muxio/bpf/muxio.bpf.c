// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "muxio.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, bool);
} pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, bool);
} in_muxio SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u64);
} in_epoll SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct poll_register_file_event) * (1<<20) * 2); // (40 * (1<<20) * 2)
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, (1<<20) * 3);
    __type(key, u64);
    __type(value, bool);
} epoll_files SEC(".maps");


static u64 zero = 0;
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

__always_inline bool track() {
    u64 tgid_pid = (u64) bpf_get_current_pid_tgid();
    u32 tgid = (u32) (tgid_pid >> 32);
    bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
    if (!pidp) 
        return false;

    return true;
}

SEC("fentry/do_sys_poll")\
int BPF_PROG(do_sys_poll) 
{
    if (!track()) 
        return 0;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct poll_start_event event = {0};
    event.event = POLL_START;
    event.tgid_pid = tgid_pid;
    event.ts = bpf_ktime_get_boot_ns();
    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    bpf_map_update_elem(&in_muxio, &tgid_pid, &truth, BPF_ANY);
    return 0;
}


SEC("fexit/do_sys_poll")\
int BPF_PROG(do_sys_poll_exit) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    bool *inmuxio = bpf_map_lookup_elem(&in_muxio, &tgid_pid);
    if (!inmuxio)
        return 0;

    struct poll_end_event event = {0};
    event.event = POLL_END;
    event.tgid_pid = bpf_get_current_pid_tgid();
    event.ts = bpf_ktime_get_boot_ns();
    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    bpf_map_delete_elem(&in_muxio, &tgid_pid);
    return 0;
}

SEC("fentry/core_sys_select")\
int BPF_PROG(core_sys_select) 
{
    if (!track()) 
        return 0;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct poll_start_event event = {0};
    event.event = POLL_START;
    event.tgid_pid = tgid_pid;
    event.ts = bpf_ktime_get_boot_ns();
    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    bpf_map_update_elem(&in_muxio, &tgid_pid, &truth, BPF_ANY);
    return 0;
}

SEC("fexit/core_sys_select")\
int BPF_PROG(core_sys_select_exit) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    bool *inmuxio = bpf_map_lookup_elem(&in_muxio, &tgid_pid);
    if (!inmuxio)
        return 0;

    struct poll_end_event event = {0};
    event.event = POLL_END;
    event.tgid_pid = bpf_get_current_pid_tgid();
    event.ts = bpf_ktime_get_boot_ns();
    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    bpf_map_delete_elem(&in_muxio, &tgid_pid);
    return 0;
}

SEC("fexit/__fdget")
int BPF_PROG(__fdget, u32 fd, u64 word)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    bool *inmuxio = bpf_map_lookup_elem(&in_muxio, &tgid_pid);
    bool *inepoll = bpf_map_lookup_elem(&in_epoll, &tgid_pid);
    if (inmuxio) {
        u64 mask = ~3;
        struct file *f = (struct file *) (word & mask);

        struct poll_register_file_event event = {0};
        event.event = POLL_REGISTER_FILE;
        event.i_rdev = BPF_CORE_READ(f, f_inode, i_rdev);
        event.magic = BPF_CORE_READ(f, f_inode, i_sb, s_magic);
        event.i_ino = BPF_CORE_READ(f, f_inode, i_ino);
        event.tgid_pid = tgid_pid;
        event.ts = bpf_ktime_get_boot_ns();
        bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    } else if (inepoll && *inepoll == zero) {
        u64 mask = ~3;
        struct file *f = (struct file *) (word & mask);
        u64 ep = (u64) BPF_CORE_READ(f, private_data);

        struct epoll_start_event event = {0};
        event.event = EPOLL_START;
        event.tgid_pid = bpf_get_current_pid_tgid();
        event.ep_address = ep;
        event.ts = bpf_ktime_get_boot_ns();
        bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
        bpf_map_update_elem(&in_epoll, &tgid_pid, &ep, BPF_ANY);
    }

    return 0;
}

SEC("fexit/__ep_remove")
int BPF_PROG(__ep_remove, struct eventpoll *ep, struct epitem *epi)
{
    if (!track()) {
        return 0;
    }

    u64 epi_address = (u64) epi;
    bpf_map_delete_elem(&epoll_files, &epi_address);

    struct epoll_register_file_event event = {0};
    event.event = EPOLL_REMOVE_FILE;
    event.magic = BPF_CORE_READ(epi, ffd.file, f_inode, i_sb, s_magic);
    event.i_rdev = BPF_CORE_READ(epi, ffd.file, f_inode, i_rdev);
    event.i_ino = BPF_CORE_READ(epi, ffd.file, f_inode, i_ino);
    event.ep_address = (u64) ep;
    event.ts = bpf_ktime_get_boot_ns();

    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    return 0;
}


SEC("fentry/do_epoll_wait")
int BPF_PROG(do_epoll_wait, struct eventpoll *ep)
{
    if (!track()) {
        return 0;
    }

    u64 tgid_pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&in_epoll, &tgid_pid, &zero, BPF_ANY);
    return 0;
}

SEC("fexit/do_epoll_wait")
int BPF_PROG(do_epoll_wait_exit, struct eventpoll *ep)
{
    if (!track()) {
        return 0;
    }

    u64 tgid_pid = bpf_get_current_pid_tgid();
    u64 *inepoll = bpf_map_lookup_elem(&in_epoll, &tgid_pid);
    if (!inepoll) 
        return 0;

    struct epoll_start_event event = {0};
    event.event = EPOLL_END;
    event.tgid_pid = tgid_pid;
    event.ep_address = *inepoll;
    event.ts = bpf_ktime_get_boot_ns();
    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);

    bpf_map_delete_elem(&in_epoll, &tgid_pid);
    return 0;
}

SEC("kprobe/ep_item_poll.isra.0")
int BPF_KPROBE(ep_item_poll, struct epitem *epi)
{
    if (!track()) {
        return 0;
    }

    u64 epi_address = (u64) epi;
    bool *p = bpf_map_lookup_elem(&epoll_files, &epi_address);
    if (p)
        return 0;

    bpf_map_update_elem(&epoll_files, &epi_address, &truth, BPF_ANY);

    struct epoll_register_file_event event = {0};
    event.event = EPOLL_INSERT_FILE;
    event.magic = BPF_CORE_READ(epi, ffd.file, f_inode, i_sb, s_magic);;
    event.i_rdev = BPF_CORE_READ(epi, ffd.file, f_inode, i_rdev);
    event.i_ino = BPF_CORE_READ(epi, ffd.file, f_inode, i_ino);
    event.ep_address = (u64) BPF_CORE_READ(epi, ep);
    event.ts = bpf_ktime_get_boot_ns();
    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    return 0;
}
