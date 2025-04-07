// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <vfs.h>

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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u32) * 8192);
} pid_rb SEC(".maps");

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


__always_inline bool track(struct bri *file, u32 tgid) {
    bool *filep = bpf_map_lookup_elem(&bris, file);
    bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
    if (!filep) {
        if (!pidp)
            return false;
        bpf_map_update_elem(&bris, file, &truth, BPF_ANY);
    }

    if (!pidp) {
        discover_tgid(&pids, &pid_rb, tgid);
        bpf_printk("[vfs] discovered tgid: %u %s %u %llu", tgid, file->fs_magic, file->i_rdev, file->i_ino);
    }
    return true;
}

SEC("fentry/vfs_read")
int BPF_PROG(vfs_read, struct file *file)
{
    struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    if (!f_inode)
        return 0;

    umode_t i_mode = BPF_CORE_READ(f_inode, i_mode);
    if (((i_mode & S_IFMT) == S_IFIFO) || ((i_mode & S_IFMT) == S_IFCHR)) {
        u64 tgid_pid = bpf_get_current_pid_tgid();
        u32 tgid = get_tgid(tgid_pid);
        struct bri file = inode_to_vfs_bri(f_inode);

        if (!track(&file, tgid)) {
            return 0;
        }

        vfs_acct_start(&pending, tgid_pid, &file, READ);
    }
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, ssize_t ret)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(vfs_write, struct file *file, char *buf, size_t count, loff_t *pos)
{
    struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    umode_t i_mode = BPF_CORE_READ(f_inode, i_mode);
    if (((i_mode & S_IFMT) == S_IFIFO) || ((i_mode & S_IFMT) == S_IFCHR)) {
        u64 tgid_pid = bpf_get_current_pid_tgid();
        u32 tgid = get_tgid(tgid_pid);
        struct bri file = inode_to_vfs_bri(f_inode);

        if (!track(&file, tgid)) {
            return 0;
        }

        vfs_acct_start(&pending, tgid_pid, &file, WRITE);
    }
    return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit, ssize_t ret)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}
