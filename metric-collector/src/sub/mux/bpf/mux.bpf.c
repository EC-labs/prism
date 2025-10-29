// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <consts.h>
#include <vfs.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, bool);
} pids SEC(".maps");

__always_inline bool track(u32 tgid) 
{
    bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
    return pidp ? true : false;
}

SEC("fentry/do_epoll_wait")
int BPF_PROG(fentry__epoll_wait, int epfd) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = get_pid(tgid_pid);
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

    struct eventpoll *ep = (struct eventpoll *) BPF_CORE_READ(f, private_data);
    bpf_printk("[epoll_wait] enter %d %p", epfd, ep);

    return 0;
}

SEC("fexit/do_epoll_wait")
int BPF_PROG(fexit__epoll_wait, int epfd) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = get_pid(tgid_pid);
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

    struct eventpoll *ep = (struct eventpoll *) BPF_CORE_READ(f, private_data);
    bpf_printk("[epoll_wait] exit %d %p", epfd, ep);

    return 0;
}
