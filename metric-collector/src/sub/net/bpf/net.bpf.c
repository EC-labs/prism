// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "net.h"

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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct socket_context_value);
} socket_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES * 2);
    __type(key, u64[2]);
    __type(value, bool);
} socket_socket_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct socket_context_value) * 8192);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u64[2]));
} socket_socket_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct internal_disc);
} pending_skb SEC(".maps");

static int zero = 0;
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

void to_update_acct(u64 start, u64 curr, struct granularity gran) {
    u64 sample = (curr / 1000000000) * 1000000000;
    if (start >= sample) {
        return;
    }

    struct to_update_key key = {0};
    key.ts = start;
    key.granularity = gran;
    bpf_map_update_elem(&to_update, &key, &sample, BPF_ANY);
}

__always_inline int vfs_acct_start(struct inode *f_inode, u8 dir) {
    if (!f_inode) {
        return 0;
    }

    u64 tgid_pid = (u64) bpf_get_current_pid_tgid();
    u32 tgid = (u32) (tgid_pid >> 32);

    struct inflight_key key = {
        .tgid_pid = tgid_pid,
    };
    struct inflight_value value;
    value.bri.i_ino = BPF_CORE_READ(f_inode, i_ino);
    value.bri.i_rdev = 0;
    value.bri.fs_magic = 0x534F434B;
    value.ts = bpf_ktime_get_ns();
    value.is_write = dir;
    bpf_map_update_elem(&pending, &key, &value, BPF_ANY);
    // bpf_printk("acct_st: %u %u %s %u %llu %c => %lld", 
    //        tgid, pid(key.tgid_pid), value.bri.s_id,
    //        value.bri.i_rdev, value.bri.i_ino, value.is_write == READ ? 'R' : 'W', value.ts);
    return 0;
}

__always_inline int vfs_acct_end() {
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
    gran.bri = value->bri;
    gran.dir = value->is_write;
    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (!stat) {
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
    
    // bpf_printk("acct_en: %d %d %s %d %lld %c => %lld %lld", 
    //        gran.tgid, gran.pid, gran.bri.s_id,
    //        gran.bri.i_rdev, gran.bri.i_ino, gran.dir == READ ? 'R' : 'W', ts, ts - value->ts);
    bpf_map_delete_elem(&pending, &tgid_pid);
    return 0;
}

__always_inline int store_socket_context(struct socket *sock, struct inode *f_inode) 
{
    if (!sock || !f_inode) {
        return 0;
    }

    u64 socket_inoid = BPF_CORE_READ(f_inode, i_ino);
    struct socket_context_value *v = bpf_map_lookup_elem(&socket_context, &socket_inoid);
    if (v)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct socket_context_value *init = bpf_ringbuf_reserve(&rb, sizeof(struct socket_context_value), 0);
    if (!init)
        return 0;

    init->inode_id = socket_inoid;
    init->netns_cookie = BPF_CORE_READ(sk, __sk_common.skc_net.net, net_cookie);
    init->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    init->sk_type = BPF_CORE_READ(sk, sk_type);
    init->sk_protocol = BPF_CORE_READ(sk, sk_protocol);

    if (init->family == AF_INET) {
        init->ipv4.src_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        init->ipv4.dst_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else if (init->family == AF_INET6) {
        init->ipv6.src_addr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        init->ipv6.dst_addr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
    }

    if (((init->family == AF_INET) || (init->family == AF_INET6)) 
         && ((init->sk_type == SOCK_STREAM)
             || (init->sk_type == SOCK_DGRAM) 
             || (init->sk_type == SOCK_SEQPACKET))) 
    {
        init->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        init->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    }

    bpf_map_update_elem(&socket_context, &socket_inoid, init, BPF_ANY);
	bpf_ringbuf_submit(init, 0);

    return 0;
}

__always_inline bool track(struct inode *f_inode) {
    u64 tgid_pid = (u64) bpf_get_current_pid_tgid();
    u32 tgid = (u32) (tgid_pid >> 32);
    bool *pidp = bpf_map_lookup_elem(&pids, &tgid);

    if (pidp)
        return true;

    u64 inode_id = BPF_CORE_READ(f_inode, i_ino);
    struct socket_context_value *sockp = bpf_map_lookup_elem(&socket_context, &inode_id);
    if (sockp && !pidp) {
        bpf_map_update_elem(&pids, &tgid, &truth, BPF_ANY);
        bpf_printk("[net] discovered %u %llu", tgid, sockp->inode_id);
        return true;
    }

    return false;
}

__always_inline int map_sockets(u64 send_inode_id, u64 recv_inode_id) 
{
    u64 *event = bpf_ringbuf_reserve(&socket_socket_rb, sizeof(u64)*2, 0);
    if (!event)
        return -1;
    event[0] = send_inode_id;
    event[1] = recv_inode_id;
	bpf_ringbuf_submit(event, 0);
    u64 socket_socket1[2] = { send_inode_id, recv_inode_id };
    u64 socket_socket2[2] = { recv_inode_id, send_inode_id };
    bpf_map_update_elem(&socket_socket_map, &socket_socket1, &truth, BPF_ANY);
    bpf_map_update_elem(&socket_socket_map, &socket_socket2, &truth, BPF_ANY);
    return 0;
}

__always_inline int internal_discovery(struct sock *sk, struct sk_buff *skb) 
{
    void *head = BPF_CORE_READ(skb, head);
    struct internal_disc *v = bpf_map_lookup_elem(&pending_skb, &head);
    if (v == NULL) {
        return 0;
    }

    u64 recv_inode_id = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    if (!recv_inode_id || !v->inode_id) {
        return 0;
    }

    u64 socket_socket[2] = { v->inode_id, recv_inode_id };

    // If this socket has already been mapped we can return early
    bool *connected = bpf_map_lookup_elem(&socket_socket_map, &socket_socket);
    struct socket_context_value *recv = bpf_map_lookup_elem(&socket_context, &recv_inode_id);
    struct socket_context_value *send = bpf_map_lookup_elem(&socket_context, &v->inode_id);
    if (!connected) {
        if (recv) {
            struct sock *sk = v->sk;
            struct socket *sock = BPF_CORE_READ(sk, sk_socket);
            struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
            store_socket_context(sock, f_inode);
            map_sockets(v->inode_id, recv_inode_id);
        }
        else if (send) {
            struct socket *sock = BPF_CORE_READ(sk, sk_socket);
            struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
            store_socket_context(sock, f_inode);
            map_sockets(v->inode_id, recv_inode_id);
        }
    }

    return 0;
}

SEC("fentry/inet_recvmsg")
int BPF_PROG(inet_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, READ);
    return 0;
}


SEC("fexit/inet_recvmsg")
int BPF_PROG(inet_recvmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/inet_sendmsg")
int BPF_PROG(inet_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, (u8) WRITE);
    return 0;
}

SEC("fexit/inet_sendmsg")
int BPF_PROG(inet_sendmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/inet6_recvmsg")
int BPF_PROG(inet6_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, READ);
    return 0;
}


SEC("fexit/inet6_recvmsg")
int BPF_PROG(inet6_recvmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/inet6_sendmsg")
int BPF_PROG(inet6_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, (u8) WRITE);
    return 0;
}

SEC("fexit/inet6_sendmsg")
int BPF_PROG(inet6_sendmsg_exit)
{
    vfs_acct_end();
    return 0;
}


SEC("fentry/sock_splice_read")
int BPF_PROG(sock_splice_read, struct file *f)
{
    struct inode *f_inode = BPF_CORE_READ(f, f_inode);
    if (!track(f_inode))
        return 0;

    struct socket *sock = BPF_CORE_READ(f, private_data);
    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, READ);
    return 0;
}

SEC("fexit/sock_splice_read")
int BPF_PROG(sock_splice_read_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/splice_to_socket")
int BPF_PROG(splice_to_socket, struct pipe_inode_info *pipe, struct file *f)
{
    struct inode *f_inode = BPF_CORE_READ(f, f_inode);
    if (!track(f_inode))
        return 0;

    struct socket *sock = BPF_CORE_READ(f, private_data);
    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, WRITE);
    return 0;
}

SEC("fexit/splice_to_socket")
int BPF_PROG(splice_to_socket_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/unix_stream_recvmsg")
int BPF_PROG(unix_stream_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, READ);
    return 0;
}

SEC("fexit/unix_stream_recvmsg")
int BPF_PROG(unix_stream_recvmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(unix_stream_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, WRITE);
    return 0;
}

SEC("fexit/unix_stream_sendmsg")
int BPF_PROG(unix_stream_sendmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/unix_dgram_recvmsg")
int BPF_PROG(unix_dgram_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, READ);
    return 0;
}

SEC("fexit/unix_dgram_recvmsg")
int BPF_PROG(unix_dgram_recvmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/unix_dgram_sendmsg")
int BPF_PROG(unix_dgram_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, WRITE);
    return 0;
}

SEC("fexit/unix_dgram_sendmsg")
int BPF_PROG(unix_dgram_sendmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/unix_seqpacket_recvmsg")
int BPF_PROG(unix_seqpacket_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, READ);
    return 0;
}

SEC("fexit/unix_seqpacket_recvmsg")
int BPF_PROG(unix_seqpacket_recvmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/unix_seqpacket_sendmsg")
int BPF_PROG(unix_seqpacket_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, WRITE);
    return 0;
}

SEC("fexit/unix_seqpacket_sendmsg")
int BPF_PROG(unix_seqpacket_sendmsg_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/unix_accept")
int BPF_PROG(unix_accept, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, ACCEPT);
    return 0;
}

SEC("fexit/unix_accept")
int BPF_PROG(unix_accept_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/inet_accept")
int BPF_PROG(inet_accept, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    vfs_acct_start(f_inode, ACCEPT);
    return 0;
}

SEC("fexit/inet_accept")
int BPF_PROG(inet_accept_exit)
{
    vfs_acct_end();
    return 0;
}

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit, struct sk_buff *skb) 
{
    struct internal_disc v = {0};
    v.sk = BPF_CORE_READ(skb, sk);
    v.inode_id = BPF_CORE_READ(skb, sk, sk_socket, file, f_inode, i_ino);
    v.head = BPF_CORE_READ(skb, head);

    bpf_map_update_elem(&pending_skb, &v.head, &v, BPF_NOEXIST);
    return 0;
}

SEC("fentry/tcp_data_queue")
int BPF_PROG(tcp_data_queue, struct sock *sk, struct sk_buff *skb) 
{
    return internal_discovery(sk, skb);
}

SEC("fentry/__udp_enqueue_schedule_skb")
int BPF_PROG(__udp_enqueue_schedule_skb, struct sock *sk, struct sk_buff *skb) 
{
    return internal_discovery(sk, skb);
}

SEC("fentry/kfree_skb_partial") 
int BPF_PROG(kfree_skb_partial, struct sk_buff *skb) 
{
    void *head = BPF_CORE_READ(skb, head);
    bpf_map_delete_elem(&pending_skb, &head);
    return 0;
}

SEC("fentry/skb_free_head") 
int BPF_PROG(skb_free_head, struct sk_buff *skb) 
{
    void *head = BPF_CORE_READ(skb, head);
    bpf_map_delete_elem(&pending_skb, &head);
    return 0;
}
