#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <vfs.h>
#include <linux/socket.h>
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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u32) * 8192);
} pid_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct internal_disc);
} pending_skb SEC(".maps");

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
        bpf_ringbuf_output(&pid_rb, &tgid, sizeof(tgid), 0);
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
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct internal_disc *v = bpf_map_lookup_elem(&pending_skb, &tgid_pid);
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
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, READ);
    return 0;
}


SEC("fexit/inet_recvmsg")
int BPF_PROG(inet_recvmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/inet_sendmsg")
int BPF_PROG(inet_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, WRITE);
    return 0;
}

SEC("fexit/inet_sendmsg")
int BPF_PROG(inet_sendmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/inet6_recvmsg")
int BPF_PROG(inet6_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, READ);
    return 0;
}


SEC("fexit/inet6_recvmsg")
int BPF_PROG(inet6_recvmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/inet6_sendmsg")
int BPF_PROG(inet6_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, WRITE);
    return 0;
}

SEC("fexit/inet6_sendmsg")
int BPF_PROG(inet6_sendmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
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
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, READ);
    return 0;
}

SEC("fexit/sock_splice_read")
int BPF_PROG(sock_splice_read_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
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
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, WRITE);
    return 0;
}

SEC("fexit/splice_to_socket")
int BPF_PROG(splice_to_socket_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/unix_stream_recvmsg")
int BPF_PROG(unix_stream_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, READ);
    return 0;
}

SEC("fexit/unix_stream_recvmsg")
int BPF_PROG(unix_stream_recvmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(unix_stream_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, WRITE);
    return 0;
}

SEC("fexit/unix_stream_sendmsg")
int BPF_PROG(unix_stream_sendmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/unix_dgram_recvmsg")
int BPF_PROG(unix_dgram_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, READ);
    return 0;
}

SEC("fexit/unix_dgram_recvmsg")
int BPF_PROG(unix_dgram_recvmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/unix_dgram_sendmsg")
int BPF_PROG(unix_dgram_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, WRITE);
    return 0;
}

SEC("fexit/unix_dgram_sendmsg")
int BPF_PROG(unix_dgram_sendmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/unix_seqpacket_recvmsg")
int BPF_PROG(unix_seqpacket_recvmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, READ);
    return 0;
}

SEC("fexit/unix_seqpacket_recvmsg")
int BPF_PROG(unix_seqpacket_recvmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/unix_seqpacket_sendmsg")
int BPF_PROG(unix_seqpacket_sendmsg, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, WRITE);
    return 0;
}

SEC("fexit/unix_seqpacket_sendmsg")
int BPF_PROG(unix_seqpacket_sendmsg_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/unix_accept")
int BPF_PROG(unix_accept, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, ACCEPT);
    return 0;
}

SEC("fexit/unix_accept")
int BPF_PROG(unix_accept_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/inet_accept")
int BPF_PROG(inet_accept, struct socket *sock)
{
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    if (!track(f_inode))
        return 0;

    store_socket_context(sock, f_inode);
    struct bri file = inode_to_vfs_bri(f_inode);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    vfs_acct_start(&pending, tgid_pid, &file, ACCEPT);
    return 0;
}

SEC("fexit/inet_accept")
int BPF_PROG(inet_accept_exit)
{
    vfs_acct_end(&pending, &samples, &to_update);
    return 0;
}

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit, struct sk_buff *skb) 
{
    struct internal_disc v = {0};
    v.sk = BPF_CORE_READ(skb, sk);
    v.inode_id = BPF_CORE_READ(skb, sk, sk_socket, file, f_inode, i_ino);
    u64 tgid_pid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&pending_skb, &tgid_pid, &v, BPF_NOEXIST);
    return 0;
}


SEC("fexit/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit_exit, struct sk_buff *skb) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending_skb, &tgid_pid);
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
