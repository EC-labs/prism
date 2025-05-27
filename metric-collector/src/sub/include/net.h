#ifndef __NET_H
#define __NET_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/socket.h>

struct socket_context_value {
    __u64 inode_id;
    __u64 netns_cookie;
    __u16 family;
    __u16 sk_type;
    __u16 sk_protocol;
    union {
        struct {
            __be32 src_addr; 
            __be32 dst_addr; 
        } ipv4;
        struct {
            struct in6_addr src_addr;
            struct in6_addr dst_addr;
        } ipv6;
    };
    __u16 src_port; 
    __be16 dst_port; 
};

struct internal_disc {
    u64         inode_id;
    struct sock *sk;
};

static __always_inline int store_socket_context(struct socket *sock, struct inode *f_inode, void *socket_context, void *rb) 
{
    if (!sock || !f_inode) {
        return 0;
    }

    u64 socket_inoid = BPF_CORE_READ(f_inode, i_ino);
    struct socket_context_value *v = bpf_map_lookup_elem(socket_context, &socket_inoid);
    if (v)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct socket_context_value *init = bpf_ringbuf_reserve(rb, sizeof(struct socket_context_value), 0);
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

    if (((init->family == AF_INET) || (init->family == AF_INET6)) && 
        ((init->sk_type == SOCK_STREAM) || (init->sk_type == SOCK_DGRAM) || (init->sk_type == SOCK_SEQPACKET))) 
    {
        init->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        init->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    }

    bpf_map_update_elem(socket_context, &socket_inoid, init, BPF_ANY);
	bpf_ringbuf_submit(init, 0);

    return 0;
}

#endif /* __NET_H */
