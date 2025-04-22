#ifndef __NET_H
#define __NET_H

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

#endif /* __NET_H */
