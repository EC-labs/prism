#ifndef __DISCOVERY_H
#define __DISCOVERY_H

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

#define EXTEND_SIZE (4 + sizeof(__u32) + sizeof(__u64))

struct discovery_id {
    __u32 machine_id;
    __u64 inode_id;
};

struct discovery_context {
    __u64 ino_id;
    __u32 iphdr_offset;
    __u16 eth_protocol;
};

struct pending_receives_key {
    __u64 sk_ptr;
    __u64 netns_cookie;
    union {
        struct {
            struct in6_addr saddr;
            struct in6_addr daddr;
        } ipv6;
        struct {
            __u32 saddr;
            __u32 daddr;
        } ipv4;
    } addr_pair;
    __u16 src_port;
    __u16 dst_port;
    __u8  family;
};

struct tcp_discovery_event {
    __u64 local_machine_id;
    __u32 local_inode_id;
    __u64 remote_machine_id;
    __u32 remote_inode_id;
} tcp_discovery_event;

#endif /* __DISCOVERY_H */
