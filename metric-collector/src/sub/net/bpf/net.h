/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __NET_H
#define __NET_H

#define MAX_ENTRIES 8192
#define SAMPLE_MAX_ENTRIES MAX_ENTRIES
#define PENDING_MAX_ENTRIES MAX_ENTRIES
#define SAMPLES 10

#define READ 0
#define WRITE 1
#define ACCEPT 2

#define AF_INET  2
#define AF_INET6 10
#define AF_UNIX  1

struct bri {
	__u32 fs_magic;
	__u32 i_rdev;
	__u64 i_ino;
};

struct inflight_key {
	__u64 tgid_pid;
};

struct inflight_value {
	__u64 ts;
	struct bri bri;
    __u8 is_write;
};

struct granularity {
	__u32 tgid;
    __u32 pid;
	struct bri bri;
	__u8 dir;
};

struct stats {
	__u64 ts_s;
	__u64 total_time;
	__u32 total_requests;
	__u32 hist[8];
};

struct to_update_key {
	__u64 ts;
	struct granularity granularity;
};

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
