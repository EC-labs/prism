#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>
#include <consts.h>
#include <vfs.h>
#include <net.h>
#include <linux/socket.h>
#include "discovery.h"

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
    __type(value, struct discovery_context);
} pid_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u8);
} inodep SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct pending_receives_key);
    __type(value, u32);
} pending_receives SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct socket_context_value);
} socket_context SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct socket_context_value) * MAX_ENTRIES);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u32) * MAX_ENTRIES);
} pid_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MTU * 1024);
} rb_skb_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct tcp_discovery_event) * MAX_ENTRIES);
} tcp_discovery_rb SEC(".maps");

struct ipbytes {
    char bytes[4];
};

static __always_inline struct ipbytes ip_bytes(__u32 ip)
{
    struct ipbytes ipb;
    ipb.bytes[0] = ip & 0xFF;
    ipb.bytes[1] = (ip >> 8) & 0xFF;
    ipb.bytes[2] = (ip >> 16) & 0xFF;
    ipb.bytes[3] = (ip >> 24) & 0xFF;   
    return ipb;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

static __always_inline __sum16 csum_ipv4_magic(
    __be32 saddr, __be32 daddr,
    __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (u32)sum;

	s += (u32)saddr;
	s += (u32)daddr;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return csum_fold_helper((__wsum)from64to32(s));
}


static __always_inline __sum16 csum_ipv6_magic(
    const struct in6_addr *saddr,
	const struct in6_addr *daddr,
	__u32 len, __u8 proto, __wsum csum)
{

	int carry;
	__u32 ulen;
	__u32 uproto;
	__u32 sum = (u32)csum;

	sum += (u32)saddr->in6_u.u6_addr32[0];
	carry = (sum < (u32)saddr->in6_u.u6_addr32[0]);
	sum += carry;

	sum += (u32)saddr->in6_u.u6_addr32[1];
	carry = (sum < (u32)saddr->in6_u.u6_addr32[1]);
	sum += carry;

	sum += (u32)saddr->in6_u.u6_addr32[2];
	carry = (sum < (u32)saddr->in6_u.u6_addr32[2]);
	sum += carry;

	sum += (u32)saddr->in6_u.u6_addr32[3];
	carry = (sum < (u32)saddr->in6_u.u6_addr32[3]);
	sum += carry;

	sum += (u32)daddr->in6_u.u6_addr32[0];
	carry = (sum < (u32)daddr->in6_u.u6_addr32[0]);
	sum += carry;

	sum += (u32)daddr->in6_u.u6_addr32[1];
	carry = (sum < (u32)daddr->in6_u.u6_addr32[1]);
	sum += carry;

	sum += (u32)daddr->in6_u.u6_addr32[2];
	carry = (sum < (u32)daddr->in6_u.u6_addr32[2]);
	sum += carry;

	sum += (u32)daddr->in6_u.u6_addr32[3];
	carry = (sum < (u32)daddr->in6_u.u6_addr32[3]);
	sum += carry;

	ulen = (u32)bpf_htonl((__u32) len);
	sum += ulen;
	carry = (sum < ulen);
	sum += carry;

	uproto = (u32)bpf_htonl(proto);
	sum += uproto;
	carry = (sum < uproto);
	sum += carry;

	return csum_fold_helper((__wsum)sum);
}

static __always_inline void inject_identifier(
    struct __sk_buff *skb, struct tcphdr th, 
    u32 tcphdr_offset,  u8 *rb_data, u32 tcp_data_len, u32 id)
{
    // Add tcp option
    bpf_skb_load_bytes(skb, tcphdr_offset + th.doff*4, rb_data, tcp_data_len);
    char option_id[EXTEND_SIZE] = {253, EXTEND_SIZE, 0x69, 0x64};
    u32 *special = (u32 *) option_id;
    *(special+1) = id;
    bpf_skb_store_bytes(skb, tcphdr_offset + th.doff*4, &option_id, EXTEND_SIZE, 0);

    // Add reserved flag and change data offset
    th.doff += EXTEND_SIZE/4;
    th.res1 = 0b1011;
    bpf_skb_store_bytes(skb, tcphdr_offset, &th, sizeof(struct tcphdr), 0);
    bpf_skb_store_bytes(skb, tcphdr_offset + th.doff*4, rb_data, tcp_data_len, 0);
}

static __always_inline int send_ipv6(struct __sk_buff *skb, u32 iphdr_offset, u64 ino_id, u32 id)
{
    u8 *data = (void *)(long)skb->data;
    u8 *data_end = (void *)(long)skb->data_end;

    if (data + iphdr_offset + sizeof(struct ipv6hdr) > data_end) 
        return -1;

    struct ipv6hdr *iph = (struct ipv6hdr *) (data + iphdr_offset);
    u8 nexthdr_type = BPF_CORE_READ(iph, nexthdr);
    if (nexthdr_type != 6)
        return -1;

    if ((u8 *)iph + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) > data_end) 
        return -1;

    struct tcphdr th;
    bpf_skb_load_bytes(skb, iphdr_offset + sizeof(struct ipv6hdr), &th, sizeof(struct tcphdr));

    __u16 old_len = bpf_ntohs(BPF_CORE_READ(iph, payload_len));
    __be16 new_len = bpf_htons(old_len + EXTEND_SIZE);
    u32 l3_hdr_len = sizeof(struct ipv6hdr);
    u32 tcp_data_len = old_len - th.doff*4;
    if (tcp_data_len <= 1 || tcp_data_len > MTU) {
        bpf_printk("early return: tcp_data_len [%u]", tcp_data_len);
        return -1;
    }

    char *rb_data = bpf_ringbuf_reserve(&rb_skb_data, MTU, 0);
    if (!rb_data) {
        bpf_printk("early return: ringbuf_reserve");
        return -1;
    }

    // We don't want any more early returns after we 
    // have extended the packet
    bpf_skb_change_tail(skb, skb->len + EXTEND_SIZE, 0);
    // NO MORE EARLY RETURNS

    // Change ipv6 len
    bpf_skb_store_bytes(
        skb, iphdr_offset + offsetof(struct ipv6hdr, payload_len), &new_len, 2, 0
    );

    // Add identifier to TCP
    inject_identifier(skb, th, iphdr_offset + l3_hdr_len, (u8 *)rb_data, tcp_data_len, id);

    // Change checksum
    struct in6_addr saddr = BPF_CORE_READ(iph, saddr);
    struct in6_addr daddr = BPF_CORE_READ(iph, daddr);
    __sum16 csum = ~csum_ipv6_magic(&saddr, &daddr, bpf_htons(new_len), IPPROTO_TCP, 0);
    bpf_skb_store_bytes(skb, iphdr_offset + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), &csum, sizeof(csum), 0);

    bpf_ringbuf_discard(rb_data, 0);

    return 0;
}

static __always_inline int send_ipv4(struct __sk_buff *skb, u32 iphdr_offset, u64 ino_id, u32 id)
{
    u8 *data = (void *)(long)skb->data;
    u8 *data_end = (void *)(long)skb->data_end;

    if (data + iphdr_offset + sizeof(struct iphdr) > data_end) 
        return -1;

    struct iphdr *iph = (struct iphdr *) (data + iphdr_offset);

    u8 nexthdr_type = BPF_CORE_READ(iph, protocol);
    if (nexthdr_type != 6)
        return -1;

    if (((u8 *)iph) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) 
        return -1;

    struct tcphdr th;
    bpf_skb_load_bytes(skb, iphdr_offset + sizeof(struct iphdr), &th, sizeof(struct tcphdr));

    __u16 old_len = bpf_ntohs(BPF_CORE_READ(iph, tot_len));
    __be16 new_len = bpf_htons(old_len + EXTEND_SIZE);
    u32 l3_hdr_len = sizeof(struct iphdr);
    u32 start_tcp_len = old_len - sizeof(struct iphdr);
    u32 tcp_data_len = start_tcp_len - th.doff*4;
    if (tcp_data_len <= 1 || tcp_data_len > MTU) {
        bpf_printk("early return: tcp_data_len [%u]", tcp_data_len);
        return -1;
    }

    char *rb_data = bpf_ringbuf_reserve(&rb_skb_data, MTU, 0);
    if (!rb_data) {
        bpf_printk("early return: ringbuf_reserve");
        return -1;
    }

    // We don't want any more early returns after we 
    // have extended the packet
    bpf_skb_change_tail(skb, skb->len + EXTEND_SIZE, 0);
    // NO MORE EARLY RETURNS

    // Change ipv4 len and checksum
    __be32 before_word; 
    bpf_skb_load_bytes(skb, iphdr_offset + offsetof(struct iphdr, tot_len), &before_word, 4);

    bpf_skb_store_bytes(
        skb, iphdr_offset + offsetof(struct iphdr, tot_len), &new_len, 2, 0
    );

    __be32 after_word;
    bpf_skb_load_bytes(skb, iphdr_offset + offsetof(struct iphdr, tot_len), &after_word, 4);

    __be16 ipcsum = BPF_CORE_READ(iph, check);
    u32 newcsum = bpf_csum_diff(&before_word, 4, &after_word, 4, ~ipcsum);
    u16 folded_csum = csum_fold_helper(newcsum);
    bpf_skb_store_bytes(skb, iphdr_offset + offsetof(struct iphdr, check), &folded_csum, 2, 0);

    // Add identifier to TCP
    inject_identifier(skb, th, iphdr_offset + l3_hdr_len, (u8 *)rb_data, tcp_data_len, id);

    // Change checksum
    __be32 saddr = BPF_CORE_READ(iph, saddr);
    __be32 daddr = BPF_CORE_READ(iph, daddr);
    __sum16 csum = ~csum_ipv4_magic(saddr, daddr, (start_tcp_len + EXTEND_SIZE), IPPROTO_TCP, 0);
    bpf_skb_store_bytes(skb, iphdr_offset + l3_hdr_len + offsetof(struct tcphdr, check), &csum, sizeof(csum), 0);

    bpf_ringbuf_discard(rb_data, 0);

    return 0;
}

static __always_inline void recv_ipv4(struct sk_buff *skb, struct sock *sk, struct tcphdr *th)
{
    void *head = BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    u16 transport_header = BPF_CORE_READ(skb, transport_header);

    u32 option[2];
    bpf_probe_read_kernel(&option, sizeof(option), head + transport_header + th->doff*4 - sizeof(option));

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);

    // packet direction is reversed to transform it into the (struct sock *)'s POV
    u32 src_ip = iph.daddr;
    u16 src_port = bpf_ntohs(th->dest);
    u32 dst_ip = iph.saddr;
    u16 dst_port = bpf_ntohs(th->source);

    struct pending_receives_key key = {0};
    key.sk_ptr = (u64) sk;
    key.family = AF_INET;
    key.netns_cookie = BPF_CORE_READ(sk, __sk_common.skc_net.net, net_cookie);
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.addr_pair.ipv4.saddr = src_ip;
    key.addr_pair.ipv4.daddr = dst_ip;
    bpf_map_update_elem(&pending_receives, &key, &option[1], BPF_ANY);
}

static __always_inline void recv_ipv6(struct sk_buff *skb, struct sock *sk, struct tcphdr *th)
{
    void *head = BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    u16 transport_header = BPF_CORE_READ(skb, transport_header);

    u32 option[2];
    bpf_probe_read_kernel(&option, sizeof(option), head + transport_header + th->doff*4 - sizeof(option));

    struct in6_addr ipv6_src = {0};
    struct in6_addr ipv6_dst = {0};
    u16 src_port = bpf_ntohs(th->dest);
    u16 dst_port = bpf_ntohs(th->source);

    u16 protocol = bpf_ntohs(BPF_CORE_READ(skb, protocol));
    if (protocol == 0x0800) {
        struct iphdr iph;
        bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);

        __be32 ipv4_src = iph.daddr;
        __be32 ipv4_dst = iph.saddr;

        ipv6_src.in6_u.u6_addr32[2] = 0xffff0000;
        ipv6_src.in6_u.u6_addr32[3] = ipv4_src;

        ipv6_dst.in6_u.u6_addr32[2] = 0xffff0000;
        ipv6_dst.in6_u.u6_addr32[3] = ipv4_dst;
    } else if (protocol == 0x86DD) {
        struct ipv6hdr iph;
        bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);

        __builtin_memcpy(&ipv6_src, &iph.saddr, sizeof(ipv6_src));
        __builtin_memcpy(&ipv6_dst, &iph.daddr, sizeof(ipv6_dst));
    }

    struct pending_receives_key key = {0};
    key.sk_ptr = (u64) sk;
    key.family = AF_INET6;
    key.netns_cookie = BPF_CORE_READ(sk, __sk_common.skc_net.net, net_cookie);
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.addr_pair.ipv6.saddr = ipv6_src;
    key.addr_pair.ipv6.daddr = ipv6_dst;
    bpf_map_update_elem(&pending_receives, &key, &option[1], BPF_ANY);
}

static __always_inline struct pending_receives_key 
build_pending_receives_key(struct socket *sock) 
{
    struct pending_receives_key key = {0};
    key.sk_ptr = (u64) BPF_CORE_READ(sock, sk);
    key.family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    key.netns_cookie = BPF_CORE_READ(sock, sk, __sk_common.skc_net.net, net_cookie);
    if (key.family == AF_INET) {
        key.src_port = BPF_CORE_READ(sock, sk, __sk_common.skc_num);
        key.dst_port = bpf_ntohs(BPF_CORE_READ(sock, sk, __sk_common.skc_dport));
        key.addr_pair.ipv4.saddr = BPF_CORE_READ(sock, sk, __sk_common.skc_rcv_saddr);
        key.addr_pair.ipv4.daddr = BPF_CORE_READ(sock, sk, __sk_common.skc_daddr);
    } else if (key.family == AF_INET6) {
        key.src_port = BPF_CORE_READ(sock, sk, __sk_common.skc_num);
        key.dst_port = bpf_ntohs(BPF_CORE_READ(sock, sk, __sk_common.skc_dport));
        key.addr_pair.ipv6.saddr = BPF_CORE_READ(sock, sk, __sk_common.skc_v6_rcv_saddr);
        key.addr_pair.ipv6.daddr = BPF_CORE_READ(sock, sk, __sk_common.skc_v6_daddr);
    }
    return key;
}

static __always_inline void match_receive(struct socket *sock)
{
    struct pending_receives_key key = build_pending_receives_key(sock);
    u32 *keyp = bpf_map_lookup_elem(&pending_receives, &key);
    if (!keyp)
        return;

    u64 tgid_pid = (u64) bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct inode *f_inode = BPF_CORE_READ(sock, file, f_inode);
    u64 inode_id = BPF_CORE_READ(f_inode, i_ino);

    store_socket_context(sock, f_inode, &socket_context, &rb);
    if (!bpf_map_update_elem(&pids, &tgid, &truth, BPF_NOEXIST)) {
        bpf_printk("[tcp] discovered %u %llu", tgid, inode_id);
        bpf_ringbuf_output(&pid_rb, &tgid, sizeof(tgid), 0);
    }

    bpf_map_delete_elem(&pending_receives, &key);

    struct tcp_discovery_event event = {
        .event_type = RECV,
        .inode_id = inode_id,
        .id = bpf_ntohl(*keyp)
    };
    bpf_ringbuf_output(&tcp_discovery_rb, &event, sizeof(event), 0);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 tgid_pid = (u64) BPF_CORE_READ(task, tgid) << 32 | BPF_CORE_READ(task, pid);
    struct discovery_context *context = bpf_map_lookup_elem(&pid_sock, &tgid_pid);
    if (!context)
        return 0;
    bpf_map_delete_elem(&pid_sock, &tgid_pid);

    void *sk = skb->sk;
    if (!sk) 
        return 0;

    int ret = -1;
    u32 id = bpf_get_prandom_u32();
    if (context->eth_protocol == ETH_P_IP) {
        ret = send_ipv4(skb, context->iphdr_offset, context->ino_id, id);
    } else if (context ->eth_protocol == ETH_P_IPV6) {
        ret = send_ipv6(skb, context->iphdr_offset, context->ino_id, id);
    }

    if (!ret) { // SUCCESSFUL
        u8 *count = bpf_map_lookup_elem(&inodep, &context->ino_id);
        if (!count)
            return 0;
        *count = *count + 1;
    }

    struct tcp_discovery_event event = {
        .event_type = SEND,
        .inode_id = context->ino_id,
        .id = bpf_ntohl(id)
    };
    bpf_ringbuf_output(&tcp_discovery_rb, &event, sizeof(event), 0);

    return 0;
}

SEC("fentry/inet_sendmsg")
int BPF_PROG(inet_sendmsg, struct socket *sock)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);
    bool *tgidp = bpf_map_lookup_elem(&pids, &tgid);
    if (!tgidp)
        return 0;

    if (BPF_CORE_READ(sock, sk, sk_protocol) != IPPROTO_TCP)
        return 0;

    u64 ino_id = BPF_CORE_READ(sock, file, f_inode, i_ino);
    int ret = bpf_map_update_elem(&inodep, &ino_id, &z8, BPF_NOEXIST);
    if (ret)
        return 0;

    u32 saddr = BPF_CORE_READ(sock, sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sock, sk, __sk_common.skc_daddr);
    struct ipbytes saddr_bytes = ip_bytes(saddr);
    struct ipbytes daddr_bytes = ip_bytes(daddr);

    return 0;
}

SEC("fentry/inet6_sendmsg")
int BPF_PROG(inet6_sendmsg, struct socket *sock)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);
    bool *tgidp = bpf_map_lookup_elem(&pids, &tgid);
    if (!tgidp)
        return 0;

    if (BPF_CORE_READ(sock, sk, sk_protocol) != IPPROTO_TCP)
        return 0;

    u64 ino_id = BPF_CORE_READ(sock, file, f_inode, i_ino);
    int ret = bpf_map_update_elem(&inodep, &ino_id, &z8, BPF_NOEXIST);
    if (ret)
        return 0;

    return 0;
}

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit, struct sk_buff *skb, struct net_device *sb_dev)
{
    u64 ino_id = BPF_CORE_READ(skb, sk, sk_socket, file, f_inode, i_ino);
    u8 *inop = bpf_map_lookup_elem(&inodep, &ino_id);
    if (!inop || (*inop > 0))
        return 0;

    u16 protocol = bpf_ntohs(BPF_CORE_READ(skb, protocol));
    if (protocol != ETH_P_IP && protocol != ETH_P_IPV6)
        return 0;
    
    u32 hard_header_len = BPF_CORE_READ(skb, dev, hard_header_len);
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct discovery_context context = {
        .ino_id = ino_id,
        .iphdr_offset = hard_header_len,
        .eth_protocol = protocol,
    };
    bpf_map_update_elem(&pid_sock, &tgid_pid, &context, BPF_ANY);
    return 0;
}

SEC("fexit/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit_exit)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pid_sock, &tgid_pid);
    return 0;
}

SEC("fentry/tcp_data_queue")
int BPF_PROG(discovery_tcp_data_queue, struct sock *sk, struct sk_buff *skb) 
{
    void *head = BPF_CORE_READ(skb, head);

    u16 transport_header = BPF_CORE_READ(skb, transport_header);
    struct tcphdr th; 
    bpf_probe_read_kernel(&th, sizeof(th), head + transport_header);

    if (th.res1 != 0xb)
        return 0;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        recv_ipv4(skb, sk, &th);
    } else if (family == AF_INET6) {
        recv_ipv6(skb, sk, &th);
    }

    return 0;
}

SEC("fexit/inet6_recvmsg")
int BPF_PROG(inet6_recvmsg, struct socket *sock) 
{
    match_receive(sock);
    return 0;
}

SEC("fexit/inet_recvmsg")
int BPF_PROG(inet_recvmsg, struct socket *sock) 
{
    match_receive(sock);
    return 0;
}

SEC("fexit/sock_splice_read")
int BPF_PROG(sock_splice_read, struct file *file) 
{
    struct socket *sock = (struct socket *) BPF_CORE_READ(file, private_data);
    match_receive(sock);
    return 0;
}
