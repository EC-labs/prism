#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <consts.h>
#include <vfs.h>
#include <linux/socket.h>
#include "discovery.h"
#include "bpf_endian.h"

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
    __type(value, u64);
} pid_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, bool);
} inodep SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u32) * MAX_ENTRIES);
} pid_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MTU * 100);
} rb_skb_data SEC(".maps");

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

static inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 tgid_pid = (u64) BPF_CORE_READ(task, tgid) << 32 | BPF_CORE_READ(task, pid);
    u64 *ino_id = bpf_map_lookup_elem(&pid_sock, &tgid_pid);
    if (!ino_id)
        return 0;
    bpf_map_delete_elem(&pid_sock, &tgid_pid);

    void *sk = skb->sk;
    if (!sk) 
        return 0;

    struct iphdr iph;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph, sizeof(struct iphdr));
    if (iph.protocol != 6) {
        bpf_printk("early return: protocol [%u]", iph.protocol);
        return 0;
    }


    struct tcphdr th;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &th, sizeof(struct tcphdr));

    u32 tcp_len = bpf_ntohs(iph.tot_len) - sizeof(struct iphdr);
    u32 tcp_data_len = tcp_len - th.doff*4;
    if (tcp_data_len <= 1 || tcp_data_len > MTU) {
        bpf_printk("early return: tcp_data_len [%u]", tcp_data_len);
        return 0;
    }

    char *rb_data = bpf_ringbuf_reserve(&rb_skb_data, MTU, 0);
    if (!rb_data) {
        bpf_printk("early return: ringbuf_reserve");
        return 0;
    }

    u32 old_len = skb->len;
    bpf_skb_change_tail(skb, skb->len + EXTEND_SIZE, 0);

    __be32 before = 0; 
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), &before, 4);

    u8 new_len = bpf_ntohs(before) + EXTEND_SIZE;
    bpf_skb_store_bytes(skb, 17, &new_len, 1, 0);

    __be32 after = 0; 
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), &after, 4);

    __be16 ipcsum;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &ipcsum, sizeof(ipcsum));
    u32 newcsum = bpf_csum_diff(&before, 4, &after, 4, ~ipcsum);
    u16 folded = csum_fold_helper(newcsum);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &folded, sizeof(folded), 0);

    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + th.doff*4, rb_data, tcp_data_len);
    char option_id[EXTEND_SIZE] = {253, EXTEND_SIZE, 0x69, 0x64};
    u32 *special = option_id;
    u32 id = bpf_get_prandom_u32();
    *(special+1) = id;
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + th.doff*4, &option_id, EXTEND_SIZE, 0);

    u32 src_ip = iph.saddr;
    u16 src_port = bpf_ntohs(th.source);
    u32 dst_ip = iph.daddr;
    u16 dst_port = bpf_ntohs(th.dest);

    struct ipbytes src_bytes = ip_bytes(src_ip);
    struct ipbytes dst_bytes = ip_bytes(dst_ip);
    bpf_printk("send: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u [%llu] [%x]", 
               src_bytes.bytes[0] & 0xff, src_bytes.bytes[1], src_bytes.bytes[2], src_bytes.bytes[3], 
               src_port,
               dst_bytes.bytes[0] & 0xff, dst_bytes.bytes[1], dst_bytes.bytes[2], dst_bytes.bytes[3],
               dst_port,
               *ino_id, bpf_ntohl(id)
               );

    th.doff += EXTEND_SIZE/4;
    th.res1 = 0b1011;
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &th, sizeof(struct tcphdr), 0);

    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + th.doff*4, rb_data, tcp_data_len, 0);
    bpf_ringbuf_discard(rb_data, 0);

    __be32 saddr, daddr;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &saddr, sizeof(saddr));
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));
    u64 s = 0;
    s += saddr; 
    s += daddr; 
    s += (6 + tcp_len + EXTEND_SIZE) << 8; 
    __wsum wsum = from64to32(s);
    u16 check = ~csum_fold_helper(wsum);
    bpf_printk("computed: %u %u %x", bpf_ntohl(saddr), bpf_ntohl(daddr), check);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), &check, sizeof(check), 0);

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

    u64 ino_id = BPF_CORE_READ(sock, file, f_inode, i_ino);
    bpf_map_update_elem(&inodep, &ino_id, &truth, BPF_ANY);
    bpf_printk("sendmsg: %llu", ino_id);
    return 0;
}

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit, struct sk_buff *skb, struct net_device *sb_dev)
{
    u64 ino_id = BPF_CORE_READ(skb, sk, sk_socket, file, f_inode, i_ino);
    bool *inop = bpf_map_lookup_elem(&inodep, &ino_id);
    if (!inop)
        return 0;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pid_sock, &tgid_pid, &ino_id, BPF_ANY);
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

    u32 option[2];
    bpf_probe_read_kernel(&option, sizeof(option), head + transport_header + th.doff*4 - sizeof(option));

    u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);
    
    // packet direction is reversed to transform it into the (struct sock *)'s POV
    u32 src_ip = iph.daddr;
    u16 src_port = bpf_ntohs(th.dest);
    u32 dst_ip = iph.saddr;
    u16 dst_port = bpf_ntohs(th.source);

    struct ipbytes src_bytes = ip_bytes(src_ip);
    struct ipbytes dst_bytes = ip_bytes(dst_ip);
    // struct ipbytes dst_bytes = ip_bytes(bpf_ntohl(iph.dest));
    u64 ino_id = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    bpf_printk("recv: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u [%llu] [%x]", 
               src_bytes.bytes[0] & 0xff, src_bytes.bytes[1], src_bytes.bytes[2], src_bytes.bytes[3], 
               src_port,
               dst_bytes.bytes[0] & 0xff, dst_bytes.bytes[1], dst_bytes.bytes[2], dst_bytes.bytes[3],
               dst_port,
               ino_id, bpf_ntohl(option[1])
               );


    return 0;
}
