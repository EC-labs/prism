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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(u32) * MAX_ENTRIES);
} pid_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8192);
} rb_skb_data SEC(".maps");

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
    u32 tgid = BPF_CORE_READ(task, tgid);
    bool *tgidp = bpf_map_lookup_elem(&pids, &tgid);
    if (!tgidp) {
        return 0;
    }

    u32 old_len = skb->len;
    bpf_skb_change_tail(skb, skb->len + EXTEND_SIZE, 0);

    __be32 before = 0; 
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), &before, 4);

    u8 new_len = 58;
    bpf_skb_store_bytes(skb, 17, &new_len, 1, 0);

    __be32 after = 0; 
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), &after, 4);

    __be16 ipcsum;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &ipcsum, sizeof(ipcsum));
    u32 newcsum = bpf_csum_diff(&before, 4, &after, 4, ~ipcsum);
    u16 folded = csum_fold_helper(newcsum);
    bpf_printk("ipcsum: %x, folded: %x", bpf_ntohs(ipcsum), folded);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &folded, sizeof(folded), 0);

    // ====================
    // ====================
    // ====================

    
    struct tcphdr th;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &th, sizeof(struct tcphdr));

    char option_id[] = {253, 4, 0x62, 0x63};
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + th.doff*4, &option_id, sizeof(option_id), 0);

    th.doff += 1;
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &th, sizeof(struct tcphdr), 0);

    char data[] = {0x61, 0x0a};
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + th.doff*4, &data, sizeof(data), 0);

    __be32 saddr, daddr;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &saddr, sizeof(saddr));
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));
    u64 s = 0;
    s += saddr; 
    s += daddr; 
    s += (6 + bpf_ntohs(before) - sizeof(struct iphdr) + EXTEND_SIZE) << 8; 
    __wsum wsum = from64to32(s);
    u16 check = ~csum_fold_helper(wsum);
    bpf_printk("computed: %u %u %x", bpf_ntohl(saddr), bpf_ntohl(daddr), check);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), &check, sizeof(check), 0);

    return 0;
}
