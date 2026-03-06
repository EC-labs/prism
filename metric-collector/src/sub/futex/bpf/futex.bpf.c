#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <consts.h>

#include "futex.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, union futex_key);
    __type(value, bool);
} futex_keys SEC(".maps");

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
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, union futex_key *);
} current_key SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} current_tgid_pid SEC(".maps");

struct inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SAMPLE_MAX_ENTRIES);
    __type(key, struct granularity);
    __type(value, union stats);
} completed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, SAMPLES);
    __uint(key_size, sizeof(u64));
    __array(values, struct inner);
} samples SEC(".maps");


__always_inline bool futex_key_match(union futex_key *key1, union futex_key *key2)
{	return (key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}

__always_inline void to_update_acct(u64 start, u64 curr, struct granularity gran) 
{
    u64 sample = (curr / 1000000000) * 1000000000;
    if (start >= sample) {
        return;
    }

    struct to_update_key key = {0};
    key.ts = start;
    key.granularity = gran;
    bpf_map_update_elem(&to_update, &key, &sample, BPF_ANY);
}

__always_inline void sample_wait_acct(void *inner, union futex_key *key, u32 tgid, u32 pid, u64 ts, struct inflight_value *value) 
{
    struct granularity wait_gran = {0};
    wait_gran.tgid = tgid;
    wait_gran.pid = pid;
    wait_gran.op = FUTEX_WAIT;
    __builtin_memcpy(&wait_gran.fkey, key, sizeof(wait_gran.fkey));

    union stats *wait_stat = bpf_map_lookup_elem(inner, &wait_gran);
    if (!wait_stat) {
        union stats init = {0};
        init.both.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &wait_gran, &init, BPF_ANY);

        wait_stat = bpf_map_lookup_elem(inner, &wait_gran);
        if (!wait_stat)
            return;
    }

    __sync_fetch_and_add(&wait_stat->both.total_requests, 1);
    __u64 sample_latency = min(ts - value->ts, ts - (ts/1000000000) * 1000000000);
    __u64 ns_latency = ts - value->ts;
    __u32 bucket = log_base10_bucket(ns_latency);
    __sync_fetch_and_add(&wait_stat->wait.total_time, sample_latency);
    __sync_fetch_and_add(wait_stat->wait.hist + bucket, 1);

    to_update_acct(value->ts, ts, wait_gran);
}

__always_inline bool track(union futex_key *key, u32 tgid) 
{
    bool *keyp = bpf_map_lookup_elem(&futex_keys, key);
    bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
    if (!keyp) {
        if (!pidp)
            return false;
        bpf_map_update_elem(&futex_keys, key, &truth, BPF_NOEXIST);
    }

    if (!pidp) {
        if (!discover_tgid(&pids, &pid_rb, tgid))
            bpf_printk("[futex] discovered tgid: %u %llu %u %u", tgid, key->both.ptr, key->both.word, key->both.offset);
    }
    return true;
}


SEC("fentry/__futex_queue")
int BPF_PROG(fentry__futex_queue, struct futex_q *q, struct futex_hash_bucket *hb) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = get_pid(tgid_pid);
    u32 tgid = get_tgid(tgid_pid);
    union futex_key key = BPF_CORE_READ(q, key);

    if (!track(&key, tgid))
        return 0;

    struct inflight_value v = {0};
    v.ts = bpf_ktime_get_boot_ns();
    v.op = FUTEX_WAIT;
    __builtin_memcpy(&v.fkey, &key, sizeof(key));

    bpf_map_update_elem(&pending, &tgid_pid, &v, BPF_ANY);

    return 0;
}


SEC("fentry/__futex_unqueue")
int BPF_PROG(fentry__futex_unqueue, struct futex_q *q) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = get_tgid(tgid_pid);
    union futex_key key = BPF_CORE_READ(q, key);

    if (!track(&key, tgid))
        return 0;


    u32 wait_pid = BPF_CORE_READ(q, task, pid);
    u32 wait_tgid = BPF_CORE_READ(q, task, tgid);
    u64 wait_tgid_pid = (u64) wait_tgid << 32 | wait_pid;
    struct inflight_value *value = bpf_map_lookup_elem(&pending, &wait_tgid_pid);
    if (!value)
        return 0;

    u64 ts = bpf_ktime_get_boot_ns();
    u64 sample = (ts / 1000000000) % SAMPLES;
    struct inner *inner = bpf_map_lookup_elem(&samples, &sample);
    if (!inner)
        return 0;

    /* futex wait accounting */
    if (!futex_key_match(&value->fkey, &key)) {
        bpf_printk("[futex] unqueue key does not match queued key");
        sample_wait_acct(inner, &value->fkey, wait_tgid, wait_pid, ts, value);
    }
    sample_wait_acct(inner, &key, wait_tgid, wait_pid, ts, value);


    /* futex wake accounting */
    if (get_pid(tgid_pid) != wait_pid) {
        struct granularity wake_gran = {0};
        wake_gran.tgid = tgid;
        wake_gran.pid = get_pid(tgid_pid);
        wake_gran.op = FUTEX_WAKE;
        __builtin_memcpy(&wake_gran.fkey, &key, sizeof(wake_gran.fkey));

        union stats *wake_stat = bpf_map_lookup_elem(inner, &wake_gran);
        if (!wake_stat) {
            union stats init = {0};
            init.both.ts_s = ts / 1000000000;
            bpf_map_update_elem(inner, &wake_gran, &init, BPF_ANY);

            wake_stat = bpf_map_lookup_elem(inner, &wake_gran);
            if (!wake_stat)
                return 0;
        }
        __sync_fetch_and_add(&wake_stat->both.total_requests, 1);
        __sync_fetch_and_add(&wake_stat->wake.successful_count, 1);
    }

    bpf_map_delete_elem(&pending, &wait_tgid_pid);
    return 0;
}
