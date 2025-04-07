#ifndef _VFS_H
#define _VFS_H

#define READ 0
#define WRITE 1

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000


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
    __u8 op;
};

struct granularity {
	__u32 tgid;
    __u32 pid;
	struct bri bri;
	__u8 op;
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

__always_inline static struct bri inode_to_vfs_bri(struct inode *f_inode) 
{
    struct bri file = {0};
    file.i_ino = BPF_CORE_READ(f_inode, i_ino);
    file.i_rdev = BPF_CORE_READ(f_inode, i_rdev);
    file.fs_magic = BPF_CORE_READ(f_inode, i_sb, s_magic);
    return file;
}

__always_inline static void to_update_acct(void *to_update_map, u64 start, u64 curr, struct granularity gran) {
    u64 sample = (curr / 1000000000) * 1000000000;
    if (start >= sample) {
        return;
    }

    struct to_update_key key = {0};
    key.ts = start;
    key.granularity = gran;
    bpf_map_update_elem(to_update_map, &key, &sample, BPF_ANY);
}

__always_inline static void vfs_acct_start(void *pending_map, u64 tgid_pid, struct bri *file, __u8 op)
{
    struct inflight_key key = {
        .tgid_pid = tgid_pid,
    };

    struct inflight_value value = {0};
    value.bri = *file;
    value.ts = bpf_ktime_get_ns();
    value.op = op;
    bpf_map_update_elem(pending_map, &key, &value, BPF_ANY);
}

__always_inline static int vfs_acct_end(void *pending_map, void *samples, void *to_update_map) 
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct inflight_value *value = bpf_map_lookup_elem(pending_map, &tgid_pid);
    if (!value) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 sample = (ts / 1000000000) % SAMPLES;
    void *inner = bpf_map_lookup_elem(samples, &sample);
    if (!inner) {
        return 0;
    }

    struct granularity gran = {0};
    gran.tgid = get_tgid(tgid_pid);
    gran.pid = get_pid(tgid_pid);
    gran.bri = value->bri;
    gran.op = value->op;

    struct stats *stat = bpf_map_lookup_elem(inner, &gran);
    if (!stat) {
        struct stats init = {0};
        init.ts_s = ts / 1000000000;
        bpf_map_update_elem(inner, &gran, &init, BPF_ANY);

        stat = bpf_map_lookup_elem(inner, &gran);
        if (!stat) {
            return 0;
        }
    }

    __u64 sample_latency = min(ts - value->ts, ts - (ts/1000000000) * 1000000000);
    __u64 ns_latency = ts - value->ts;
    __u32 bucket = log_base10_bucket(ns_latency);
    __sync_fetch_and_add(&stat->total_requests, 1);
    __sync_fetch_and_add(&stat->total_time, sample_latency);
    __sync_fetch_and_add(stat->hist + bucket, 1);

    to_update_acct(to_update_map, value->ts, ts, gran);
    
    bpf_map_delete_elem(pending_map, &tgid_pid);
    return 0;
}


#endif /* _VFS_H */
