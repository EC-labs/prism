#ifndef __IOWAIT_H
#define __IOWAIT_H

#define READ 0
#define WRITE 1

#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)

static inline bool op_is_write(__u32 op)
{
	return !!(op & 1);
}

static inline enum req_op req_op(const struct request *req)
{
	return BPF_CORE_READ(req, cmd_flags) & REQ_OP_MASK;
}

#define rq_data_dir(rq)	(op_is_write(req_op(rq)) ? WRITE : READ)

struct inflight {
    __u32 part0;
    __u64 sector;
    __u32 op;
} inflight;

struct inflight_val {
    __u64 ts;
    __u64 pid_tgid;
    __u32 bdev;
    __u64 size;
} inflight_val;

struct granularity {
    __u32 tgid;
    __u32 pid;
    __u64 part0;
    __u64 bdev;
    __u8  dir;
} granularity;

struct stats {
    __u64 ts_s;
    __u64 total_time;
    __u32 sector_cnt;
    __u32 total_requests;
    __u32 hist[8];
} stats;


#endif /* __IOWAIT_H */
