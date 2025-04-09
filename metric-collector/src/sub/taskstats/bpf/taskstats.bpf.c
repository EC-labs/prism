#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "taskstats.h"

#include <common.h>
#include <consts.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, bool);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct task_delay_acct) * MAX_ENTRIES);
} taskstats_rb SEC(".maps");

__always_inline struct task_delay_acct get_taskstats(struct task_struct *task)
{
	struct task_delay_acct stats = {0};

    stats.ts = bpf_ktime_get_boot_ns();
	stats.pid = BPF_CORE_READ(task, tgid);
	stats.tid = BPF_CORE_READ(task, pid);
    BPF_CORE_READ_INTO(&stats.comm, task, comm);

    stats.runtime_total = BPF_CORE_READ(task, se.sum_exec_runtime);

    stats.rq_delay_total = BPF_CORE_READ(task, sched_info.run_delay);
    stats.rq_count = BPF_CORE_READ(task, sched_info.pcount);

    stats.blkio_delay_total = BPF_CORE_READ(task, delays, blkio_delay);
    stats.blkio_count = BPF_CORE_READ(task, delays, blkio_count);

    stats.uninterruptible_delay_total = BPF_CORE_READ(task, stats.sum_block_runtime);

    stats.freepages_delay_total = BPF_CORE_READ(task, delays, freepages_delay);
    stats.freepages_count = BPF_CORE_READ(task, delays, freepages_count);

    stats.thrashing_delay_total = BPF_CORE_READ(task, delays, thrashing_delay);
    stats.thrashing_count = BPF_CORE_READ(task, delays, thrashing_count);

    stats.swapin_delay_total = BPF_CORE_READ(task, delays, swapin_delay);
    stats.swapin_count = BPF_CORE_READ(task, delays, swapin_count);

    stats.nvcsw = BPF_CORE_READ(task, nvcsw);
    stats.nivcsw = BPF_CORE_READ(task, nivcsw);
	return stats;
}

__always_inline bool track(u64 tgid) {
    bool *pidp = bpf_map_lookup_elem(&pids, &tgid);
    if (!pidp) 
        return false;
    return true;
}

SEC("iter/task")
int get_tasks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (!task)
		return 0;

    struct task_delay_acct stats = get_taskstats(task);
	int ret = bpf_seq_write(seq, &stats, sizeof(struct task_delay_acct));
	return 0;
}


SEC("tp_btf/sched_process_fork")
int sched_process_fork(u64 *ctx)
{
    // https://elixir.bootlin.com/linux/v5.13/source/include/trace/events/sched.h#L371
    struct task_struct *child = (struct task_struct *) ctx[1];
    u64 tgid = BPF_CORE_READ(child, tgid);
    if (!track(tgid)) 
        return 0;

    u64 pid = BPF_CORE_READ(child, pid);
    struct task_delay_acct stats = get_taskstats(child);
    bpf_ringbuf_output(&taskstats_rb, &stats, sizeof(stats), 0);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int sched_process_exit(u64 *ctx)
{
    // https://elixir.bootlin.com/linux/v5.13/source/include/trace/events/sched.h#L332
    struct task_struct *task = (struct task_struct *) ctx[0];
    u64 tgid = BPF_CORE_READ(task, tgid);
    if (!track(tgid)) 
        return 0;

    struct task_delay_acct stats = get_taskstats(task);
    bpf_ringbuf_output(&taskstats_rb, &stats, sizeof(stats), 0);
    return 0;
}
