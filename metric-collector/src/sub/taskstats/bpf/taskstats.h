#ifndef _TASKSTATS_H
#define _TASKSTATS_H

#include <asm/types.h>

#define TASK_COMM_LEN 16

// Mostly a subset of taskstats
// https://elixir.bootlin.com/linux/v6.12.6/source/include/uapi/linux/taskstats.h#L41
struct task_delay_acct {
    __u64  ts;
    __u64  pid;
    __u64  tid;
    char                comm[TASK_COMM_LEN];

    // runtime
    __u64 runtime_total;

    // rqtime
    __u64 rq_delay_total;
    __u64 rq_count;

    // uninterruptible sleep
    __u64 uninterruptible_delay_total;

    // total time sleeping as a consequence block io
    // https://elixir.bootlin.com/linux/v6.12.6/source/kernel/delayacct.c#L120
    __u64 blkio_delay_total;
    __u64 blkio_count;

    __u64 freepages_delay_total;
    __u64 freepages_count;

    __u64 thrashing_delay_total;
    __u64 thrashing_count;

    __u64 swapin_delay_total;
    __u64 swapin_count;

    __u64 nvcsw;
    __u64 nivcsw;
};

#endif /* _TASKSTATS_H */
