#define TASK_COMM_LEN 16
#define MAX_STACK_LEN 127

// Mostly a subset of taskstats
// https://elixir.bootlin.com/linux/v6.12.6/source/include/uapi/linux/taskstats.h#L41
struct task_delay_acct {
    unsigned long long  ts;
	unsigned long long  pid;
	unsigned long long  tid;
    char                comm[TASK_COMM_LEN];

    // runtime
    unsigned long long runtime_total;

    // rqtime
	unsigned long long rq_delay_total;
	unsigned long long rq_count;

    // uninterruptible sleep
	unsigned long long uninterruptible_delay_total;

    // total time sleeping as a consequence block io
    // https://elixir.bootlin.com/linux/v6.12.6/source/kernel/delayacct.c#L120
	unsigned long long blkio_delay_total;
	unsigned long long blkio_count;

	unsigned long long freepages_delay_total;
	unsigned long long freepages_count;

	unsigned long long thrashing_delay_total;
	unsigned long long thrashing_count;

	unsigned long long swapin_delay_total;
	unsigned long long swapin_count;

	unsigned long long nvcsw;
	unsigned long long nivcsw;
};

