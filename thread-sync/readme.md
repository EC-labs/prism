bpftrace program that signals when a thread enters a waiting state for a futex,
and when it returns from waiting. This information can be used to determine the
total time the thread is spending in a waiting state.

```bash
sudo bpftrace -e '
#include <linux/futex.h>

BEGIN {
    printf("%-10s\t%20s\t%20s\n", "TYPE", "THREAD-ID", "VALUE");
}

tracepoint:syscalls:sys_enter_futex 
/ comm == "thread-sync" /
{
    $op = args->op^128;

    if ($op == FUTEX_WAIT_BITSET) {
        @start[tid] = nsecs;
        printf("%-10s\t%20lld\t%20lld\n", "start", tid, @start[tid]);
    }
}

tracepoint:syscalls:sys_exit_futex 
/ @start[tid] / 
{
    $diff = (uint64)(nsecs - @start[tid]);
    @start[tid] = 0;
    printf("%-10s\t%20lld\t%20lld\n", "elapsed", tid, $diff);
}

END {
    clear(@start);
}'
```
