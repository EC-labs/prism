```bash
sudo bpftrace -e '
kprobe:schedule 
/ comm == "fs-sync" / 
{ 
    @[kstack] = count(); 
}'
```

```bash
sudo bpftrace -e '
kprobe:vfs_fsync_range 
/ comm == "fs-sync" / 
{ 
    @start = nsecs;    
}

kretprobe:vfs_fsync_range
/ comm == "fs-sync" && @start != 0 /
{
    @total = @total + (nsecs - @start);    
    @start = 0;
}

interval:s:1 
{
    printf("%lld.%09lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

```bash
sudo bpftrace -e '
kprobe:prepare_to_wait*
/ comm == "fs-sync" / 
{ 
    @start = nsecs;    
}

kprobe:finish_wait
/ comm == "fs-sync" && @start != 0 /
{
    @total = @total + (nsecs - @start);    
    @start = 0;
}

interval:s:1 
{
    printf("%lld.%lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

```bash
sudo bpftrace -e '
kprobe:prepare_to_wait*
/ comm == "fs-sync" / 
{ 
    @[kstack, probe] = count();
}

kprobe:finish_wait
/ comm == "fs-sync" /
{
    @[kstack, probe] = count();
}
'
```

```bash
sudo bpftrace -e '
kprobe:vfs_fsync_range 
/ comm == "fs-sync" / 
{ 
    @start_vfs = nsecs;    
}

kretprobe:vfs_fsync_range
/ comm == "fs-sync" && @start_vfs != 0 /
{
    @total_vfs = @total_vfs + (nsecs - @start_vfs);    
    @start_vfs = 0;
}


kprobe:file_write_and_wait_range
/ comm == "fs-sync" /
{
    @start_fwwr = nsecs;    
}

kretprobe:file_write_and_wait_range
/ comm == "fs-sync" && @start_fwwr != 0 /
{
    @total_fwwr = @total_fwwr + (nsecs - @start_fwwr);    
    @start_fwwr = 0;
}


kprobe:jbd2_log_wait_commit
/ comm == "fs-sync" /
{
    @start_jbd2 = nsecs;    
}

kretprobe:jbd2_log_wait_commit
/ comm == "fs-sync" && @start_jbd2 != 0 /
{
    @total_jbd2 = @total_jbd2 + (nsecs - @start_jbd2);    
    @start_jbd2 = 0;
}


interval:s:1 
{
    printf("%s[%lld.%09lld]\t%s[%lld.%09lld]\t%s[%lld.%09lld]\n", 
        "vfs",
        (@total_vfs - @prev_vfs)/1000000000, 
        (@total_vfs - @prev_vfs) % 1000000000,
        "fwwr",
        (@total_fwwr - @prev_fwwr)/1000000000, 
        (@total_fwwr - @prev_fwwr) % 1000000000,
        "jbd2",
        (@total_jbd2 - @prev_jbd2)/1000000000, 
        (@total_jbd2 - @prev_jbd2) % 1000000000
    );
    @prev_vfs = @total_vfs;
    @prev_fwwr = @total_fwwr;
    @prev_jbd2 = @total_jbd2;
}
'
```

```bash
sudo bpftrace -e '
kprobe:jbd2_complete_transaction
/ comm == "fs-sync" /
{
    @start_jbd2 = nsecs;    
}

kretprobe:jbd2_complete_transaction
/ comm == "fs-sync" && @start_jbd2 != 0 /
{
    @total_jbd2 = @total_jbd2 + (nsecs - @start_jbd2);    
    @start_jbd2 = 0;
}


kprobe:jbd2_log_start_commit
/ comm == "fs-sync" /
{
    @start_start_commit = nsecs;    
}

kretprobe:jbd2_log_start_commit
/ comm == "fs-sync" && @start_start_commit != 0 /
{
    @total_start_commit = @total_start_commit + (nsecs - @start_start_commit);    
    @start_start_commit = 0;
}


kprobe:jbd2_log_wait_commit
/ comm == "fs-sync" /
{
    @start_wait_commit = nsecs;    
}

kretprobe:jbd2_log_wait_commit
/ comm == "fs-sync" && @start_wait_commit != 0 /
{
    @total_wait_commit = @total_wait_commit + (nsecs - @start_wait_commit);    
    @start_wait_commit = 0;
}

interval:s:1 
{
    printf("%s[%lld.%09lld]\t%s[%lld.%09lld]\t%s[%lld.%09lld]\n", 
        "jbd2",
        (@total_jbd2 - @prev_jbd2)/1000000000, 
        (@total_jbd2 - @prev_jbd2) % 1000000000,
        "start_commit",
        (@total_start_commit - @prev_start_commit)/1000000000, 
        (@total_start_commit - @prev_start_commit) % 1000000000,
        "wait_commit",
        (@total_wait_commit - @prev_wait_commit)/1000000000, 
        (@total_wait_commit - @prev_wait_commit) % 1000000000
    );
    @prev_jbd2 = @total_jbd2;
    @prev_start_commit = @total_start_commit;
    @prev_wait_commit = @total_wait_commit;
}
'
```

```bash
sudo bpftrace -e '
kprobe:jbd2_log_wait_commit 
/ comm == "fs-sync" / 
{ 
    @start = nsecs;    
}

kretprobe:jbd2_log_wait_commit
/ comm == "fs-sync" && @start != 0 /
{
    @total = @total + (nsecs - @start);    
    @start = 0;
}

interval:s:1 
{
    printf("%lld.%09lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

```bash
sudo bpftrace -e '
kprobe:vfs_fsync_range
/ comm == "fs-sync" / 
{ 
    @enter = 1;
}

kretprobe:vfs_fsync_range
/ comm == "fs-sync" /
{
    @enter = 0;
}


kprobe:schedule
/ comm == "fs-sync" && @enter == 1 / 
{ 
    @start = nsecs;    
}

kretprobe:schedule
/ comm == "fs-sync" && @start != 0 /
{
    @total = @total + (nsecs - @start);    
    @start = 0;
}

interval:s:1 
{
    printf("%lld.%09lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

```bash
sudo bpftrace -e '
kprobe:jbd2_log_wait_commit
/ comm == "fs-sync" / 
{ 
    @enter = 1;
}

kretprobe:jbd2_log_wait_commit
/ comm == "fs-sync" /
{
    @enter = 0;
}


tracepoint:sched:sched_switch
/ comm == "fs-sync" && @enter / 
{ 
    @start = nsecs;    
}

tracepoint:sched:sched_switch
/ args->next_comm == "fs-sync" && @start != 0 /
{
    @total = @total + (nsecs - @start);    
    @start = 0;
}

interval:s:1 
{
    printf("%lld.%09lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

Succesful attempt to find the total time the process spends off-cpu after
having entered `jbd2_log_wait_commit`.
```bash
sudo bpftrace -e '
kprobe:jbd2_log_wait_commit
/ comm == "fs-sync" / 
{ 
    @enter = 1;
}

kretprobe:jbd2_log_wait_commit
/ comm == "fs-sync" /
{
    @enter = 0;
}


tracepoint:sched:sched_switch
/ @enter / 
{ 
    if (comm == "fs-sync") {
        @start = nsecs;    
    } else if (args->next_comm == "fs-sync") {
        @total = @total + (nsecs - @start);    
        @start = 0;
    }
}

interval:s:1 
{
    printf("%lld.%09lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

Failed attempt to find the total time the process spent off-cpu after having
entered `jbd2_log_wait_commit`.
```bash
sudo bpftrace -e '
kprobe:jbd2_log_wait_commit
/ comm == "fs-sync" / 
{ 
    @enter = 1;
}

kretprobe:jbd2_log_wait_commit
/ comm == "fs-sync" /
{
    @enter = 0;
}

kprobe:schedule 
/ comm == "fs-sync" && @enter /
{
    @start = nsecs;
}

kretprobe:schedule 
/ comm == "fs-sync" && @start /
{
    @total = @total + (nsecs - @start);    
    @start = 0;
}

interval:s:1 
{
    printf("%lld.%09lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

Failed attempt to determine the total time a process spends off CPU after
voluntarily yielding.
```bash
sudo bpftrace -e '
kprobe:schedule 
/ comm == "fs-sync" /
{
    @start = nsecs;
}

kretprobe:schedule 
/ comm == "fs-sync" && @start /
{
    @total = @total + (nsecs - @start);    
    @start = 0;
}

interval:s:1 
{
    printf("%lld.%09lld\n", (@total - @prev)/1000000000, (@total - @prev) % 1000000000);
    @prev = @total;
}
'
```

Calculate the CPU's runtime in the `vfs_fsync_range` syscall:
```bash
sudo bpftrace -e '
#include <linux/sched.h>

kprobe:vfs_fsync_range 
/ comm == "fs-sync" /
{
    $task = (struct task_struct *) curtask;
    @start_runtime = $task->se.sum_exec_runtime;
}

kretprobe:vfs_fsync_range
/ comm == "fs-sync" && @start_runtime /
{
    $task = (struct task_struct *) curtask;
    @total_runtime = @total_runtime + ($task->se.sum_exec_runtime - @start_runtime);
}

interval:s:1
{
    $diff = @total_runtime - @prev_runtime;
    printf("%lld.%09lld\n", $diff > 0 ? $diff/1000000000 : 0, $diff % 1000000000);
    @prev_runtime = @total_runtime;
}
'
```


Display `sched_statistics` wait stats.
```bash
sudo bpftrace -e '
#include <linux/sched.h>

profile:ms:100 
{
    $task = (struct task_struct *) curtask;
    //if ($task->comm == "fs-sync") {
        printf("%s -> %s[%lld] %s[%lld] %s[%lld] %s[%lld] %s[%lld]\n",
            $task->comm,
            "se.runtime.sum",
            $task->se.sum_exec_runtime,
            "block.sum",
            $task->stats.sum_block_runtime,
            "wait.sum",
            $task->stats.wait_sum,
            "iowait.sum",
            $task->stats.iowait_sum,
            "sleep.sum",
            $task->stats.sum_sleep_runtime
        );
    //}
}
'
```
