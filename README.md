# Kernel Configurations

`CONFIG_TASK_DELAY_ACCT` && `sysctl "kernel.task_delayacct=1`: Enables taskstats metrics from `struct taskstats` in `include/uapi/linux/taskstats.h`.
`CONFIG_SCHEDSTATS` && `sysctl "kernel.sched_schedstats=1"`: Enables schedular statistics in the form of `struct sched_statistics` in `include/linux/sched.h`.

# Scenarios

## CPU

## Disk

This section refers to any operations that operate on regular files, i.e.,
files in a filesystem that are persisted on block devices.

### Direct Read

The first workload created to test this scenario has a thread read a file's
data directly from disk. To do so, the file is opened with the flags 
`O_DIRECT | O_RDONLY`. The read operation is then performed in a loop,
providing no interval between 2 consecutive calls. In these conditions, the
task is expected to run on CPU, followed by chaning into kernel context where
it must perform the read operation. The read operation will have to put the
process in *uninterruptible* sleep until the data is fetched from the disk. As
soon as that occurs, the task is then re-scheduled, and the read operation
terminates. The userspace program performs another read request, and the cycle
repeats.

**Metrics**

active_time = cpu_runtime + wait_time + block_time ~ 1
iowait_time / active_time -> close to 1
block_time / active_time -> close to 1

jbd2 thread inactive almost irrelevant

### Synchronous Append

A thread writes data to disk, sequential and synchronously. To do so it opens a
file with the `O_CREAT | O_SYNC | O_WRONLY` flags. It then enters a loop where
for each iteration, it performs a write system call. As soon as the system call
is executed, it enters the kernel space where it copies the data that is to be
written to the file, updates the pagecache, and synchronizes the page cache
with the filesystem metadata on disk. While synchronizing the inode's data with
the data on disk, the kernel must send the data combined with the inode's
filesystem metadata to disk. The time it takes to perform this operation is
what we expect to take most of the time. This activity is represented by the
block_time dominating the active_time, and part of it being due to iowait_time.
However, the remaining block time is due to the journaling kernel thread that
has to synchronise the filesystem's metadata with the disk. As such, metrics
from the `jbd2` thread are also included. 

**Metrics** 

active_time = cpu_runtime + wait_time + block_time ~ 1
iowait_time / active_time -> close to 0
block_time / active_time -> close to 1
vfs_fsync_time / active_time -> close to 1

jbd2_active_time = cpu_runtime + wait_time + block_time ~ 1 
jbd2_iowait_time / jbd2_active_time -> close to 1

### Synchronous Edit

A thread continuously edits data in a file, without generating new data. The
file is still opened with the same flags as for the previous case 
(`O_CREAT | O_SYNC | O_WRONLY`), however the fact that the thread simply edits
data that already exists on the disk, the amount of file metadata to be
synchronised with the disk is reduced. This activity manifests itself with the
iowait_time occupying most of the active_time, and there being additional
unaccounted block_time due to the synchronisation performed by the journaling
thread (jbd2). The jbd2 thread no longer presents bottleneck behaviour, but is
performing useful work. As such vfs_fsync_time should be lower when compared to
the previous case. 

**Metrics**

active_time = cpu_runtime + wait_time + block_time ~ 1
iowait_time / active_time -> > 75%
block_time / active_time -> close to 1
vfs_fsync_time / active_time -> close to 0

jbd2_active_time = cpu_runtime + wait_time + block_time ~ 0.2 
jbd2_iowait_time / jbd2_active_time -> close to 0

### ThreadPool IO

Multiple threads collect requests from a queue on a first come first serve
basis. Only the threads that are idle are free to pick requests from the
request queue. Up until a specific request rate, between all threads, some will
have idle time it can use to process a new request. However, given enough
requests, when there is no more idle time between the threads processing the
requests, we expect the response time to start increasing. Considering each
request is asking for IO resources, the non-idle threads will all present a
saturated active_time. The cause for the saturation might be different
depending on the type of requests being executed on each thread. For a high
rate of synchronous append requests, we expect high `iowait_time` in the kernel
journaling thread, and long `block_time` in each thread that is executing a
request of this type. For a high rate of requests performing direct IO, we expect to
measure high `iowait_time`s, and not much activity on the journaling thread.
Lastly, threads executing synchronous edits should present high `iowait_time`s,
with some activity on the journaling kernel thread.

## Locking

## VFS

## Memory

# TODO

Consider limits
