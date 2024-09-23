# Design

- [ ] Monitor pagecache statistics
- [ ] Incorporate CPU PMU counters
- [ ] Incorporate netlink events
    `https://www.kernel.org/doc/Documentation/accounting/taskstats.txt`
- [ ] Introducing histograms

# Unsolved

**io_uring**

**aio_read / aio_write**

**namespaces**

**What is the impact of using containers instead of regular processes?**

**How should we handle short-lived threads / processes?**

https://docs.kernel.org/accounting/taskstats.html

**Which metrics are appropriate for a combination of short computation and long
sleep reads?**

An example of this behaviour, is having a thread sleeping while waiting for
data and as soon as it receives data, it does some light processing or
notifying, and then proceeds to sleep again while reading the same file.

In this scenario, the total wait time is almost as high as if there were no
events to be handled by the thread due to the little amount of work it has to
do when waking up. 

A possible alternative would be to have another metric such as average time
between wake-ups.

# Analysis

- [ ] Create loading procedures for each type of metric
- [ ] Implement filtering

# Collector

**High**

- [ ] Distinguish between write and read socket pipes
- [ ] Unix socket file naming in the datafs
- [ ] Fix `remove target` with time-sensitive collect thread
- [ ] clone.bpf fork container tolerant
      We are currently using the pid returned to the parent process. This
      returned pid is translated by its namespace and is therefore different
      from the pid as seen from the host. We should really on the process' real
      pid as returned by bpftrace's `pid` builtin, other than relying on the
      return value.
- [ ] Create a central file cache other than having each program store its own
- [ ] Start tracking processes that connect to a particular IP port combination

**Medium**

- [ ] Add a new comm and cmdline collector
- [ ] Store a per second counter for futex calls
- [ ] Store futex only if values change
- [ ] Rename socket file only in NewSocketMap / Connect / Accept event
- [ ] Profile metric-collector to optimise performance
- [ ] Add logging
- [ ] Change clone handler to run as soon as possible within metric-collector
- [ ] Track when a new target was added or removed to allow ignoring new
  relationships

**Low**

- [ ] Adapt futex to perform statistics in-kernel
- [ ] Check whether futex uaddr in process's shared memory region for
      forknoexec.
- [ ] Hive database for files?
