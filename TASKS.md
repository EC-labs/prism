# TODO

- [ ] futex: Wake should have 2 counts. One when it successfully woke up other
      threads, another being the times it entered the system call, regardless
      of whether it woke other threads. 
- [ ] sched: sleep is the least accurate sched stat as there is a time skew
  between the time as measured by the collect process, and the time registered
  by the kernel in the `start` stats. Alternatively, we could simply leverage
  the fact that the sleep time is 1 - runtime - rq_time (check whether
  block_time is also included in sleep time or not). However to do so, we
  should also include additional information as to when a process terminates
  and or starts. When the total combined time of sleep + runtime + rq_time is
  0, then we know the thread did not exist at the sample instant.
- [ ] Single cache file-name -> File
- [ ] Change time-sensitive timer to use interval-timer instead of new thread
  in TimeSensitive impl
- [ ] Commit most important changes
- [ ] Change collect bpf parsers from `impl From` to `impl TryFrom`
- [ ] Redis E1: Fill secondary thread's on-CPU and CPU runqueue missing values
  with 0 for the duration of the experiment. 

  Based on the graphs used for the poster, I would expect that the secondary
  thread's on-CPU time presents a positive correlation with the response time.
  While the secondary thread is executing, we expect the response time to
  increase. While it was not executing, we can consider it spends 0 time in the
  "on-CPU" state. As such, the correlation between the secondary thread's
  on-CPU time and response time should be positive.
    
  With regard to the thread's CPU runqueue time, it should also present a
  positive correlation with response time. The thread only spends time on the
  CPU runqueue while the response time was at its highest.

# Doing 

# Done

- [x] Add support for additional protocols other than IPv4 sockets to track
      their read and write time
- [x] ipc: collect all samples and not aggregate if falling behind
    - [x] sockets: Convert terminated into snapshots
    - [x] pipes: Convert terminated into snapshots
    - [x] Remove last sample instant from return value from ipc program take
      events
- [x] Implement BpfReader trait for other bpf programs
- [x] Track stats for ipc socket and stream calls
- [x] Change fs hierarchy to include a thread's main process id instead of
      `comm`.
    - [x] Change Target comm to pid
    - [x] Change iowait comm to pid
- [x] rust: Change clone to receive new process requests
    - [x] Add new process after fork
    - [x] Remove process after exec?
- [x] Move workload-generator to example-application as another binary
- [x] Use collection timestamp instead of 'current' timestamp
    - [x] scheduler
    - [x] ipc
    - [x] iowait
    - [x] futex
- [x] Move proof of concept source code to poc directory
- [x] Create another directory that distinguishes between per-thread events and
      global events.
- [x] Add futex thread to handle bpftrace events
- [x] Fix sleep overshoot
- [x] `comm` names without '/'
- [x] Do not store minute map if it is empty
- [x] Fix ipc metrics Remove contrib_snapshot > Add contrib_snapshot
- [x] Add epoll stats to item ready
- [x] Add NewProcess ipc bpftrace

## 2024/04/29 - 2024/05/05

- [x] Add depth to epoll wait bpf
- [x] NewProcess event on socket send and receive
- [x] Integrate IO multiplexing
  - [x] Ingest `ipc.bt` epoll events
  - [x] `programs/ipc.rs`:
    - [x] Add epoll logic
  - [x] `metrics/ipc.rs`:
    - [x] Track target files for each event_poll
- [x] Add pipes to epoll
  - [x] Add epoll events to pipes process_events
  - [x] Solve wait end caching wait time
  - [x] Add wait depth to item add epoll
  - [x] Remove item epoll update wait time maps
- [x] Refactor streams ipc logic
- [x] Refactor Sockets
  - [x] Change socket map to kfile map
  - [x] Add active kfiles map to sockets
  - [x] Process epoll events
  - [x] Process connect and accept events

## 2024/04/22 - 2024/04/28

- [x] Collect sync FIFO metrics
  - [x] Ingest `ipc.bt` FIFO events
  - [x] `programs/ipc.rs`: 
    - [x] Add sync FIFO logic
  - [x] `metrics/ipc.rs`:
    - [x] Track per thread per FIFO metrics
    - [x] Track per thread FIFO metrics
    - [x] Store per thread per FIFO metrics
    - [x] Store per thread FIFO metrics

- [x] Collect per `<host>:<port>` socket metrics for each thread.
  - [x] Ingest `ipc.bt` socket events
  - [x] `programs/ipc.rs`: 
    - [x] Add sync socket logic
  - [x] `metrics/ipc.rs`:
    - [x] Track per thread per `<host>:<port>` metrics
    - [x] Store per thread per `<host>:<port>` metrics

## 2024/04/01 - 2024/04/07

- [x] Parse all io_wait events into rust data structures
- [x] Create pending requests map

## 2024/03/25 - 2024/03/31

- [x] Handle NewProcess futex event
- [x] Add communication between `metric-collector` and bpf programs
    - [x] Create communication poc for metric-collector
    - [x] Remove 1 monitor group per process
- [x] Refactor executor to run a single bpf program per type w/ communication
- [x] Refactor to_csv_row to not include a timestamp
- [x] Process propagation
    - [x] Global ID for a file descriptor
    - [x] Differentiate between reading from a FIFO or a regular file
    - [x] Emit FifoEvents 
    - [x] Emit regular file histogram
- [x] Convert repository into a Cargo workspace
- [x] Refactor workload generator
- [x] Save response time in metric directory
    - [x] List all folders in the root data directory
    - [x] Select the most recent file based on name
    - [x] Define application & response-time metric standards

## 2024/03/18 - 2024/03/24

- [x] Create ThreadPool to try and sample the data with a sampling interval as
  close to the requested period
- [x] Pass application name as cmdline option
- [x] collector: Register new threads created by the monitored process
- [x] collector: Unregister target if sampling failed
- [x] collector: Account for sleep_start, exec_start, block_start, wait_start
    These indicate the time their respective accounting variable was last
    updated, in seconds since the machine booted.

## 2024/03/11 - 2024/01/17

**2024/03/13**

- [x] Create bpf new thread monitoring program
- [x] poc: asynchronous executor

**2024/03/12**

- [x] poc: ipc between rust and bpf processes

**2024/03/11**

- [x] Add interactive filtering matplotlib
- [x] Plot slo_violation and metrics as a 3D plot, with depth encoding
  different threads
- [x] Why is there missing data in the collector?

## 2024/03/04 - 2024/03/10

- [x] Does sleep time in futex manifest in cpu block or sleep time?
    **A**: It manifests itself as sleep time
- [x] Research the internals of `futex`
    - [x] Read Eli's blog post
    - [x] Read *Futexes are Tricky*
    - [x] Read LPI mutexes
    - [x] Read futex man pages example code
- [x] PoC that uses the futex interface

## 2024/02/26 - 2024/03/03

- [x] Plot disk metrics with response time
- [x] Calculate transformation metrics
- [x] Process response time to have the 99th percentile latencies for each
  second
- [x] Generate disk workload and collect the metrics
- [x] Get all threads for a process being searched by regex
- [x] Read from jdb2 target
    - [x] Refactor code to create targets per thread
    - [x] Search /proc for target containing string

## 2024/02/19 - 2024/02/25

- [x] Add metric-collector execution start to data hierarchy
- [x] Refactor metric collection application
- [x] Add disk related operations to example app
- [x] Collect /proc/[pid]/sched metrics

## 2024/02/5 - 2024/02/11

- [x] Create simple workload generator against app
    - [x] Check C&E computing course workload generator's crates
    - [x] Each request should be performed asynchronously and in parallel
    - [x] Create request loop logic

- [x] Track response time per request 
    - [x] Create shared data structure where the response time can be stored
      for each request
- [x] Store response time & metrics to file
    - [x] Write response time to csv file
    - [x] Write metrics to csv file
- [x] Plot response time and metrics

# Related Work

- [x] Intel PAT & Pin tools: related papers
- [x] Restrict set of keywords through which we can search for related work.
- [x] Sysdig and any other possible related software
