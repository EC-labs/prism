# TODO

- [ ] Redis E1: Fill secondary thread's missing values with 0 for the duration
  of the experiment.

# Metrics

1. lock statistics: 
    1. The time a thread spends waiting for a lock
    2. When a thread started waiting for a lock
    3. When a thread triggered a wake on a lock
2. scheduler statistics: 
    1. The time a thread spends on-CPU
    2. The time a thread spends waiting on a CPU runqueue.
    3. The time a thread spends in a TASK_UNINTERRUPTIBLE state (block)
    4. The time a thread spends in a TASK_INTERRUPTIBLE state (sleep)
    5. The time a thread spends in iowait
3. multiplexing IO:
    1. If a thread uses poll/select this monitors the time a thread spends
       waiting for a particular file descriptor
    2. If using epoll, we monitor the time a thread spends waiting on the epoll
       file descriptor, and we then track for each epoll file descriptor the
       time it spent waiting for each file descriptor individually
4. disk statistics: 
    1. For each thread, the collector tracks the number of completed and in
      flight requests for each second
5. inter-process communication:
    1. Process discovery. Through inter-process communication methods such as
       FIFOs and sockets we find new processes interacting with the current set
       of tracked processes.
    2. Per-thread track the time spent receiving/sending data from/to sockets.
    3. Per-thread track the time spent reading/writing data from/to FIFOs
6. thread attribution:
    1. Each metric is tracked on a per-thread basis.
7. track new thread/process:
    1. When a new thread is created within a process, we start tracking this
       thread
    2. When a process is forked we start tracking this process
8. Multi target analysis
    1. Using multiple target metrics to interpret the collected system-level
       metrics

# Interesting

* Analyse the same set of metrics over different target application metrics

# Experiments

Each experiment aims to create a degradation scenario on the target
application. We then validate whether our system related metrics are able to
accurately encode this degradation behaviour. Additionally, for each experiment
we add an expectations section that describes the behaviour we expect to
observe, and an observations section that highlights the observed behaviour.

## Redis

Redis is an in memory key-value data store. It follows a multi-threaded
architecture where the main operations are performed on only one of its
threads, while the remaining operations are performed on other threads in the
"background". We expect scheduler statistics to be most prevalent while
analysing the executed experiments.

### Experiment 1

Start a base request load. While the base request load is running, start a
second load that overwhelms Redis to the point it has to run at its full
capacity.

**Expectations**: We expect that the main thread's on-CPU time will reach
approximately 100%. We should also observe the 99th percentile latency increase
while the second load is running.

* (6.1.) Thread attribution: We should be able to single redis' main thread
* (2.1.) on-CPU time should positively correlate with response time

**Observations**

Due to an interesting event, we find that another one of Redis' threads is
scheduled on the same core. This lead to the following correction:

* (2.1.) main thread on-CPU time positively correlates with response time.
* (2.2.) main thread CPU runqueue time positively correlates with response
  time.
* (2.1.) secondary thread on-CPU time **should** positively correlate with
  response time
* (2.2.) secondary thread CPU runqueue time positively correlates with response
  time

### Experiment 2

Start a base request load. While the first load is running, start another
process contending for the same CPU resources, forcing Redis to spend less time
on-CPU than it requires for the base load.

**Expectations**: We expect that the main thread's on-CPU time negatively
correlates with the base load's 99th percentile response time.

* (6.1.) Thread attribution: We should be able to single out redis' main thread
* (2.1.) on-CPU should negatively correlate with the response time
* (2.2.) CPU runqueue time should positively correlate with response time

**Observations**:

Nothing abnormal

* (6.1.) Thread attribution: We observe the main thread being involved in the
  response time's reduced performance.
* (2.1.) main thread on-CPU time negatively correlates with response time
* (2.2.) main thread CPU runqueue time positively correlates with response time

## MySQL

MySQL is a relational database that performs the common ACID operations we are
accustomed to, to provide a consistent view to the data it hosts to the
clients that connect to it. Due to its consistency and persistence guarantees,
we expect futex and disk metrics being the main contributors toward the
response time degradation. When handling connections, MySQL leverages what
seems to be a thread pool of 5 threads. It seems like there is a 1-1 mapping
between a connection and a thread.

### Experiment 1

`2024-06-20T14:43:31.949761868+00:00`

This experiment relies on the YCSB benchmark. The first YCSB benchmark runs for
120 seconds, and is mainly read intensive. We then start a second YCSB
benchmark, mainly write intensive, that updates the same set of rows being read
by the first benchmark. This should lead to increased lock contention and disk
activity, with a strong emphasis on the time spent waiting for locks.

**Expectations**: Since we run 2 benchmarks simultaneously, we expect at least
2 of MySQL's threads to present futex activity. While the second benchmark
runs, we should observe an increase in each thread's futex wait time, and on
the response time.

* (1.1.) & (6.1.) The time the connection threads spent waiting for locks
* (1.2.) & (1.3.) For each connection thread, the share of time it spends
  waiting for any other threads
* (3.1.) & (5.2.) The time a thread spends waiting for socket operations.
* (4.1.) & (2.3.)? & (2.5.)? Disk activity while running the second benchmark.

**Observations**: The 99th percentile response time increases throughout the
execution of the second benchmark. Out of the 5 connection threads (349084
349201 392874 407378 409014), 3 of them (392874 407378 409014) present futex
activity that seems to go along with the proposed benchmarking procedure.

/* ADDITIONAL OBSERVATIONS HERE */

### Experiment 2

`2024-06-21T11:53:26.276310664+00:00`

In this experiment, we leverage the TPCC benchmark. We run a single instance of
the benchmark for 120 seconds. While the benchmark is running, we instantiate
disk write intensive processes, which contend for the same disk resource. This
should lead to increased time to resolve the mysql's disk requests, which in
turn should increase the response time.

**Expectations**: We expect the response time to increase as the share of disk
sector requests belonging to our connection thread decreases. E.g. before the
disk contention processes the disk request share for the connection thread
might be close to 100%, and while the disk intensive processes are running,
this would reduce significantly.

* (4.1.) & (6.1.) The share of disk requests belonging to the connection thread
  will decrease significantly.

**Observations**: While the disk write intensive processes ran, the benchmark's
response time increased.

/* ADDITIONAL OBSERVATIONS HERE */

### Experiment 3

`2024-06-21T21:13:07.123964657+00:00`
`2024-07-30T12:33:54.172726935+00:00`

This experiment is a combination of the previous 2 experiments. Our aim is to
illustrate how we can leverage multiple application target metrics to analyse
the same set of metrics, providing different insights toward the application
behaviour. Our base cases are the tpcc and YCSB read intensive benchmarks. Our
degradation scenarios are induced by starting disk write intensive processes
(`fs-sync`) followed by running the same write intensive YCSB benchmark as in
experiment 1.

**Expectations**: This time we have 2 target metrics, tpcc and YCSB read
intensive benchmarks' response times. While executing the disk write intensive
processes, we expect tpcc's response time to degrade while YCSB's response time
remains the same. On the other hand, while running the YCSB write intensive
benchmark, we expect YCSB's response time to degrade while having a slight
impact on tpcc (due to also writing data to disk).

**Observations**: tpcc really takes a hit while the disk write intensive
workloads run, and does not suffer that great an impact while the YCSB write
intensive benchmark runs. With regard to the YCSB read intensive benchmark, it
remains relatively stable throughout the experiment, except while the YCSB
write intensive benchmark ran, where it saw an order of magnitude increase in
its response time.

/* ADDITIONAL OBSREVATIONS HERE */

## Solr

Solr is an open-source implementation of an indexed search engine. There are
really no expectations with regard to the application's resource usage
patterns, however, the search engine's response time when the CPU's are
saturated. 

`2024-07-05T13:23:49.743174414+00:00`
`2024-07-31T14:10:52.424946255+00:00`

This experiment consists of slowly increasing the number of users and analyzing
the application's response time.

## Cassandra

Cassandra is a highly available NoSQL database. The database store data in disk
however, our workloads will not perform any acid transactions so we don't
really expect locking mechanisms to be a bottleneck in this case. We expect
other resources such as CPU and disk resource share and availability to impact
the performance of executed workloads.

`2024-07-08T15:47:12.912455745+00:00`
`2024-08-03T05:51:31.266846823+00:00`

This experiment runs 2 competing workloads that compete with / impact the
target workload.

## Kafka 

Kafka is a message broker system that mediates the communication between data
producers and data consumers. By default, Kafka uses replication to provide
message persistence guarantees, which leads to Kafka relying on the OSs
pagecache when data is written to disk. To lower the chance of a message being
lost, we configured Kafka to flush data to disk at a higher rate through its
`KAFKA_LOG_FLUSH_INTERVAL_MESSAGES` and `KAFKA_LOG_FLUSH_INTERVAL_MS`
configuration variables set to `1`. For this reason, we expect the rate at
which Kafka is able to write to disk to be the limiting factor.

`2024-07-15T09:56:01.894228563+00:00`
`2024-08-04T18:01:53.300127572+00:00`

This experiment slowly increases the rate of consumption, from 5-45 experiments
running simultanesously. Each experiment produces a total 10,000 events per
second if allowed to.

## Teastore

Teastore is a reference microservice architecture, commonly used to test
microservice architectures. The distributed system is composed of multiple
services, each providing specific functionality to the other services. We will
monitor a particular service in the architecture, while slowly increasing the
load. Despite the service not being the bottleneck in the architecture, we
expect the time the service waits for communication from the bottlenecked
service to increase.

`2024-07-17T14:58:27.927691753+00:00`
`2024-07-22T14:50:21.319563176+00:00`

In this experiment we apply a "double wave" load pattern, an example load
pattern provided by locust to the system's entrypoint, while restricting the
resources to one of the downstream components, in this case, the `persistence`
service. While doing so, we collect metrics from the `webui` service.

## ML inference

This is a sample serving application that wraps a sentiment analysis ML model
with FastAPI, uvicorn and gunicorn. Gunicorn starts 4 worker processes, all of
them attaching to the same host IP and port combination, in essence sharing
connection load between all worker processes. We expect CPU to be the limiting
resource when the load is too high. More specifically, we expect an increase on
the time the worker threads have to wait for a core (runnable state instead of
running).

`2024-07-19T09:17:30.350280302+00:00`

In this experiment, we use the "double wave" load pattern, similar to the
example load pattern provided by the locust development team.
