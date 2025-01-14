# 🔎 Prism: Deconstructing Performance Degradation

Prism is a fine-grained metric collection tool that aims to facilitate uncovering the cause of an application's performance degradation through a generalisable set of metrics. E.g. In a scenario where a database is under lock contention through simultaneous access to the same dataset, Prism will highlight the database threads and futex resource behind this activity. Currently Prism supports discovering and tracing co-located processes that have communicated (through IPC mechanisms such as pipes, sockets, and futexes) with the initial target application.

Usenix ATC'25 Artifact: **Prism: Application-agnostic Granular Instrumentation Approach to Deconstruct Performance Degradation**

# Dependencies

Prism has been tested on x86_64 Ubuntu 22.04 machines, with kernel version `6.8.12`, and bpftrace version `v0.18.0-42-g6404`.

## Ubuntu 

These are the software requirements to run Prism
```
# Install Rust and Cargo
curl https://sh.rustup.rs -sSf | sh 

# Install bpftrace
sudo apt install -y bpftrace
```

# How-to-use

Make sure Prism's dependencies are installed before proceeding.

## Basic Usage Example

Before we start Prism, we have to make sure we have configured the kernel and our environment with the following options:
```bash
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
```

To start Prism, we have to first get the pid of our target process. In the following example, I will start the redis instance used in our benchmarks: 

```bash
# Start redis
docker run \
    -d --rm \
    --name redis \
    --user redis \
    redis:7.4.2

# Get redis' pid
target="$(docker top redis | tail -n +2 | awk '{print $2}')"

# Start Prism and the running redis instance
cargo run -r -p metric-collector -- --pids "$target"
```

Sending a SIGINT signal (e.g. Ctrl-C) to Prism will terminate the main and child processes.

## Output

By default, the data collected by Prism is stored in a directory with the naming convention `<repo-root>/data/<timestamp>`, where `repo-root` points to the repository's root directory, and `timestamp` represents the time Prism was instantiated to trace a particular target.

Within this directory, there is another directory named `system-metrics`, which includes a `global` and a `thread` directory. The `global` directory includes statistics that for `iowait` (block IO) which is collected system-wide, and therefore, the remainder of the path represents the `<process>/<thread>/<minute>/<device>.csv` the data was collected for. `global` includes an `epoll` directory to account for multiple threads waiting for the same epoll resource. This directory however accounts for the time waiting for a specific resources added through the `epoll_ctl` syscall. E.g. `.../global/epoll/ffff9a7a3f5e0240/sockets/1722794820/ipv4_172.26.0.2:58656_172.26.0.2:29093.csv` would indicate that the target application waited for an epoll resource with the ID ffff9a7a3f5e0240, that was tracking an ipv4 socket with 172.26.0.2:58656 source address, and 172.26.0.2:29093 destination address.

On the other hand, the `thread` directory includes metrics collected at a thread granularity for multiple subsystems. The following directories have a hierarchy that starting with the `<pid>/<tid>` of the traced thread. The next level includes directories named `sched`, `schedstat`, `ipc` and `futex` (`schedstat` is a subset of the data included in `sched`): 

* The `sched` directory includes thread scheduling statistics; 
* The `ipc` directory includes Interprocess Communication data related with pipes and sockets. The data is tracked on a per-socket/per-pipe basis.
* The `futex` directory includes statistics on the wake and wait frequency for a particular `futex`.

# Experimentation

## Datasets

To unzip the datasets, run: 
```bash
./scripts/unzip-datasets.sh
```

Within the `data/` directory you should now find the following directories, each corresponding to an application in the paper's experimentation section:

* `2024-07-30T12:33:54.172726935+00:00`: MySQL
* `2024-07-31T14:10:52.424946255+00:00`: Solr
* `2024-08-03T05:51:31.266846823+00:00`: Cassandra
* `2024-08-04T18:01:53.300127572+00:00`: Kafka
* `2024-08-24T16:10:31.710423758+00:00`: Teastore
* `2024-08-06T07:50:39.470480264+00:00`: ML-inference
* `2024-05-19T13:08:15.671530744+00:00`: Redis

Other than the `system-metrics` collected by Prism, these directories also include `application-metrics` which contain their target metrics and data specific to the load execution, e.g. configuration files, and a README file.

## Analysis

Each application has its own jupyter notebook script in the `notebooks` directory which includes the analysis presented in the paper and additional results.

## Reproducibility

To generate similar datasets for the same applications as those presented in the previous section, we have provided a description, and in some cases a run script in the `benchmarks/` directory for each application.

# Resource Usage

To check Prism's resource usage, you can run the following command:
```bash 
top -d 1 -H -p "$(ps -ef | grep -E 'target/.*metric-collector|bpftrace' | head -n -1 | awk '{print $2}' | paste -s -d ,)"
```
