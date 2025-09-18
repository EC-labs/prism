# Cassandra

## Setup

**The following commands assume you are within the benchmarks/cassandra directory:**
```bash
cd benchmarks/cassandra
```

Create the network to be shared between the clients and the server:
```bash
docker network create cassandra
```

Server: 

```bash
docker run \
    --cpuset-cpus 0-1 --cpus 2 -d --rm --name cassandra-server \
    --net cassandra cloudsuite/data-serving:server
```

Start tracing cassandra with Prism:
```bash
cd ../..
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
cargo run -r -p metric-collector -- --pids "$(docker top cassandra-server | tail -n +2 | awk '{print $2}' | paste -s -d, -)" >./prism_${ts}.log 2>&1 &
cd benchmarks/cassandra
```


There are two workload configuration files that define the operations the
benchmarking clients will perform. In the following command, the workload
configuration file is in `ycsb-update`.

Run the YCSB update workload:
```bash
docker run \
    --rm -it --name cassandra-client-update \
    -v ./ycsb-update:/ycsb/workloads/workloada \
    -v ./log:/tmp \
    --net cassandra cloudsuite/data-serving:client bash

# Within the client now
# ./warmup.sh <server-ip> <num-records> <num-threads>
./warmup.sh cassandra-server 1000 1

# ./load.sh <server-ip> <num-records> <target-load> <num-threads> <num-operations>
# The following command runs for an estimated 150s
./load.sh cassandra-server 1000 100000 10 3000000
```


Wait for 30 seconds, and in another terminal that is not part of the client container, start disk intensive workloads from the root directory of the Prism repository:
```bash
cd ../..
for i in $(seq 0 80); do cargo run -p poc --bin fs-sync >/dev/null 2>&1 &; done
```

Wait for another 30 seconds and stop disk intensive workloads:
```bash
ps -ef | grep fs-sync | head -n -1 | awk '{print $2}' | xargs -I @ -d '\n' kill -SIGTERM @
```

Run the YCSB
```bash
cd benchmarks/cassandra
docker run \
    --rm -it --name cassandra-client-read \
    -v ./ycsb-read:/ycsb/workloads/workloada \
    --net cassandra cloudsuite/data-serving:client bash

# Within the client now
# ./warmup.sh <server-ip> <num-records> <num-threads>
./warmup.sh cassandra-server 1000 1

# ./load.sh <server-ip> <num-records> <target-load> <num-threads> <num-operations>
# The following command runs for an estimated 150s
./load.sh cassandra-server 1000 100000 10 3000000
```

After 30 seconds terminate the ycsb-read benchmark:
```bash 
docker stop cassandra-client-read cassandra-client-update cassandra-server
docker network rm cassandra
sudo chown -R $USER:$USER log
```

You will find the YCSB update per-request latency data in `benchmark/cassandra/log/raw_response_time`.

## Experiment

Our goal is to measure the throughput of our `ycsb-update` benchmark, while
simultaneously running loads that impact cassandra's performance. We expect the
throughput to be regular when these workloads are not running, and the
throughput to drop throughout the execution of these competing workloads.

Procedure: 

1. Start the `ycsb-update` client workload which should run for approx. 150s.
1. After 30s start the `ycsb-read` workload.
1. After 60s stop the `ycsb-read` workload.
1. After 90s from the start of the experiment, start disk intensive workloads.
1. After 120s stop the disk intensive workloads.

The experiment uses/produces the following artifacts, that can be found in
`application-metrics`: 

* `ycsb-read`: Workload configuration for a read-intensive ycsb benchmark
* `ycsb-update`: Workload configuration for an update-intensive ycsb benchmark
* `ycsb-update-output`: ycsb update-intensive workload per request response
  time benchmark output. 
* `update-response-time`: Per request information, derived from
  `ycsb-update-output`, to be passed into `percentile-ps`.
