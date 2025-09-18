# MySQL

## Setup

To start mysql server: 

```bash
docker run --rm --name mysqldb -p 127.0.0.1:3306:3306  -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mysql:8.4.0
```

Create the `benchbase` database which is required to run the workloads:
```bash
mysql -h localhost -u root -P 3306 -p
# CREATE DATABASE benchbase
```

Wait for 1 minute and start tracing mysql with prism. **Make sure you are in Prism's root directory**:
```bash
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
cargo run -r -p metric-collector -- --pids "$(docker top mysqldb | tail -n +2 | awk '{print $2}')" >./prism_${ts}.log 2>&1 &
```

Now change directory into benchbase's repository:
```bash
cd dependencies/benchbase
```
and follow their quickstart [guide](https://github.com/cmu-db/benchbase?tab=readme-ov-file#quickstart) to build the mysql profile:

**The following commands assume you are back in our repository's `benchmarks/mysql` directory**. To run the experiment:

```bash
cp experiment.sh benchmarks/benchbase/target/benchbase-mysql
cd benchmarks/benchbase/target/benchbase-mysql
./experiment.sh
```

The benchmark outputs will be in the `benchmarks/dependencies/benchbase/target/benchbase-mysql/results` directory.

## Experiment

The goal of this experiment is to combine both previous experiments to
illustrate the use of multiple target metrics to analyse the same underlying
set of metrics.

Procedure: 

1. Start both the tpcc and the YCSB read intensive benchmarks. Configuration
   can be found in the `application-metrics` directory
2. After approximately 30s since the beginning of the experiment, start the
   disk write intensive processes for a duration of 20s.
3. After approximately 70s since the beginning of the experiment, start the
   second YCSB write intensive benchmark. Configuration can be found in the
   `application-metrics` directory.

The second step in the procedure targets the first workload, as it contends for
the same disk resources the tpcc benchmark requires. However, the third step in
the procedure initiates the write intensive YCSB benchmark. This second
benchmark might impact the tpcc instance, however we expect it to have a bigger
impact on the first read-intensive benchmark. As such, we can use the response
time of each initial benchmark to illustrate how the highlighted metrics will
differ between degradation scenarios.

Artifacts: 

* `experiment.sh`: Script used to run the experiment
* `thread_comm.log`: Thread to comm mapping
* `tpcc*`: Benchbase artifacts produced after the termination of the base tpcc
  benchmark
* `ycsb_2024-07-30_14-36-23*`: Benchbase artifacts produced after the
  termination of the base ycsb benchmark
* `ycsb_2024-07-30_14-36-18*`: Benchbase artifacts produced after the
  termination of the write intensive ycsb benchmark
