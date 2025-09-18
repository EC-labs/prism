# Solr

## Setup

To download the websearch dataset, run the following command **from the cloudsuite repository (`benchmarks/dependencies/cloudsuite`):
```bash 
cd ../dependencies/cloudsuite
docker run --name web_search_dataset -v ./dataset:/download cloudsuite/web-search:dataset
```

> Note: The download might take a while

After the download has completed, run the following commands:
```bash
sudo chown -R $USER:$USER dataset
mv dataset/index_14GB/data/ websearch-dataset
```

To start the server:

```bash
# Still in the benchmarks/dependencies/cloudsuite directory
docker run \
    --cpus 2 --rm -d \
    -it --name websearch-server \
    -p 8983:8983 -v ./websearch-dataset:/download/index_14GB/data \
    --net websearch \
    cloudsuite/web-search:server 14g 1
```

Wait until the server has initiated, and start tracing solr with Prism:
```bash
docker logs -f websearch-server
cd ../../..
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
cargo run -r -p metric-collector -- --pids "$(docker top websearch-server | tail -n +2 | awk '{print $2}' | paste -s -d, -)" >./prism_${ts}.log 2>&1 &
```

Navigate to the `solr-benchmark` directory:
```bash
cd benchmarks/solr-benchmark
```

and generate the test plan: 
```bash
{ for i in $(seq 10 20 150); do printf "%d,1s;%d,9s;" $i $i; done; echo "0,1s"; } > test-plan
```

To start the load test: 
```bash
cargo r -r -- --host http://localhost:8983 --report-file report.html --test-plan "$(cat test-plan)"
```

Upon termination, a file `benchmarks/dependencies/solr-benchmark/request_stats.csv` file will contain the per-request latency data. This can be converted to a per-second 90th percentile latency with: 
```bash
cat benchmarks/dependencies/solr-benchmark/request_stats.csv | cargo run -r -p percentile-ps -- --time-factor 1000 --percentile 0.9
```

## Experiment

The goal of this experiment is to determine the query load that saturates our
search engine (implemented in solr).

The application-metrics contains the artifacts of the experiment: 

* `request_stats.csv`: This file indicates the start and end times of each
  request, and their respective delays.
* `request_percentile_95.csv`: Computation of the 95th percentile latencies for
  each second during which requests ran.
* `test-plan`: Is the test plan used when executing the load test with goose.
* `test_plan.csv`: The resulting test plan indicating the time a specific plan
  ran for, and the amount of users.
