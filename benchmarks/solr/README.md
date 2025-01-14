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
    --cpus 2 --rm \
    -it --name websearch-server \
    -p 8983:8983 -v ./websearch-dataset:/download/index_14GB/data \
    --net websearch \
    cloudsuite/web-search:server 14g 1
```

Navigate to the goose-test directory:
```bash
cd ../goose-test
```

and generate the test plan: 
```bash
# Navigate to the goose-test directory
{ for i in $(seq 10 20 150); do printf "%d,1s;%d,9s;" $i $i; done; echo "0,1s"; } > test-plan
```

To start the load test: 
```bash
# Navigate to the goose-test directory
cargo r -r -- --host http://localhost:8983 --report-file report.html --test-plan "$(cat test-plan)"
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
