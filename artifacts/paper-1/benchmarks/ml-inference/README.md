# ML Inference

We serve an open source sentiment analysis model to infer the sentiment of a
tweet.

For the machine learning inference server, we wrap the model in a FastAPI
application. Upon receiving a get request coupled with the tweet, the API
responds with the models sentiment prediction.

As for the load, each request consists of a randomly selected tweet from this
[dataset](https://www.kaggle.com/datasets/jp797498e/twitter-entity-sentiment-analysis).
We then generate a double wave load, the load pattern provided in one of
locust's example load patterns.

## Setup

**The following commands assume you are running within the `benchmarks/ml-inference` directory:**
```bash
cd benchmarks/ml-inference
```

Create the network that will be shared between the client and the server:
```bash
docker network create ml-inference
```

To build the ML inference server: 

```bash
# Change directory into `./application-metrics/ml-inference`
docker build -t ml-inference ./inference
```

To start the server:
```bash
docker run -d --network ml-inference --name inference-server --rm --cpus 4 -p 8000:8000 ml-inference
```

Start tracing the ml-inference server with Prism: 
```bash
cd ../..
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
cargo run -r -p metric-collector -- --pids "$(docker top inference-server | tail -n +2 | awk '{print $2}' | paste -s -d, -)" >./prism_${ts}.log 2>&1 &
cd benchmarks/ml-inference
```

### Load

To build the ML load generator: 
```bash
docker build -t ml-load ./load
```

To start the load generator:
```bash
docker run \
    --rm -d \
    -v ./load/twitter_training.csv:/usr/src/app/twitter_training.csv \
    -v ./data:/usr/src/data \
    --network ml-inference \
    --name inference-load \
    -p 8089:8089 \
    ml-load
```

To generate the load against the inference server, open locust's UI at `localhost:8089`, and where it says `Host`, put the inference server's container name and port, i.e., `http://inference-server:8000`. Press start and it should start generating load.

Terminate the load generator:
```bash
docker stop inference-load
```

and you should observe 2 files `benchmarks/ml-inference/data/raw_{users,requests}.csv`. The `raw_requests.csv` can be further processed into its per-second 95th percentile stream with:
```bash
cd ../..
cat benchmarks/ml-inference/data/raw_requests.csv | cargo run -r -p percentile-ps -- --time-factor 1000 --percentile 0.95
```

To remove the resources created:
```bash
docker stop inference-server inference-load
docker network rm ml-inference
```

## Experiment

1. Start the locust load pattern as described above

The experiment has the following artifacts: 

* `./application-metrics/raw_requests.csv`: Contains the start and end times of
  a request, and its latency 
* `./application-metrics/raw_users.csv`: The number of users started at a
  particular instant
* `./application-metrics/load`: Source code for the load generator
* `./application-metrics/ml-inference`: Source code for the ML inference server
