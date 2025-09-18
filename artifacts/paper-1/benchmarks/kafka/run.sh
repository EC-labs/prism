#! /bin/bash

script_d="$(cd "$(dirname $0)" && pwd)"
ts="$(date +%s)"

cd "$script_d"

echo "Starting kafka"
docker compose up -d

cd ../..
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
cargo run -r -p metric-collector -- --pids "$(docker top kafka | tail -n +2 | awk '{print $2}')" >./prism_${ts}.log 2>&1 &
prism=$!
cd "$script_d"

echo "Starting producers"
docker run \
    --rm -d \
    -v "$script_d/config.json":/app/config.json \
    --network host \
    yyuhj46l4y0s7mn/experiment-producer \
    --brokers localhost:9092 \
    --no-ssl \
    --config-file "./config.json"

cd ./scrape-experiment-producer
cargo r -r >/dev/null 2>&1 &
scrape_pid=$!
wait $scrape_pid

echo "Experiment terminated"
echo "Clearing resources created by benchmark"
cd "$script_d"
docker compose down
kill -SIGINT "$prism"
