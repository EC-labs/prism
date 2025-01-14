#!/bin/bash

set -e

script_d="$(realpath "$(dirname $0)")"
ts="$(date +%s)"

cd $script_d

docker network create redis 2>/dev/null || true

docker run \
    --cpuset-cpus 0 -d \
    --rm --name redis \
    --user redis \
    --network redis \
    redis:7.4.2

cd ../..
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
cargo run -r -p metric-collector -- --pids "$(docker top redis | tail -n +2 | awk '{print $2}')" >./prism_${ts}.log 2>&1 &
prism=$!


cd "$script_d"

sleep 10
echo "Starting the memtier (target) benchmark"
docker run \
    --cpuset-cpus 1-15 \
    --rm -d -v ./log:/tmp \
    --network redis \
    --name memtier-benchmark \
    yyuhj46l4y0s7mn/prism-memtier:1.0.0 \
    --ratio=1:1 --test-time=320 --rate-limiting=130 -t 4 -c 200 -h redis

sleep 30
echo "Starting redis-benchmark"
docker run \
    --cpuset-cpus 1-15 --rm -d \
    --network redis \
    --name redis-benchmark \
    redis:7.4.2 \
    redis-benchmark \
    -t set -c 1 -r 100000 -d 10000 -n 1000000 -h redis
sleep 30
echo "Stopping redis-benchmark"
docker stop redis-benchmark || true

sleep 30 
echo "Starting the cpu contention workload"
"${script_d}/../dependencies/cpu_contender/run.sh" >/dev/null 2>&1 &
cpu_contender=$!
sleep 30
echo "Terminating cpu contender"
kill -SIGTERM "$cpu_contender"

sleep 30

echo "Clearing resources created by benchmark"
docker stop redis 
docker stop memtier-benchmark || true
docker network rm redis 
kill -SIGINT "$prism"
sudo chown -R $USER:$USER "${script_d}/log"
