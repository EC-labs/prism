#!/bin/bash

pids=()

echo "Starting base ycsb and tpcc loads"
java -jar benchbase.jar -b ycsb -c config/mysql/experiment_ycsb_base.xml --create=true --load=true --execute=true >/dev/null 2>&1 &
pids+=($!)

java -jar benchbase.jar -b tpcc -c config/mysql/sample_tpcc_config.xml --create=true --load=true --execute=true >/dev/null 2>&1 &
pids+=($!)

sleep 25

echo "Starting disk intensive contention"
# Start disk intensive write activity
cd /home/diogo/Repos/personal/paper-1
for _ in $(seq 0 80); do
    cargo r -r -p poc --bin fs-sync >/dev/null 2>&1 &
done
cd -

sleep 30

echo "Terminating disk intensive contention"
ps -ef | grep fs-sync | awk '{print $2}' | head -n -1 | xargs -I @ kill -sigterm @

sleep 30

echo "Start ycsb lock contention"
java -jar benchbase.jar -b ycsb -c config/mysql/experiment_ycsb_tmp.xml --execute=true >/dev/null 2>&1 &
pids+=($!)

wait "${pids[@]}"
