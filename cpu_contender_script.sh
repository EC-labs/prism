#!/bin/bash 

child_pids=()

function kill_child_pids() {
    kill -9 "${child_pids[@]}" 
}

trap kill_child_pids SIGINT

python cpu_contender.py &
child_pids+=($!)
echo ${child_pids[@]}
taskset -p 0x2 "${child_pids[-1]}"

python cpu_contender.py &
child_pids+=($!)
echo ${child_pids[@]}
taskset -p 0x4 "${child_pids[-1]}"

wait
