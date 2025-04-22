#!/bin/bash 

set -e

script_d="$(realpath "$(dirname $0)")"
child_pids=()

function kill_child_pids() {
    kill -9 "${child_pids[@]}" 
}

trap kill_child_pids SIGTERM

python "${script_d}/cpu_contender.py" &
child_pids+=($!)
echo ${child_pids[@]}
taskset -p 0x1 "${child_pids[-1]}"
wait
