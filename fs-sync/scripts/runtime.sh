#!/bin/bash

USAGE="\
Usage: 
    runtime.sh <pid>

Options:
    <pid>   target process
"

if [[ $# -ne 1 ]]; then
    echo "$USAGE"
    exit 1
fi 

pid=$1
if ! [[ "$pid" =~ [0-9]+ ]]; then
    echo "$USAGE"
    exit 1
fi 


# while true; do 
#     prev_utime="$curr_utime"
#     curr_utime="$(cat /proc/$pid/stat | awk '{print $14}')"

#     prev_stime="$curr_stime"
#     curr_stime="$(cat /proc/$pid/stat | awk '{print $15}')"

#     if [[ -z "$prev_utime" ]]; then
#         continue
#     fi
#     if [[ -z "$prev_stime" ]]; then
#         continue
#     fi 
#     
#     diff_utime=$(python -c "print(($curr_utime - $prev_utime))")
#     diff_stime=$(python -c "print(($curr_stime - $prev_stime))")
#     printf "stime: $diff_stime\tutime: $diff_utime\n"
#     sleep 1 
# done
#

printf "%20s\t%s\t%s\t%s\t%s\t%s\t%s\n" "timestamp" "exec_runtime" "sleep_runtime" "block_runtime" "wait_sum" "iowait_sum" "total_runtime"
while true; do
    ts=$(date +"%T.%N")
    off_cpu="$(cat /proc/$pid/sched | grep -E "sum_sleep_runtime|sum_block_runtime|sum_exec_runtime|wait_sum|iowait_sum")"
    # awk '{ print(NR, $0) }' <<< $off_cpu
    # break
    
    exec_runtime[1]="$(awk '{ if (NR==1) print($3) }' <<< $off_cpu)"
    sleep_runtime[1]="$(awk '{ if (NR==2) print($3) }' <<< $off_cpu)"
    block_runtime[1]="$(awk '{ if (NR==3) print($3) }' <<< $off_cpu)"
    wait_sum[1]="$(awk '{ if (NR==4) print($3) }' <<< $off_cpu)"
    iowait_sum[1]="$(awk '{ if (NR==5) print($3) }' <<< $off_cpu)"
    printf "%20s\t%12s\t%13s\t%13s\t%8s\t%10s\t%13s\n" \
        $ts \
        $(python -c "print(int(${exec_runtime[1]} - ${exec_runtime[0]:-${exec_runtime[1]}}))") \
        $(python -c "print(int(${sleep_runtime[1]} - ${sleep_runtime[0]:-${sleep_runtime[1]}}))") \
        $(python -c "print(int(${block_runtime[1]} - ${block_runtime[0]:-${block_runtime[1]}}))") \
        $(python -c "print(int(${wait_sum[1]} - ${wait_sum[0]:-${wait_sum[1]}}))") \
        $(python -c "print(int(${iowait_sum[1]} - ${iowait_sum[0]:-${iowait_sum[1]}}))") \
        $(python -c "print(int((${exec_runtime[1]}-${exec_runtime[0]:-${exec_runtime[1]}})\
                              +(${block_runtime[1]}-${block_runtime[0]:-${block_runtime[1]}})\
                              +(${wait_sum[1]}-${wait_sum[0]:-${wait_sum[1]}})\
                              ))")

    # python -c "print(int(${exec_runtime[1]} - ${exec_runtime[0]:-0}))"
    # python -c "print(int(${sleep_runtime[1]} - ${sleep_runtime[0]:-0}))"

    exec_runtime[0]=${exec_runtime[1]}
    sleep_runtime[0]=${sleep_runtime[1]}
    block_runtime[0]=${block_runtime[1]}
    wait_sum[0]=${wait_sum[1]}
    iowait_sum[0]=${iowait_sum[1]}

    # python -c "print($exec_runtime+$sleep_runtime+$block_runtime+$wait_sum+$iowait_sum)"
    sleep 0.93
done
