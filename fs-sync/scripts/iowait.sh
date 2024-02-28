#!/bin/bash

USAGE="\
Usage: 
    iowait.sh <pid>

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


while true; do 
    prev="$curr"
    curr="$(cat /proc/$pid/stat | awk '{print $42}')"

    if ! [[ -z $prev ]]; then
        python -c "print(($curr - $prev)*1.0)"
    fi

    sleep 1 
done
