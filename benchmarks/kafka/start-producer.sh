#!/bin/bash

script_d="$(realpath "$(dirname "$0")")"

docker run \
    --rm \
    -v "$script_d/config.json":/app/config.json --network host dclandau/cec-experiment-producer \
    --brokers localhost:9092 \
    --no-ssl \
    --config-file "./config.json"
