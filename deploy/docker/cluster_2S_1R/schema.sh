#!/bin/bash

while ! wget --spider --no-check-certificate -T 1 -q "http://clickhouse-01:8123/ping" 2>/dev/null; do
  echo "Waiting for ClickHouse..."
  sleep 1
done
echo "ClickHouse is up — applying schema..."
clickhouse-client -h clickhouse-01 --port 9000 --user cluster_user --password "cluster_pass" -n < /docker-entrypoint-initdb.d/init.sql

res="$(clickhouse-client -h clickhouse-01 --port 9000 --user cluster_user --password "cluster_pass" -q "select count(*) from information_schema.tables where table_schema = 'default'" | tr -d '[:space:]')"

if [ "$res" -eq "36" ]; then
  echo "Default schema has 36 tables. Success"
  exit 0
else
  echo "Default schema has $res tables. Expected 36"
  exit 1
fi
