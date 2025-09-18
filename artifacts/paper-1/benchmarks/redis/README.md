# Redis

The target benchmark we will collect metrics from is the memtier benchmark. However, throughout the execution of this benchmark, we will first start a competing benchmark that will saturate redis' resources (`redis-benchmark`), followed by executing a cpu contenting benchmark (`cpu-contender-script`).

To execute the benchmark run:
```bash
benchmarks/redis/run.sh
```

You should now see a new file in the `benchmarks/redis/log` directory that contains the per-request latency of the memtier benchmark. To get the 95th percentile latency for this data run:
```bash
find benchmarks/redis/log -name "memtier_*.csv" | head -n 1 | xargs -I @ bash -c 'cat @ | cargo r -r -p percentile-ps -- --time-factor 1000000 --percentile 0.95'
```

The commands output contains a per-second 95th percentile latency. This data can be used as the target metric for the data analysis.

With regards to prism's metrics, you should find a new directory in the root `data` directory containing all system metrics collected for redis, by prism. These can be used to understand what caused redis' degraded performance throughout the benchmark.
