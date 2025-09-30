# 🔎 Prism: Application-Agnostic Observability

Prism is a fine-grained metric collection tool that aims to facilitate uncovering the cause of an application's performance degradation through a generalisable set of metrics. E.g. In a scenario where a database is under lock contention through simultaneous access to the same dataset, Prism will highlight the database threads and futex resource behind this activity. Currently Prism supports discovering and tracing co-located processes that have communicated (through IPC mechanisms such as pipes, sockets, and futexes) with the initial target application.

![demo](docs/demo.gif)

# Getting Started

## Docker

```bash
docker run \
    --rm -it --privileged \
    -e RUST_LOG=info \
    --pid host \
    -v ./cdata:/data \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/kernel/debug:/sys/kernel/debug \
    --name ripple \
    dclandau/ripple --machine-id <machine-id>
```

## Nix

1. Install [nix](https://nixos.org/download/) for your distro
2. Get a local clone of this repository

We start by creating a data directory, which is where Prism will write its data to: 

```bash
mkdir data 2>/dev/null
```

We then install the dependencies specified in the `shell.nix` file, and make these available in your shell environment with:
```bash
nix-shell shell.nix
```

Within the nix-shell environment, you may now start Prism (**don't forget to change the `<pid>` argument in the command**): 
```bash
RUST_LOG=info cargo run -r -p metric-collector --config 'target."cfg(all())".runner="sudo -E"' -- --pids <pid>
```

Press `Ctrl-C` to terminate Prism. A new file will be made available in the `data/` directory we created in the first command. E.g.:
```bash
$ ls -la data
.rw-r--r-- 4,7M username 11 apr 16:54 prism-2025-04-11T14:53:27.082056990+00:00.db3
```

Make sure you are still in the nix-shell environment and you may analyse the data with:
```
v1.1.3 19864453f7
$ duckdb "data/prism-2025-04-11T14:53:27.082056990+00:00.db3"
Enter ".help" for usage hints.
D select * from taskstats_view;
┌────────────────────────────┬────────────┬────────┬────────┬─────────────────┬───────────┬──────────┬───────────────────────┬─────────────┬─────────────────────┐
│             ts             │ time_diff  │  pid   │  tid   │      comm       │ run_share │ rq_share │ uninterruptible_share │ blkio_share │ interruptible_share │
│         timestamp          │   int64    │ uint32 │ uint32 │     varchar     │  double   │  double  │        double         │   double    │       double        │
├────────────────────────────┼────────────┼────────┼────────┼─────────────────┼───────────┼──────────┼───────────────────────┼─────────────┼─────────────────────┤
│ 2025-04-11 14:53:56.872306 │  998514000 │   1018 │   1062 │ gdbus           │       0.0 │      0.0 │                   0.0 │         0.0 │                 1.0 │
│             ·              │      ·     │     ·  │     ·  │   ·             │        ·  │       ·  │                    ·  │          ·  │                  ·  │
│             ·              │      ·     │     ·  │     ·  │   ·             │        ·  │       ·  │                    ·  │          ·  │                  ·  │
│             ·              │      ·     │     ·  │     ·  │   ·             │        ·  │       ·  │                    ·  │          ·  │                  ·  │
│ 2025-04-11 14:54:45.893241 │ 1000157000 │  73150 │  73155 │ GpuMemoryThread │       0.0 │      0.0 │                   0.0 │         0.0 │                 1.0 │
├────────────────────────────┴────────────┴────────┴────────┴─────────────────┴───────────┴──────────┴───────────────────────┴─────────────┴─────────────────────┤
│ 20640 rows (2 shown)                                                                                                                                10 columns │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

D select * from vfs;
┌────────────────────────────┬────────┬────────┬────────────┬───────────┬──────────┬───────┬────────────┬────────────────┬────────┬────────┬────────┬────────┬────────┬────────┬────────┬────────┐
│            ts_s            │  pid   │  tid   │  fs_magic  │ device_id │ inode_id │  op   │ total_time │ total_requests │ hist0  │ hist1  │ hist2  │ hist3  │ hist4  │ hist5  │ hist6  │ hist7  │
│         timestamp          │ uint32 │ uint32 │   uint32   │  uint32   │  uint64  │ uint8 │   uint64   │     uint32     │ uint32 │ uint32 │ uint32 │ uint32 │ uint32 │ uint32 │ uint32 │ uint32 │
├────────────────────────────┼────────┼────────┼────────────┼───────────┼──────────┼───────┼────────────┼────────────────┼────────┼────────┼────────┼────────┼────────┼────────┼────────┼────────┤
│ 2025-04-11 14:53:32.009116 │   2004 │   2039 │   16914836 │ 236978177 │      683 │     0 │      36250 │              4 │      0 │      3 │      1 │      0 │      0 │      0 │      0 │      0 │
│             ·              │     ·  │     ·  │       ·    │         · │       ·  │     · │        ·   │              · │      · │      · │      · │      · │      · │      · │      · │      · │
│             ·              │     ·  │     ·  │       ·    │         · │       ·  │     · │        ·   │              · │      · │      · │      · │      · │      · │      · │      · │      · │
│             ·              │     ·  │     ·  │       ·    │         · │       ·  │     · │        ·   │              · │      · │      · │      · │      · │      · │      · │      · │      · │
│ 2025-04-11 14:54:43.009116 │   8187 │   8230 │ 1397703499 │         0 │   257746 │     0 │     580141 │             36 │      0 │      2 │     34 │      0 │      0 │      0 │      0 │      0 │
├────────────────────────────┴────────┴────────┴────────────┴───────────┴──────────┴───────┴────────────┴────────────────┴────────┴────────┴────────┴────────┴────────┴────────┴────────┴────────┤
│ 5950 rows (2 shown)                                                                                                                                                                 17 columns │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

# Data

Prism collects data for multiple subsystems and stores the enriched metrics in a duckdb database. The tables available are:
```
D show tables;
┌─────────────────┐
│      name       │
│     varchar     │
├─────────────────┤
│ docker          │
│ futex_wait      │
│ futex_wake      │
│ iowait          │
│ k8s             │
│ linux_consts    │
│ process_context │
│ socket_context  │
│ socket_inet     │
│ socket_map      │
│ taskstats       │
│ taskstats_view  │
│ tcp_discovery   │
│ vfs             │
├─────────────────┤
│     14 rows     │
└─────────────────┘
```

# Paper
The following content refers to the data generated for the following paper:<br>
            
      Diogo Landau, Jorge Barbosa, Nishant Saurabh. "eBPF-Based Instrumentation for Generalisable Diagnosis 
      of Performance Degradation". arXiv preprint arXiv:2505.13160 (2025).

## Bibtex
      @misc{landau2025ebpfbasedinstrumentationgeneralisablediagnosis,
      title={eBPF-Based Instrumentation for Generalisable Diagnosis of Performance Degradation}, 
      author={Diogo Landau and Jorge Barbosa and Nishant Saurabh},
      year={2025},
      eprint={2505.13160},
      archivePrefix={arXiv},
      primaryClass={cs.DC},
      url={https://arxiv.org/abs/2505.13160},
      }

## Experiments

To unzip the datasets, run: 
```bash
./scripts/unzip-datasets.sh
```

Within the `data/` directory you should now find the following directories, each corresponding to an application in the paper's experimentation section:

* `2024-07-30T12:33:54.172726935+00:00`: MySQL
* `2024-07-31T14:10:52.424946255+00:00`: Solr
* `2024-08-03T05:51:31.266846823+00:00`: Cassandra
* `2024-08-04T18:01:53.300127572+00:00`: Kafka
* `2024-08-24T16:10:31.710423758+00:00`: Teastore
* `2024-08-06T07:50:39.470480264+00:00`: ML-inference
* `2024-05-19T13:08:15.671530744+00:00`: Redis

Other than the `system-metrics` collected by Prism, these directories also include `application-metrics` which contain their target metrics and data specific to the load execution, e.g. configuration files, and a README file.

Each application has its own jupyter notebook script in the `notebooks` directory which includes the analysis presented in the paper and additional results.

## Reproducibility

To generate similar datasets for the same applications as those presented in the paper, we have provided a description, and in some cases a run script in  `artifacts/paper-1/benchmarks/` directory for each application.
