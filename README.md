# Prism

Prism is a Linux performance diagnostic tool for analysing thread dynamics in distributed systems. It uses lightweight eBPF-based metrics across scheduling, futexes, I/O, networking, and storage, to enable fine-grained analysis of application performance at the level of individual threads, their interactions with each other, and with system resources.

# Quickstart

This section illustrates how to start Prism on a single instance. For a distributed setup, refer to [docs/distributed.md](docs/distributed.md)

<details>
<summary>Run with Docker</summary>

## Docker

Prerequisites:

* [docker](https://docs.docker.com/engine/install/)

Start the metric collector:
```
docker run \
    --rm -it --privileged \
    -e RUST_LOG=info \
    --pid host \
    -v ./data:/data \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/kernel/debug:/sys/kernel/debug \
    --name prism \
    dclandau/prism --machine-id <machine-id> --pids <pid-list>
```

<details>
<summary><b>Example</b></summary>

```
docker run \
    --rm -it --privileged \
    -e RUST_LOG=info \
    --pid host \
    -v ./data:/data \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/kernel/debug:/sys/kernel/debug \
    --name prism \
    dclandau/prism --machine-id 1 --pids 233296,246465
```

</details>


Start the analysis UI:
```
docker run \
    --rm -it \
    -p 8501:8501 \
    --name prism-analysis \
    dclandau/prism-analysis
```

</details>

<details>
<summary>Run with Nix</summary>

## Nix

Prerequisites:

* [nix](https://nixos.org/download/)

Start the metric collector:
```
sudo RUST_LOG=info nix run .#prism -- --machine-id <machine-id> --pids <pid-list>
```

<details>
<summary><b>Example</b></summary>

```
sudo RUST_LOG=info nix run .#prism -- --machine-id 1 --pids 233296,246465
```

</details>

Start the analysis UI:
```
nix run .#analysis
```

</details>

Let the metric collector collect some data, and terminate the metric collector when you would like to move on to analysis.

Visit the analysis UI at `http://localhost:8501/`. The UI includes some template analysis and a simple way to explore the data collected. To start the analysis, you will have to import the database into the UI. By default, the metric collector database files are written to `./data/prism*`. As such, you may now:

1. Import the database file in the `Home` page
1. Visit the `Ripple` page
1. Select a process you want to create a service dependency graph for
1. Visualise the service dependency graph for that process
1. Run custom queries in the `Debug` page
   <details><summary>Examples</summary>

   The following query provides a distribution analysis on the time a specific process spent waiting for block IO activity. For this query to run, you must: Provide `compare` and `baseline` periods in the KPI page; Fill out a `pid_filter` variable in the `Template Variables` section of the `Debug page`, e.g., `(pid = 1302804 and machine_id = 1)`.

   ```sql
    SELECT ts, pid, tid, rq_share as share, 'baseline' as type
    FROM taskstats_view 
    WHERE {{ pid_filter }}
      AND {{ baseline_filter("ts") }}
      AND rq_share > 0.01
    UNION ALL
    SELECT ts, pid, tid, rq_share, 'compare' AS type
    FROM taskstats_view 
    WHERE {{ pid_filter }}
      AND {{ compare_filter("ts") }}
      AND rq_share > 0.01
   ```

   You may find other queries in tne `./analysis/src/sql` directory.

   </details>

# Papers

This tool is the result of research presented in the following papers:

**eBPF-Based Instrumentation for Generalisable Diagnosis of Performance Degradation:**

```
Landau, D., Barbosa, J., & Saurabh, N. (2025). eBPF-Based Instrumentation for Generalisable Diagnosis of Performance Degradation. arXiv preprint arXiv:2505.13160.

@article{landau2025ebpf,
  title={eBPF-Based Instrumentation for Generalisable Diagnosis of Performance Degradation},
  author={Landau, Diogo and Barbosa, Jorge and Saurabh, Nishant},
  journal={arXiv preprint arXiv:2505.13160},
  year={2025}
}
```

**Retrofitting Service Dependency Discovery in Distributed Systems:**

```
Landau, D., Blanken, G., Barbosa, J., & Saurabh, N. (2025). Retrofitting Service Dependency Discovery in Distributed Systems. arXiv preprint arXiv:2510.15490.

@article{landau2025retrofitting,
  title={Retrofitting Service Dependency Discovery in Distributed Systems},
  author={Landau, Diogo and Blanken, Gijs and Barbosa, Jorge and Saurabh, Nishant},
  journal={arXiv preprint arXiv:2510.15490},
  year={2025}
}
```
