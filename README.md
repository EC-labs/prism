# Prism

Prism is a Linux performance diagnostic tool for analysing thread dynamics in distributed systems. It uses lightweight eBPF-based metrics across scheduling, futexes, I/O, networking, and storage, to enable fine-grained analysis of application performance at the level of individual threads, their interactions with each other, and with system resources.

# Quickstart

This section illustrates how to start Prism on a single instance. For a distributed setup, refer to [deploy/prism-chart](deploy/prism-chart) to deploy with helm on a kubernetes cluster.

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
   <details><summary>Example</summary>

   We have provided an example database you can import [data/oboutique-k8s.db3](data/oboutique-k8s.db3).

   </details>
1. Visit the `Ripple` page
1. Select a process you want to create a service dependency graph for
   <details><summary>Example</summary>

   For the example dataset ([data/oboutique-k8s.db3](data/oboutique-k8s.db3)), selecting the process with `(machine_id : pid)` -> `(3 : 853159)` shows the service dependency graph for online boutique, including the system processes that also interact with the online boutique services for operations such as healthchecks:

   <img width="729" height="760" alt="Screenshot From 2026-04-17 10-43-24" src="https://github.com/user-attachments/assets/7fae3116-fad8-4b92-b771-6fa615796c2f" />

   </details>
   
1. Navigate to the Thread Dynamics page
1. Select a process that is part of the dependency graph
   <details><summary>Example</summary>

   Selecting the `recommendationservice-5767cf4d97-wjq4q (2:100162)` from the example online-boutique dataset generates the following thread dynamics graph:

   <img width="1519" height="762" alt="Screenshot From 2026-04-17 10-51-15" src="https://github.com/user-attachments/assets/9c2cadf0-1d6a-44ed-acce-ac27e89233c6" />
   
   </details>
1. Interact with the thread dynamics graph to visualise statistics on the selected resouces
   <details><summary>Example</summary>

   The following screenshots are, respectively, for a contention and a thread resource for the `recommendationservice-5767cf4d97-wjq4q (2:100162)` from the example online-boutique dataset:

   <img width="1519" height="762" alt="Screenshot From 2026-04-17 10-51-26" src="https://github.com/user-attachments/assets/5045e159-34de-4f6a-8f4a-05731dcbe5c3" />
   <img width="1519" height="762" alt="Screenshot From 2026-04-17 10-53-08" src="https://github.com/user-attachments/assets/075f7c6f-a4a2-4703-b784-6c744662c94e" />

   </details>
1. Run custom queries in the `Debug` page
   <details><summary>Example</summary>

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

**Beyond Thread States: Diagnosing Performance Degradation with eBPF and Thread Dynamics:**

```
D. Landau, J. G. Barbosa and N. Saurabh, "Beyond Thread States: Diagnosing Performance Degradation with eBPF and Thread Dynamics," in 2026 IEEE International Parallel and Distributed Processing Symposium (IPDPS), New Orleans, LA, USA, 2026, pp. 819-834, doi: 10.1109/IPDPS65963.2026.00073.

@INPROCEEDINGS {11575369,
author = { Landau, Diogo and Barbosa, Jorge G. and Saurabh, Nishant },
booktitle = { 2026 IEEE International Parallel and Distributed Processing Symposium (IPDPS) },
title = {{ Beyond Thread States: Diagnosing Performance Degradation with eBPF and Thread Dynamics }},
year = {2026},
volume = {},
ISSN = {},
pages = {819-834},
abstract = { Online Data-Intensive applications face performance degradation from load variability and resource interference. While Thread State Analysis (TSA) based approaches enable identifying constrained subsystems, they lack the granularity to reveal the inter-thread dependencies that propagate degradation. In this paper, we present an application-agnostic performance degradation analysis method that extends TSA by capturing fine-grained thread dynamics. We implemented 16 eBPF-based metrics across six kernel subsystems, including scheduling, VFS, networking, futex, multiplexing IO, and block IO which enables tracing thread interactions with specific resources like futexes, sockets, and disks. Our method leverages the fact that performance degradation propagates along inter-thread dependencies, and a subset of thread-resource interactions can enable capturing common degradation patterns. To this end, we employ a selective thread tracking algorithm that traces performance issues from entry-point threads to constrained resources. Experimentation with diverse applications under variable workloads and resource contention shows our method successfully diagnoses CPU, disk, lock, and external service contention with minimal overhead, while also revealing internal application constraints. },
keywords = {Degradation;Measurement;Timing;Kernel;Printing;Conferences;Dynamics;Sockets;Central Processing Unit;Manuals},
doi = {10.1109/IPDPS65963.2026.00073},
url = {https://doi.ieeecomputersociety.org/10.1109/IPDPS65963.2026.00073},
publisher = {IEEE Computer Society},
address = {Los Alamitos, CA, USA},
month =May}
```

```
Landau, D., Barbosa, J., & Saurabh, N. (2026). Beyond Thread States: Diagnosing Performance Degradation with eBPF and Thread Dynamics. arXiv preprint arXiv:2605.25298.

@misc{landau2026threadstatesdiagnosingperformance,
      title={Beyond Thread States: Diagnosing Performance Degradation with eBPF and Thread Dynamics}, 
      author={Diogo Landau and Jorge G. Barbosa and Nishant Saurabh},
      year={2026},
      eprint={2605.25298},
      archivePrefix={arXiv},
      primaryClass={cs.DC},
      url={https://arxiv.org/abs/2605.25298}, 
}
```

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
