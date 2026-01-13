import pandas as pd
import numpy as np
import os
import re
import matplotlib
import matplotlib.pyplot as plt
import v0_2_0

matplotlib.style.use("bmh")
font = {'size': 13}
matplotlib.rc('font', **font)

thread_ids = {}
COLLECT_TS = "2024-07-30T12:33:54.172726935+00:00"
TARGET_TS = "2024-07-30_14-36-23"
MYSQL_PID = "250468"
JBD2_PID = "718"
PATH = "figures/mysql"
FIGSIZE=(3.2, 3)
os.makedirs(PATH, exist_ok=True)

ycsb = pd.read_csv(f"../data/{COLLECT_TS}/application-metrics/ycsb_{TARGET_TS}.samples.csv")
tpcc = pd.read_csv(f"../data/{COLLECT_TS}/application-metrics/tpcc_{TARGET_TS}.samples.csv")

plt.figure(figsize=FIGSIZE)
plt.plot(tpcc["Time (seconds)"], tpcc["Throughput (requests/second)"])
plt.xlabel("Relative Time (s)")
plt.ylabel("Throughput (req/s)")
plt.tight_layout()
plt.savefig(f"{PATH}/target_throughput.pdf", bbox_inches='tight', pad_inches=0)

plt.figure(figsize=FIGSIZE)
plt.plot(ycsb["Time (seconds)"], ycsb["95th Percentile Latency (microseconds)"]/1_000)
plt.xlabel("Relative Time (s)")
plt.ylabel("Response Time (ms)")
plt.tight_layout()
plt.savefig(f"{PATH}/target_percentile.pdf", bbox_inches='tight', pad_inches=0)

plt.close("all")

COLOR_1, COLOR_2 = "tab:red", "tab:blue"

fig, ax1 = plt.subplots(figsize=FIGSIZE)
ax1.plot(tpcc["Time (seconds)"], tpcc["Throughput (requests/second)"], color=COLOR_1)
ax1.set_xlabel("Relative Time (s)")
ax1.set_ylabel("Throughput (req/s)", color=COLOR_1)
ax1.tick_params(axis='y', labelcolor=COLOR_1)

ax1.tick_params(axis='both')

ax2 = ax1.twinx()
ax2.plot(ycsb["Time (seconds)"], ycsb["95th Percentile Latency (microseconds)"]/1_000, color=COLOR_2)
ax2.set_ylabel("Response Time (ms)", color=COLOR_2)
ax2.tick_params(axis='y', labelcolor=COLOR_2)
ax2.tick_params(axis='both')

fig.tight_layout()

plt.savefig(f"{PATH}/target.pdf", bbox_inches='tight', pad_inches=0)

MIN_TIMESTAMP = 1722342863.056538
MAX_TIMESTAMP = ycsb["Time (seconds)"].max() + MIN_TIMESTAMP
MIN_TIMESTAMP, MAX_TIMESTAMP

XLIM = [0, 60]

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/global/iowait")
metric_files = pd.Series(metric_files)
metrics = v0_2_0.metric_files_to_df(metric_files)

devices = metrics.columns.str.replace(r".*/global_iowait/(\d+)/.*", r"\1", regex=True).unique()
devices = devices[~devices.str.contains("epoch_s")]
device_total = pd.DataFrame()
for device in devices:
    col_filter = col_filter = metrics.columns[metrics.columns.str.contains(f"/{device}/")]
    metrics_device = metrics.loc[:, col_filter]
    device_total[device] = metrics_device.sum(axis=1)

plt.figure(figsize=FIGSIZE)
plt.xlabel("Relative Time (s)")
plt.ylabel("Sectors")
mysql_threads = metrics.columns[metrics.columns.str.contains(MYSQL_PID)]
for col in mysql_threads:
    if col == "epoch_s":
        continue
    # plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col])

for idx, device in enumerate(devices):
    MAJOR, MINOR = int(device) >> 20, int(device) & ((1 << 20) - 1)
    plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, device_total[device], label=f"{MAJOR}:{MINOR}")# label=f"{MAJOR}:{MINOR}")
plt.legend(loc=(0.5, 0.545), prop={'size': 10})
plt.xlim([0, 120])
plt.ticklabel_format(axis='y', style='sci', scilimits=(0,0))
plt.tight_layout()
plt.savefig(f"{PATH}/io_device_total.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

plt.figure(figsize=FIGSIZE)
plt.xlabel("Relative Time (s)")
plt.ylabel("Share (%)")
pid_tids = metric_files.str.replace(r".*/iowait/(\d+)/(\d+)/.*", r"\1/\2", regex=True).unique()
pid_tids = ["250468/250783", "250468/250787", "250468/259654"]
for pid_tid in pid_tids:
    for device in ["264241153"]:
        col = f"global/{pid_tid}/global_iowait/{device}/sector_cnt"
        if not metrics.columns.str.contains(col).any():
            continue
        tid = re.search(r"global/\d+/(\d+)/", col).groups()[0]
        thread_id = thread_ids.get(tid)
        if not thread_id:
            thread_ids[tid] = f"t{len(thread_ids) + 1}"
            thread_id = thread_ids[tid]
        plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, (metrics[col]/device_total[device])*100, label=f"{thread_id}")
plt.legend(loc="upper center", prop={"size": 10}, ncol=3, handletextpad=0.1, handlelength=0.5, columnspacing=0.5)
plt.xlim([0, 120])
plt.ylim([0, 120])
plt.tight_layout()
plt.savefig(f"{PATH}/io_dev_264241153_threads.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

XLIM = [60, 120]

plt.figure(figsize=FIGSIZE)
plt.plot(ycsb["Time (seconds)"], ycsb["95th Percentile Latency (microseconds)"]/1_000)
plt.xlabel("Relative Time (s)")
plt.ylabel("Response Time (ms)")
plt.tight_layout()
plt.xlim(XLIM)
plt.savefig(f"{PATH}/database_latency.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

# Wait

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread/{MYSQL_PID}")
metric_files = pd.Series(filter(lambda s: 'futex/wait' in s, metric_files))
plt.figure(figsize=FIGSIZE)
plt.ylabel("Wait Time (s/s)")
plt.xlabel("Relative Time (s)")
for thread in ["251281", "259654"]:
    files = metric_files[metric_files.str.contains(f"{MYSQL_PID}/{thread}/")]
    futexes = files.str.replace(r".*/([\w-]+).csv$", r"\1", regex=True).unique()
    for futex in ["250468-0x76d594012f30"]:#, "250468-0x76d594012f34"]:
        futex_files = files[files.str.contains(f"/{futex}.csv")]
        metrics = v0_2_0.metric_files_to_df(futex_files, epoch_interval_s=(int(MIN_TIMESTAMP), int(MAX_TIMESTAMP)))
        futex_wait_filter = metrics.columns[metrics.columns.str.contains("futex_wait_rate")]
        thread_id = thread_ids.get(thread)
        if not thread_id:
            thread_ids[thread] = f"t{len(thread_ids) + 1}"
            thread_id = thread_ids[thread]
        for col in futex_wait_filter:
            plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col], label=f"{thread_id}")
plt.xlim(XLIM)
plt.ylim([-0.02, 1.1])
plt.legend(prop={"size": 10}, handletextpad=0.1, handlelength=0.5)
plt.tight_layout()
plt.savefig(f"{PATH}/database_lock_wait.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

# Wake

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread/{MYSQL_PID}")
metric_files = pd.Series(filter(lambda s: 'futex/wake' in s, metric_files))

plt.figure(figsize=FIGSIZE)
plt.ylabel("Wake Count")
plt.xlabel("Relative Time (s)")
threads = metric_files.str.replace(r".*/thread/\d+/(\d+)/.*", r"\1", regex=True).unique()
for thread in ["251281", "259654"]:
    if thread == "260296": 
        continue
    files = metric_files[metric_files.str.contains(f"{MYSQL_PID}/{thread}/")]
    futexes = files.str.replace(r".*/([\w-]+).csv$", r"\1", regex=True).unique()
    for futex in ["250468-0x76d594012f30"]:#, "250468-0x76d594012f34"]:
        futex_files = files[files.str.contains(f"/{futex}.csv")]
        metrics = v0_2_0.metric_files_to_df(futex_files, epoch_interval_s=(int(MIN_TIMESTAMP), int(MAX_TIMESTAMP)))
        futex_wait_filter = metrics.columns[metrics.columns.str.contains("futex_count")]
        thread_id = thread_ids.get(thread)
        if not thread_id:
            thread_ids[thread] = f"t{len(thread_ids) + 1}"
            thread_id = thread_ids[thread]
        for col in futex_wait_filter:
            plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col], label=f"{thread_id}")
plt.xlim(XLIM)
plt.legend(loc="upper left", prop={"size": 10}, handletextpad=0.1, handlelength=0.5)
plt.tight_layout()
plt.savefig(f"{PATH}/database_lock_wake.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

XLIM = [0, 120]

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread/{MYSQL_PID}")
metric_files = pd.Series(filter(lambda s: 'futex/wait' in s, metric_files))
plt.figure(figsize=FIGSIZE)
plt.ylabel("Wait Time (s/s)")
plt.xlabel("Relative Time (s)")
for thread in ["251281", "259654"]:
    files = metric_files[metric_files.str.contains(f"{MYSQL_PID}/{thread}/")]
    futexes = files.str.replace(r".*/([\w-]+).csv$", r"\1", regex=True).unique()
    for futex in ["250468-0x76d594012f30", "250468-0x76d594012f34"]:
        futex_files = files[files.str.contains(f"/{futex}.csv")]
        metrics = v0_2_0.metric_files_to_df(futex_files, epoch_interval_s=(int(MIN_TIMESTAMP), int(MAX_TIMESTAMP)))
        futex_wait_filter = metrics.columns[metrics.columns.str.contains("futex_wait_rate")]

        thread_id = thread_ids.get(thread)
        if not thread_id:
            thread_ids[thread] = f"t{len(thread_ids) + 1}"
            thread_id = thread_ids[thread]
        for col in futex_wait_filter:
            plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col], label=f"{thread_id}")
plt.xlim(XLIM)
plt.ylim([-0.02, 1.1])
plt.legend(prop={"size": 10}, handletextpad=0.1, handlelength=0.5)
plt.tight_layout()
plt.savefig(f"{PATH}/scenario_1_futex_wait.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

# Wake

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread/{MYSQL_PID}")
metric_files = pd.Series(filter(lambda s: 'futex/wake' in s, metric_files))

plt.figure(figsize=FIGSIZE)
plt.ylabel("Wake Count")
plt.xlabel("Relative Time (s)")
threads = metric_files.str.replace(r".*/thread/\d+/(\d+)/.*", r"\1", regex=True).unique()
for thread in ["251281", "259654"]:
    if thread == "260296": 
        continue
    files = metric_files[metric_files.str.contains(f"{MYSQL_PID}/{thread}/")]
    futexes = files.str.replace(r".*/([\w-]+).csv$", r"\1", regex=True).unique()
    for futex in ["250468-0x76d594012f30", "250468-0x76d594012f34"]:
        futex_files = files[files.str.contains(f"/{futex}.csv")]
        metrics = v0_2_0.metric_files_to_df(futex_files, epoch_interval_s=(int(MIN_TIMESTAMP), int(MAX_TIMESTAMP)))
        futex_wait_filter = metrics.columns[metrics.columns.str.contains("futex_count")]
        thread_id = thread_ids.get(thread)
        if not thread_id:
            thread_ids[thread] = f"t{len(thread_ids) + 1}"
            thread_id = thread_ids[thread]
        for col in futex_wait_filter:
            plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col], label=f"{thread_id}")
plt.xlim(XLIM)
plt.legend(loc="upper left", prop={"size": 10}, handletextpad=0.1, handlelength=0.5)
plt.tight_layout()
plt.savefig(f"{PATH}/scenario_1_futex_wake.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

XLIM = [60, 120]

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread")
metric_files = pd.Series(filter(lambda s: 'sched/' in s, metric_files))

XLIM = [60, 120]

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/global/iowait")
metric_files = pd.Series(metric_files)
metrics = v0_2_0.metric_files_to_df(metric_files)

devices = metrics.columns.str.replace(r".*/global_iowait/(\d+)/.*", r"\1", regex=True).unique()
devices = devices[~devices.str.contains("epoch_s")]
device_total = pd.DataFrame()
for device in devices:
    col_filter = col_filter = metrics.columns[metrics.columns.str.contains(f"/{device}/")]
    metrics_device = metrics.loc[:, col_filter]
    device_total[device] = metrics_device.sum(axis=1)

XLIM = [0, 120]

# Wait Time

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread/{MYSQL_PID}")
metric_files = pd.Series(filter(lambda s: 'futex/wait' in s, metric_files))
samples = pd.DataFrame({}, columns=["epoch_s", "value"])
plt.figure(figsize=FIGSIZE)
plt.xlabel("Relative Time (s)")
plt.ylabel("Wait Time (s/s)")
for thread in ["250787"]:
    files = metric_files[metric_files.str.contains(f"{MYSQL_PID}/{thread}/")]
    futexes = files.str.replace(r".*/([\w-]+).csv$", r"\1", regex=True).unique()
    for futex in ["250468-0x76d5fc83c994", "250468-0x76d5fc83c990"]:
        futex_files = files[files.str.contains(f"/{futex}.csv")]
        metrics = v0_2_0.metric_files_to_df(futex_files, epoch_interval_s=(int(MIN_TIMESTAMP), int(MAX_TIMESTAMP)))
        futex_wait_filter = metrics.columns[metrics.columns.str.contains("futex_wait_rate")]
        for col in futex_wait_filter:
            plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col], label=f"{thread}")

            sub = metrics.loc[:, ["epoch_s", col]]
            sub.columns = ["epoch_s", "value"]
            sub["epoch_s"] = sub["epoch_s"] - MIN_TIMESTAMP
            samples = pd.concat([sub, samples])
plt.xlim(XLIM)
plt.ylim([0, 1.1])
# plt.legend()
plt.tight_layout()
plt.savefig(f"{PATH}/scenario_2_futex_wait.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

samples.loc[
    ((samples["epoch_s"] > 0) & (samples["epoch_s"] < 25)) | ((samples["epoch_s"] > 55) & (samples["epoch_s"] < 80)),
    "group"
] = "baseline"

samples.loc[
    ((samples["epoch_s"] > 25) & (samples["epoch_s"] < 55)) | ((samples["epoch_s"] > 80) & (samples["epoch_s"] < 115)),
    "group"
] = "compare"

plt.figure(figsize=FIGSIZE)
plt.ylabel("Relative Frequency")
plt.xlabel("Wait Time (s/s)")
for group in ["baseline", "compare"]:
    filtered = samples.loc[samples["group"] == group, "value"]
    counts, bins = np.histogram(
        filtered,
        bins=20,
        range=(0, 0.4)
    )

    pmf = counts / counts.sum()

    plt.bar(
        bins[:-1],
        pmf,
        width=np.diff(bins),
        align="edge",
        alpha=0.4,
        label=group
    )
plt.tight_layout()
# plt.xlim([0, 25])
# plt.ylim([0, 1])
plt.legend()
plt.savefig(f"{PATH}/scenario_2_futex_wait_hist.pdf")

# Wait Count


# Sched

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread/{MYSQL_PID}")
metric_files = pd.Series(filter(lambda s: 'sched/' in s, metric_files))

for thread in ["250787"]:
    plt.figure(figsize=FIGSIZE)
    plt.ylabel("Time in IOWait (s/s)")
    plt.xlabel("Relative Time (s)")
    files = metric_files[metric_files.str.contains(f"{MYSQL_PID}/{thread}")]
    metrics = v0_2_0.metric_files_to_df(files, epoch_interval_s=(int(MIN_TIMESTAMP), int(MAX_TIMESTAMP)))
    rate_filter = metrics.columns[metrics.columns.str.contains("iowait_time_rate")].append(pd.Index(["epoch_s"]))
    metrics = metrics.loc[:, rate_filter]
    for col in metrics.columns:
        if col == "epoch_s": 
            continue
        plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col])
    plt.xlim(0, MAX_TIMESTAMP - MIN_TIMESTAMP)
    plt.ylim([0, 1.1])
    plt.tight_layout()
    plt.savefig(f"{PATH}/scenario_2_io_wait.pdf", bbox_inches='tight', pad_inches=0)
    # plt.show()

# Wake

metric_files = v0_2_0.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/thread/{MYSQL_PID}")
metric_files = pd.Series(filter(lambda s: 'futex/wake' in s, metric_files))

plt.figure(figsize=FIGSIZE)
plt.xlabel("Relative Time (s)")
plt.ylabel("Wake Count")
threads = metric_files.str.replace(r".*/thread/\d+/(\d+)/.*", r"\1", regex=True).unique()
for thread in threads:
    if thread not in ["259654", "260296", "250789"]:
        continue
    files = metric_files[metric_files.str.contains(f"{MYSQL_PID}/{thread}/")]
    futexes = files.str.replace(r".*/([\w-]+).csv$", r"\1", regex=True).unique()
    for futex in ["250468-0x76d5fc83c994", "250468-0x76d5fc83c990"]:
        futex_files = files[files.str.contains(f"/{futex}.csv")]
        metrics = v0_2_0.metric_files_to_df(futex_files, epoch_interval_s=(int(MIN_TIMESTAMP), int(MAX_TIMESTAMP)))
        futex_wait_filter = metrics.columns[metrics.columns.str.contains("futex_count")]
        thread_id = thread_ids.get(thread)
        if not thread_id:
            thread_ids[thread] = f"t{len(thread_ids) + 1}"
            thread_id = thread_ids[thread]
        for col in futex_wait_filter:
            plt.plot(metrics["epoch_s"] - MIN_TIMESTAMP, metrics[col], label=f"{thread_id}")
plt.xlim(XLIM)
plt.legend(loc="upper center", prop={"size": 10}, ncol=3, handletextpad=0.1, handlelength=0.5, columnspacing=0.5)
plt.tight_layout()
plt.savefig(f"{PATH}/scenario_2_futex_wake.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()
print(thread_ids)
