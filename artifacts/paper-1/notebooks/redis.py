import pandas as pd
import numpy as np
import os
import re
import matplotlib
import matplotlib.pyplot as plt

import transform


matplotlib.style.use("bmh")
font = {'size': 13}
matplotlib.rc('font', **font)


COLLECT_TS = "2024-05-19T13:08:15.671530744+00:00"
PATH = "figures/redis"
FIGSIZE=(3.2, 3)
LIMITS = (50, 120)
XLIM = [55, 130]
os.makedirs(PATH, exist_ok=True)

percentiles = pd.read_csv(f"../data/{COLLECT_TS}/application-metrics/memtier_percentiles_95.csv")
metric_files = transform.recursive_dfs(f"../data/{COLLECT_TS}/system-metrics/redis-server")
metric_files = list(filter(lambda s: 'sched/' in s, metric_files))
metrics = transform.metric_files_to_df(metric_files)
metrics = pd.merge(metrics, percentiles, on="epoch_s", how="outer")


col_filter = metrics.filter(
    regex="("
              "_rate|"
              "response_time_us|"
              "epoch_s"
          ")"
).columns

col_filter = col_filter[~col_filter.str.contains("sleep_time_rate", regex=False)]
related = metrics.loc[LIMITS[0]:LIMITS[1], col_filter]
corr = related.corr(method="spearman")["response_time_us"].sort_values(ascending=False, key=abs)


bar = corr[(corr.isna() == False) & (~corr.index.str.contains("response_time_us|epoch_s", regex=True))]

metrics_view = related.loc[related["epoch_s"].isna() == False, bar.index.union(["epoch_s", "response_time_us"])]
metrics_view = metrics_view.sort_values(by="epoch_s")
metrics_view = metrics_view.loc[LIMITS[0]:LIMITS[1], :]
metrics_view["relative_epoch_s"] = metrics_view["epoch_s"] - metrics["epoch_s"].min()
metrics_view = metrics_view.loc[:, :]
Y = metrics_view.loc[:, ~metrics_view.columns.isin(["epoch_s", "relative_epoch_s", "response_time_us"])]


colours = ['#4477AA', '#EE6677', '#228833', '#CCBB44', '#66CCEE', '#AA3377', '#BBBBBB']

bar.index = [re.sub(r"thread/redis-server/(\d+)/sched/(.*)_rate$", r"\1/\2", col) for col in bar.index]
Y.columns = [re.sub(r"thread/redis-server/(\d+)/sched/(.*)_rate$", r"\1/\2", col) for col in Y.columns]
Y = Y.loc[:, bar.index]
x1, x2, y1, y2 = 81, 93, 0.45, 0.55
plt.figure(figsize=FIGSIZE)
axins = plt.gca().inset_axes(
    [0.05, 0.15, 0.30, 0.30],
    xlim=(x1, x2), ylim=(y1, y2), xticklabels=[], yticklabels=[]
)
plt.gca().indicate_inset_zoom(axins, edgecolor="black")
thread_ids = {}
for y, colour in zip(Y.columns, colours):
    if "block_time" in y or "24999" in y:
        continue
    label = re.search(r"(\d+/[a-z]+)_?time", y).groups()[0]
    tid, metric = re.search(r"(\d+)/(.*)", label).groups()
    thread_id = thread_ids.get(tid)
    if not thread_id: 
        thread_ids[tid] = f"t{len(thread_ids) + 1}"
        thread_id = thread_ids[tid]
    plt.plot(metrics_view["relative_epoch_s"], Y[y], color=colour, label=f"{thread_id}/{metric}")
    axins.plot(metrics_view["relative_epoch_s"], Y[y], color=colour)
plt.xlabel("Relative Time (s)")
plt.ylabel("Share (s/s)")
plt.xlim(XLIM)
plt.legend(loc=(0.55, 0.1), prop={"size": 10}, handletextpad=0.1, columnspacing=0.5, handlelength=0.4)
plt.tight_layout()
plt.savefig(f"{PATH}/sched_stats.pdf", bbox_inches='tight', pad_inches=0)

plt.figure(figsize=FIGSIZE)
plt.plot(metrics_view["epoch_s"] - metrics["epoch_s"].min(), metrics_view["response_time_us"])
plt.ticklabel_format(axis='y', style='sci', scilimits=(4,4))
plt.xlabel("Relative Time (s)")
plt.ylabel("Response Time ($\mu$s)")
plt.xlim(XLIM)
plt.tight_layout()
plt.savefig(f"{PATH}/response_time.pdf", bbox_inches='tight', pad_inches=0)


print(thread_ids)
plt.show()
