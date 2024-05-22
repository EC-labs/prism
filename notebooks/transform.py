from __future__ import annotations
import os
import pandas as pd
import re
import csv

from enum import Enum
from typing import List, Optional


class MetricClass(Enum): 
    TARGET_SCHEDSTAT = 'schedstat'
    TARGET_SCHED = 'sched'
    TARGET_FUTEX = 'futex'
    TARGET_IPC = 'ipc'
    GLOBAL_IOWAIT = 'global_iowait'
    GLOBAL_FUTEX = 'global_futex'
    GLOBAL_EPOLL = 'global_epoll'

    def __str__(self): 
        return self.value


def recursive_dfs(path: str) -> list[str]: 
    """Lists all files contained within `path`."""

    if not os.path.isdir(path): 
        return [path]
    
    files = []
    for dentry in os.listdir(path):
        files.extend(recursive_dfs(f"{path}/{dentry}"))
    return files

def transform_metrics(metrics: pd.DataFrame, file_path: str): 
    """Create new DataFrame with based on `metrics`."""


    m = re.search(r'system-metrics/(.+?)/', file_path)
    if m == None: 
        return
    child_dir  = m.groups()[0]

    if child_dir in ["iowait", "futex", "epoll"]:
        metric_class = MetricClass(f"global_{child_dir}")
    else: 
        m = re.search(r'system-metrics/.+?/\d+/(\w+)/', file_path)
        if m == None: 
            return
        child_dir  = m.groups()[0]
        metric_class = MetricClass(child_dir)

    prefix = ""
    if metric_class == MetricClass.TARGET_SCHEDSTAT: 
        metrics["epoch_s"] = (metrics["epoch_ms"]//1e3).astype("Int64")
        time_delta = metrics["epoch_ms"].diff()
        metrics["runtime_rate"] = metrics["runtime"].diff() / time_delta
        metrics["rq_rate"] = metrics["rq_time"].diff() / time_delta

        m = re.search(r'\d/(.*)/(\d+)/(\w+)/(\d+\.csv$)', file_path)
        if m == None: 
            return
        comm, thread, _, _ = m.groups()
        prefix = f"{comm}/{thread}/{metric_class}"
    elif metric_class == MetricClass.TARGET_SCHED: 
        metrics["epoch_s"] = (metrics["epoch_ms"]//1e3).astype("Int64")
        time_delta = metrics["epoch_ms"].diff()
        metrics["runtime_rate"] = metrics["runtime"].diff() / time_delta
        metrics["rq_rate"] = metrics["rq_time"].diff() / time_delta
        metrics["iowait_rate"] = metrics["iowait_time"].diff() / time_delta
        metrics["block_rate"] = metrics["block_time"].diff() / time_delta
        metrics["sleep_rate"] = metrics["sleep_time"].diff() / time_delta
        metrics["runnable"] = metrics["runtime_rate"] + metrics["rq_rate"]
        metrics["active_rate"] = metrics["block_rate"] + metrics["runtime_rate"] + metrics["rq_rate"]

        m = re.search(r'\d/(.*)/(\d+)/(\w+)/(\d+\.csv$)', file_path)
        if m == None: 
            return
        comm, thread, _, _ = m.groups()
        prefix = f"{comm}/{thread}/{metric_class}"
    elif metric_class == MetricClass.TARGET_FUTEX: 
        metrics["epoch_s"] = (metrics["epoch_ms"]//1e3).astype("Int64")
        time_delta = metrics["epoch_ms"].diff()
        metrics["futex_wait"] = metrics["futex_wait"] / 1_000_000
        metrics["futex_wait_rate"] = metrics["futex_wait"].diff() / time_delta

        m = re.search(r'\d/(.*)/(\d+)/(\w+)/(\d+\.csv$)', file_path)
        if m == None: 
            return
        comm, thread, _, _ = m.groups()
        prefix = f"{comm}/{thread}/{metric_class}"
    elif metric_class == MetricClass.TARGET_IPC:
        metrics["epoch_s"] = (metrics["epoch_ms"]//1e3).astype("Int64")
        time_delta = metrics["epoch_ms"].diff()

        m = re.search(r'system-metrics/(.*)/(\d+)/(\w+)/(\w+)/(\d+)/(.*).csv$', file_path)
        if m == None: 
            return
        comm, thread, _, ipc_type, minute, stem = m.groups()
        prefix = f"{comm}/{thread}/{metric_class}/{ipc_type}/{minute}/{stem}"

        if ipc_type == "streams":
            metrics["stream_wait"] = metrics["stream_wait"]/1_000_000
            metrics["stream_wait_rate"] = metrics["stream_wait"].diff() / time_delta
        elif ipc_type == "sockets": 
            metrics["socket_wait"] = metrics["socket_wait"]/1_000_000
            metrics["socket_wait_rate"] = metrics["socket_wait"].diff() / time_delta

    elif metric_class == MetricClass.GLOBAL_IOWAIT:
        m = re.search(r'system-metrics/iowait/(.*?)/(\d+)/(\d+)/(\d+).csv$', file_path)
        if m == None: 
            return
        comm, thread, minute, device = m.groups()
        prefix = f"{comm}/{thread}/{metric_class}/{device}/{minute}"

    else: 
        raise NotImplemented()
    
    metrics.columns = [
        f"{prefix}/{col}" if col != "epoch_s" else col
        for col in metrics.columns
    ]

    metrics.dropna(inplace=True)

def apply_naming_convention(metric_df: pd.DataFrame, file_path: str):
    m = re.search(r'system-metrics/(.+?)/', file_path)
    if m == None: 
        return

    child_dir  = m.groups()[0]
    if child_dir in ["iowait", "futex", "epoll"]:
        metric_class = MetricClass(f"global_{child_dir}")
    else: 
        m = re.search(r'system-metrics/.+?/\d+/(\w+)/', file_path)
        if m == None: 
            return
        child_dir  = m.groups()[0]
        metric_class = MetricClass(child_dir)

    prefix = ""
    if metric_class == MetricClass.TARGET_SCHEDSTAT: 
        m = re.search(r'system-metrics/(.+?)/(\d+)/(\w+)/(\d+)\.csv$', file_path)
        if m == None: 
            return
        comm, thread, _, day = m.groups()
        prefix = f"thread/{comm}/{thread}/{metric_class}" 

    elif metric_class == MetricClass.TARGET_SCHED: 
        m = re.search(r'system-metrics/(.+?)/(\d+)/(\w+)/(\d+)\.csv$', file_path)
        if m == None: 
            return
        comm, thread, _, day = m.groups()
        prefix = f"thread/{comm}/{thread}/{metric_class}"

    elif metric_class == MetricClass.TARGET_FUTEX: 
        m = re.search(r'system-metrics/(.+?)/(\d+)/(\w+)/(\d+)\.csv$', file_path)
        if m == None: 
            return
        comm, thread, _, day = m.groups()
        prefix = f"thread/{comm}/{thread}/{metric_class}"

    elif metric_class == MetricClass.TARGET_IPC:
        m = re.search(r'system-metrics/(.+?)/(\d+)/(\w+)/(\w+)/(\d+)/(.*).csv$', file_path)
        if m == None: 
            return
        comm, thread, _, ipc_type, minute, stem = m.groups()
        prefix = f"thread/{comm}/{thread}/{metric_class}/{ipc_type}/{stem}"

    elif metric_class == MetricClass.GLOBAL_IOWAIT:
        m = re.search(r'system-metrics/iowait/(.+?)/(\d+)/(\d+)/(\d+).csv$', file_path)
        if m == None: 
            return
        comm, thread, minute, device = m.groups()
        prefix = f"global/{comm}/{thread}/{metric_class}/{device}"

    elif metric_class == MetricClass.GLOBAL_EPOLL:
        m = re.search(r'system-metrics/epoll/(.+?)/(\w+)/(\d+)/(.+).csv$', file_path)
        if m == None: 
            return
        addr, ipc_type, minute, stem = m.groups()
        prefix = f"global/epoll/{addr}/{ipc_type}/{stem}"

    else: 
        raise NotImplemented()
    
    metric_df.columns = [
        f"{prefix}/{col}" if col != "epoch_s" else col
        for col in metric_df.columns
    ]

def load_metric(file_path: str) -> pd.DataFrame: 
    df = pd.read_csv(file_path)
    if "epoch_s" not in df: 
        df["epoch_s"] = (df["epoch_ms"] // 1e3).astype("Int64")
    return df

def merge_partitioned_data(metrics: List[pd.DataFrame]) -> pd.DataFrame:
    map_prefix_timeseries = {}
    for metric in metrics:
        for col in metric.columns: 
            if col == "epoch_s": 
                continue

            metric_timeseries = metric.loc[:, ["epoch_s", col]]
            timeseries = map_prefix_timeseries.get(col)
            if timeseries is None: 
                map_prefix_timeseries[col] = metric_timeseries
            else: 
                map_prefix_timeseries[col] = pd.concat([timeseries, metric_timeseries])
    
    joined_metrics = pd.DataFrame({"epoch_s": []})
    for timeseries in map_prefix_timeseries.values(): 
        joined_metrics = pd.merge(
            joined_metrics, 
            timeseries.loc[timeseries["epoch_s"].duplicated() == False, :], 
            on="epoch_s", 
            how="outer"
        )

    return joined_metrics


def compute_derived_metrics(metrics: pd.DataFrame) -> pd.DataFrame: 
    new_cols = {}
    for col in metrics: 
        m = re.search(r'^(thread/.*)/(socket_wait|stream_wait)$', col)
        if m != None: 
            ipc_prefix, ipc_metric = m.groups()

            metrics[col].fillna(method="pad", inplace=True)
            epoch_ms_col = f"{ipc_prefix}/epoch_ms"
            metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                epoch_ms_col
            ] = metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                "epoch_s"
            ] * 1e3
            epoch_ms = metrics[epoch_ms_col]
            derived = f"{ipc_prefix}/{ipc_metric}_rate"
            new_cols[derived] = ((metrics[col] / 1e6).diff() / epoch_ms.diff())

        m = re.search(r'^(thread/.*)/(runtime|rq_time|sleep_time|block_time|iowait_time)$', col)
        if m != None: 
            ipc_prefix, ipc_metric = m.groups()

            epoch_ms_col = f"{ipc_prefix}/epoch_ms"
            epoch_ms_series = metrics[epoch_ms_col]

            derived_col = f"{ipc_prefix}/{ipc_metric}_rate"
            derived_series = metrics[col].interpolate().diff() / epoch_ms_series.interpolate().diff()
            new_cols[derived_col] = derived_series


    new_cols = pd.DataFrame(new_cols)
    return pd.concat([metrics, new_cols], axis=1)


def metric_files_to_df(files: list[str]) -> pd.DataFrame:
    """Reads all `files` and adds them to a single DataFrame."""

    metrics = []

    for file in files: 
        metric = load_metric(file)
        apply_naming_convention(metric, file)
        metrics.append(metric)

    metrics = merge_partitioned_data(metrics)
    metrics = metrics.sort_values(by="epoch_s")
    metrics = compute_derived_metrics(metrics)
    return metrics
    

    iowait_map = {}
    for col in metrics.columns:
        m = re.search(r'^(.*)/(\d+)/global_iowait/(\d+)/.*$', col)
        if m == None: 
            continue
        comm, thread, device = m.groups()

        new_col = f"{comm}/{thread}/global_iowait/{device}/sector_cnt"
        if iowait_map.get(new_col) is None:
            iowait_map[new_col] = pd.DataFrame({new_col: [], "epoch_s": []})
        cumulative = iowait_map[new_col]
        df = metrics.loc[metrics[col].isna() == False, [col, "epoch_s"]].rename(columns={col: new_col})
        iowait_map[new_col] = pd.concat(
            [cumulative, df]
        )
        metrics = metrics.drop([col], axis=1)

    for col, df in iowait_map.items():
        metrics = pd.merge(metrics, df, on="epoch_s", how="outer")


    total = None
    for col in metrics.columns: 
        if "global_iowait" in col:
            metrics[col] = metrics[col].fillna(0)
            total = total + metrics[col] if total is not None else 0 + metrics[col]
    

    for col in metrics.columns: 
        if "global_iowait" in col:
            metrics[f"{col}_pct"] = metrics[col] / total

    

    return metrics

def load_response_times(file: str) -> pd.DataFrame: 
    response_time = pd.read_csv(file)
    response_time["end_epoch_s"] = (
        pd.to_datetime(response_time["end_ts"]).astype("int64")//1e9
    ).astype("Int64")
    response_time["duration_s"] = response_time["duration_ms"]/1e3
    response_time["start_epoch_s"] = (response_time["end_epoch_s"] - response_time["duration_s"]).astype("Int64")
    return response_time

def response_time_percentiles(
    response_times: pd.DataFrame, 
    quantile: float = 0.9, 
    violation_threshold: Optional[float] = None
) -> pd.DataFrame: 
    """Convert response time samples to per second percentiles."""
    response_sorted_start = response_times.loc[
        :, ["start_epoch_s", "end_epoch_s", "duration_s"]
    ].sort_values(by="start_epoch_s")
    response_sorted_end = response_times.loc[
        :, ["start_epoch_s", "end_epoch_s", "duration_s"]
    ].sort_values(by="end_epoch_s")

    temp = []

    start_time, end_time = (response_sorted_start["start_epoch_s"].min(), response_sorted_end["end_epoch_s"].max())

    for curr in range(start_time, end_time+1):
        started_before = response_sorted_start.loc[
            response_sorted_start["start_epoch_s"] <= curr, :
        ]
        ended_after = response_sorted_end.loc[
            response_sorted_end["end_epoch_s"] >= curr, :
        ]
        intersection = pd.merge(
            started_before, 
            ended_after, 
            how="inner", 
            on=["start_epoch_s", "end_epoch_s", "duration_s"],
        )
        temp.append((
            curr, 
            intersection["duration_s"].quantile(q=quantile),
        ))
    percentiles = pd.DataFrame(temp, columns=["epoch_s", "percentile_value"])
    if violation_threshold == None: 
        return percentiles
    percentiles['slo_violation'] = (percentiles["percentile_value"] > violation_threshold).astype("float64")
    return percentiles


def response_time_percentiles_redis(
    response_times: pd.DataFrame, 
    quantile: float = 0.9, 
    time_factor: int = 1,
    violation_threshold: Optional[float] = None
) -> pd.DataFrame: 
    """Convert response time samples to per second percentiles."""
    response_sorted_start = response_times.loc[
        :, ["start", "end", "duration"]
    ].sort_values(by="start")
    response_sorted_end = response_times.loc[
        :, ["start", "end", "duration"]
    ].sort_values(by="end")

    temp = []

    start_time, end_time = response_sorted_start["start"].min(), response_sorted_end["end"].max()

    for curr in range(start_time, end_time+time_factor, time_factor):
        started_before = response_sorted_start.loc[
            response_sorted_start["start"] <= curr, :
        ]
        ended_after = response_sorted_end.loc[
            response_sorted_end["end"] > curr-time_factor, :
        ]
        intersection = pd.merge(
            started_before, 
            ended_after, 
            how="inner", 
            on=["start", "end", "duration"],
        )
        temp.append((
            curr, 
            intersection["duration"].quantile(q=quantile),
        ))
    percentiles = pd.DataFrame(temp, columns=["epoch_s", "percentile_value"])
    if violation_threshold == None: 
        return percentiles
    percentiles['slo_violation'] = (percentiles["percentile_value"] > violation_threshold).astype("float64")
    return percentiles
