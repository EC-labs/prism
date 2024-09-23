from __future__ import annotations
import os
import pandas as pd
import re
import csv

from enum import Enum
from typing import List, Optional, Tuple


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

def apply_naming_convention(metric_df: pd.DataFrame, file_path: str):
    m = re.search(r'system-metrics/(.+?)/', file_path)
    if m == None: 
        return

    scope = m.groups()[0]
    if scope == "global":
        m = re.search(r'system-metrics/global/(\w+)/', file_path)
        if m == None: 
            return
        metric_type  = m.groups()[0]
        metric_class = MetricClass(f"global_{metric_type}")
    else: 
        m = re.search(r'system-metrics/thread/\d+/\d+/(\w+)/', file_path)
        if m == None: 
            return
        metric_type  = m.groups()[0]
        metric_class = MetricClass(metric_type)

    prefix = ""
    if metric_class == MetricClass.TARGET_SCHEDSTAT: 
        m = re.search(r'system-metrics/thread/(\d+)/(\d+)/schedstat/(\d+)\.csv$', file_path)
        if m == None: 
            raise UnexpectedFilePath(file_path)
        pid, thread, day = m.groups()
        prefix = f"thread/{pid}/{thread}/{metric_class}" 

    elif metric_class == MetricClass.TARGET_SCHED: 
        m = re.search(r'system-metrics/thread/(\d+)/(\d+)/sched/(\d+)\.csv$', file_path)
        if m == None: 
            raise UnexpectedFilePath(file_path)
        pid, thread, day = m.groups()
        prefix = f"thread/{pid}/{thread}/{metric_class}"

    elif metric_class == MetricClass.TARGET_FUTEX: 
        m = re.search(r'system-metrics/thread/(\d+)/(\d+)/futex/(\w+)/(\d+)/([\w-]+)\.csv$', file_path)
        if m == None: 
            raise UnexpectedFilePath(file_path)
        pid, thread, futex_type, minute, address = m.groups()
        prefix = f"thread/{pid}/{thread}/{metric_class}/{futex_type}/{address}"

    elif metric_class == MetricClass.TARGET_IPC:
        m = re.search(r'system-metrics/thread/(\d+)/(\d+)/ipc/(\w+)/(\d+)/(.*)\.csv$', file_path)
        if m == None: 
            raise UnexpectedFilePath(file_path)
        pid, thread, ipc_type, minute, stem = m.groups()
        prefix = f"thread/{pid}/{thread}/{metric_class}/{ipc_type}/{stem}"

    elif metric_class == MetricClass.GLOBAL_IOWAIT:
        m = re.search(r'system-metrics/global/iowait/(\d+)/(\d+)/(\d+)/(\d+).csv$', file_path)
        if m == None: 
            raise UnexpectedFilePath(file_path)
        pid, thread, minute, device = m.groups()
        prefix = f"global/{pid}/{thread}/{metric_class}/{device}"

    elif metric_class == MetricClass.GLOBAL_EPOLL:
        m = re.search(r'system-metrics/global/epoll/(.+?)/(\w+)/(\d+)/(.+).csv$', file_path)
        if m == None: 
            raise UnexpectedFilePath(file_path)
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


def compute_derived_metrics(metrics: pd.DataFrame, start_epoch_s: Optional[int] = None, end_epoch_s: Optional[int] = None) -> pd.DataFrame: 
    new_cols = {}
    for col in metrics: 
        m = re.search(r'^(thread/.*)/(socket_wait|stream_wait)$', col)
        if m != None: 
            prefix, metric = m.groups()

            metrics[col].fillna(method="pad", inplace=True)
            epoch_ms_col = f"{prefix}/epoch_ms"
            metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                epoch_ms_col
            ] = metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                "epoch_s"
            ] * 1e3
            epoch_ms = metrics[epoch_ms_col]
            derived = f"{prefix}/{metric}_rate"
            new_cols[derived] = ((metrics[col] / 1e6).diff() / epoch_ms.diff())
            new_cols[derived].fillna(0, inplace=True)

        m = re.search(r'^(thread/.*)/(runtime|rq_time|sleep_time|block_time|iowait_time)$', col)
        if m != None: 
            prefix, metric = m.groups()

            epoch_ms_col = f"{prefix}/epoch_ms"
            epoch_ms_series = metrics[epoch_ms_col]

            derived_col = f"{prefix}/{metric}_rate"
            derived_series = metrics[col].interpolate().diff() / epoch_ms_series.interpolate().diff()
            new_cols[derived_col] = derived_series
            new_cols[derived_col].fillna(0, inplace=True)

        m = re.search(r'^(global/.*)/(socket_wait|stream_wait)$', col)
        if m != None: 
            prefix, metric = m.groups()

            metrics[col].fillna(method="pad", inplace=True)
            metrics[col].fillna(0, inplace=True)

            epoch_ms_col = f"{prefix}/epoch_ms"
            metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                epoch_ms_col
            ] = metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                "epoch_s"
            ] * 1e3
            epoch_ms = metrics[epoch_ms_col]
            derived = f"{prefix}/{metric}_rate"
            new_cols[derived] = ((metrics[col] / 1e6).diff() / epoch_ms.diff())
            new_cols[derived].fillna(0, inplace=True)

        m = re.search(r'^(thread/.*)/(futex_wait)_ns$', col)
        if m != None: 
            prefix, metric = m.groups()

            metrics[col].fillna(method="pad", inplace=True)
            metrics[col].fillna(0, inplace=True)

            epoch_ms_col = f"{prefix}/epoch_ms"
            metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                epoch_ms_col
            ] = metrics.loc[
                metrics[epoch_ms_col].isna() == True, 
                "epoch_s"
            ] * 1e3
            epoch_ms = metrics[epoch_ms_col]

            derived = f"{prefix}/{metric}_rate"
            new_cols[derived] = ((metrics[col] / 1e6).diff() / epoch_ms.diff())
            new_cols[derived].fillna(0, inplace=True)

        m = re.search(r'^(thread/.*)/(futex_count)$', col)
        if m != None: 
            metrics[col].fillna(0, inplace=True)

        m = re.search(r'^(global/.*)/(sector_cnt)$', col)
        if m != None: 
            metrics[col].fillna(0, inplace=True)

    new_cols = pd.DataFrame(new_cols)
    return pd.concat([metrics, new_cols], axis=1)


def metric_files_to_df(files: list[str], epoch_interval_s: Optional[Tuple[int, int]] = None) -> pd.DataFrame:
    """Reads all `files` and adds them to a single DataFrame."""

    metrics = []

    for file in files: 
        metric = load_metric(file)
        apply_naming_convention(metric, file)
        metrics.append(metric)

    metrics = merge_partitioned_data(metrics)
    metrics = metrics.sort_values(by="epoch_s")

    if epoch_interval_s: 
        min_epoch_s, max_epoch_s = metrics["epoch_s"].min(), metrics["epoch_s"].max()
        min_epoch_s = min_epoch_s if min_epoch_s < epoch_interval_s[0] else epoch_interval_s[0]
        max_epoch_s = max_epoch_s if max_epoch_s > epoch_interval_s[1] else epoch_interval_s[1]
        time = pd.DataFrame(range(min_epoch_s, max_epoch_s), columns=["epoch_s"])
    else:
        min_epoch, max_epoch = metrics["epoch_s"].min(), metrics["epoch_s"].max()
        time = pd.DataFrame(range(min_epoch, max_epoch + 1), columns=["epoch_s"])
    
    metrics = pd.merge(metrics, time, how="outer", on="epoch_s")
    metrics = metrics.sort_values(by="epoch_s")
    metrics = compute_derived_metrics(metrics)
    return metrics

class UnexpectedFilePath(Exception):
    def __init__(self, file_path: str):
        super().__init__(file_path)
