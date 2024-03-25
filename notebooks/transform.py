from __future__ import annotations
import os
import pandas as pd
import re
import csv

from enum import Enum
from typing import List, Optional


class MetricClass(Enum): 
    SCHEDSTAT = 'schedstat'
    SCHED = 'sched'

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

def transform_metrics(metrics: pd.DataFrame, metric_class: MetricClass): 
    """Create new DataFrame with based on `metrics`."""

    time_delta = metrics["epoch_ms"].diff()
    if metric_class == MetricClass.SCHEDSTAT: 
        metrics["runtime_rate"] = metrics["runtime"].diff() / time_delta
        metrics["rq_rate"] = metrics["rq_time"].diff() / time_delta
    elif metric_class == MetricClass.SCHED: 
        metrics["runtime_rate"] = metrics["runtime"].diff() / time_delta
        metrics["rq_rate"] = metrics["rq_time"].diff() / time_delta
        metrics["iowait_rate"] = metrics["iowait_time"].diff() / time_delta
        metrics["block_rate"] = metrics["block_time"].diff() / time_delta
        metrics["sleep_rate"] = metrics["sleep_time"].diff() / time_delta
        metrics["runnable"] = metrics["runtime_rate"] + metrics["rq_rate"]
        metrics["active_rate"] = metrics["block_rate"] + metrics["runtime_rate"] + metrics["rq_rate"]
    else: 
        raise NotImplemented()
    metrics.dropna(inplace=True)

def metric_files_to_df(files: list[str]) -> pd.DataFrame:
    """Reads all `files` and adds them to a single DataFrame."""

    metrics = pd.DataFrame({"epoch_s": []})
    for file in files: 
        m = re.search(r'\d/(.*)/(\d+)/(\w+)/(\d+\.csv$)', file)
        if m == None: 
            continue

        comm, thread, metric_class, _ = m.groups()
        metric_class = MetricClass(metric_class)
        prefix = f"{comm}/{thread}/{metric_class}"

        metric = pd.read_csv(file)
        metric["epoch_s"] = (metric["epoch_ms"]//1e3).astype("Int64")
        transform_metrics(metric, metric_class)

        metric.columns = [
            f"{prefix}/{col}" if col != "epoch_s" else col
            for col in metric.columns
        ]
        metrics = pd.merge(metrics, metric, on="epoch_s", how="outer")
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
    for curr in response_sorted_start["start_epoch_s"].unique():
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
