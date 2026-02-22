import streamlit as st
import pandas as pd

from BTrees.OOBTree import OOBTree

def time_filter(ts_column: str, range_type: str) -> str:
    tree = st.session_state.get("tree")
    entries = pd.DataFrame({'start': pd.Series(dtype='datetime64[ns]'), 'end': pd.Series(dtype='datetime64[ns]'), 'range_type': pd.Series(dtype='str')})
    if tree is not None:
        for elem in tree:
            start, end, rtype = elem, tree[elem][0], tree[elem][1]
            if rtype != range_type:
                continue
            row = pd.DataFrame([[start, end, range_type]], columns=entries.columns)
            entries = pd.concat([entries, row], ignore_index=True)

    return (
        "(" + " OR ".join([f'({ts_column} >= \'{row["start"]}\' AND {ts_column} <= \'{row["end"]}\')' for _, row in entries.iterrows()]) + ")" 
        if entries.shape[0] > 0 else 
        "true"
    )

def compare_filter(ts_column: str):
    return time_filter(ts_column, "compare")

def baseline_filter(ts_column: str):
    return time_filter(ts_column, "baseline")

def calculate_total_range_time(range_type: str) -> float:
    res = 0.0
    tree = st.session_state.get("tree")
    if tree is not None:
        for elem in tree:
            start, end, rtype = elem, tree[elem][0], tree[elem][1]
            if rtype != range_type:
                continue
            res += (end - start).total_seconds()
    return res

def template_variables() -> dict:
    res = {}

    res["compare_filter"] = compare_filter
    res["baseline_filter"] = baseline_filter
    res["total_compare_seconds"] = calculate_total_range_time("compare")
    res["total_baseline_seconds"] = calculate_total_range_time("baseline")
    return res
