import streamlit as st
import pandas as pd
import numpy as np

from pathlib import Path
from jinja2 import Template

from database import DatabaseClient
from variables import template_variables


SHARES = [
    {
        "share_type": "run",
        "file_path": "sql/distributions/pid_run_share.sql",
    },
    {
        "share_type": "runqueue",
        "file_path": "sql/distributions/pid_rq_share.sql",
    },
    {
        "share_type": "uninterruptible",
        "file_path": "sql/distributions/pid_uninterruptible_share.sql",
    },
    {
        "share_type": "blkio",
        "file_path": "sql/distributions/pid_blkio_share.sql",
    },
    {
        "share_type": "futex_schedule",
        "file_path": "sql/distributions/pid_futex_total_schedule.sql",
    },
    {
        "share_type": "futex_contention",
        "file_path": "sql/distributions/pid_futex_total_contention.sql",
    },
]


def total_time_range(range_filter: str) -> float | None:
    if "tree" not in st.session_state or st.session_state.tree is None:
        return None
    
    total_time = 0.0
    tree = st.session_state.tree
    for elem in tree:
        start, end, range_type = elem, tree[elem][0], tree[elem][1]
        if range_type == range_filter:
            total_time += (end - start).total_seconds()
    return total_time

def process_shares(machine_id: int, pid: int, total_time_compare: float, total_time_baseline: float, db: DatabaseClient):
    res = pd.DataFrame([[pd.NA] * 6], columns=["run", "runqueue", "uninterruptible", "blkio", "futex_schedule", "futex_contention"])
    pid_filter = f"(pid={pid} AND machine_id={machine_id})"
    for share in SHARES:
        share_type, query_path = share["share_type"], share["file_path"]
        variables = {**template_variables(), "pid_filter": pid_filter}
        template = Path(query_path).read_text()
        rendered = Template(template).render(**variables)
        result = db.custom_query(rendered)
        result["max_shares"] = result["type"].map({"compare": total_time_compare, "baseline": total_time_baseline})
        result["share"] = result[["share", "max_shares"]].min(axis=1)
        stats = result.groupby(["type"])["share"].sum()
        score = 0.0
        if "compare" in stats and "baseline" in stats:
            compare, baseline = stats["compare"]/total_time_compare, stats["baseline"]/total_time_compare
            # do not over-inflate when baseline is small
            if baseline < 0.001:
                score = compare
            else:
                score = (compare-baseline)/baseline * compare
            if score < 0.001:
                score = 0.0
        elif "compare" in stats and "baseline" not in stats:
            score = stats["compare"]/total_time_compare
        res[share_type] = score

    return res



def main():
    if ('db' not in st.session_state) or (st.session_state.db is None):
        st.info("You’re almost ready — connect to a Prism database")

        if st.button("Connect to Database"):
            st.switch_page("main.py")

        return

    if ('ripple_graph' not in st.session_state) or (st.session_state.ripple_graph is None):
        st.info("Create ripple graph")

        if st.button("Go to Ripple"):
            st.switch_page("pages/ripple.py")

        return
    db = st.session_state.db
    graph = st.session_state.ripple_graph
    total_time_compare, total_time_baseline = total_time_range("compare"), total_time_range("baseline")
    if total_time_compare is None or total_time_baseline is None: 
        return

    graph_len = len(graph.nodes)
    status = st.status(f"⏳ Computing shares 0/{graph_len}", expanded=False)
    scores = pd.DataFrame(columns=["service", "run", "runqueue", "uninterruptible", "blkio", "futex_schedule", "futex_contention"])
    for i, node in enumerate(graph):
        machine_id, pid = graph.nodes[node]["machine"], graph.nodes[node]["pid"],
        status.update(label=f"⏳Computing shares {i}/{graph_len}", expanded=False)
        pid_shares = process_shares(machine_id, pid, total_time_compare, total_time_baseline, db)
        pid_shares["service"] = node
        scores = pd.concat([scores, pid_shares])
        
    scores.insert(1, "score", np.linalg.norm(scores.loc[:, ["run", "runqueue", "uninterruptible", "blkio", "futex_schedule", "futex_contention"]], axis=1))
    scores.sort_values(by="score", ascending=False, inplace=True)
    scores.reset_index(drop=True, inplace=True)
    status.update(label=f"✅️ Complete", state="complete", expanded=False)
    scores = scores.style.background_gradient(
        subset=["score"],
        cmap="copper"
    )
    st.dataframe(scores)

st.set_page_config(page_title="Degradation", layout="centered")
st.markdown("""
    # Distributed System Performance Degradation Analysis

    Given a distributed service graph (Ripple), and baseline (application operating under normal conditions) and compare (application operating under degraded conditions) ranges, this page computes the degradation score for each service present in the service graph provided by Ripple.
""")

main()
