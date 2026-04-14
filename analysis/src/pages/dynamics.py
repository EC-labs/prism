from pathlib import Path
from jinja2 import Template

import networkx as nx
import streamlit as st
import pandas as pd
import numpy as np
import re

from src.components.thread_dynamics import thread_dynamics
from src.variables import template_variables


SQL_DIR = Path(__file__).parent / "../sql"


def store_value(key):
    st.session_state[key] = st.session_state["_"+key]

def load_value(key):
    st.session_state["_"+key] = st.session_state.get(key)

def request_handler_futex(machine_id, pid, vfkey): 
    db = st.session_state.db

    pid_filter = f"(machine_id = {machine_id} AND pid = {pid})"
    query_template = Template((SQL_DIR / "thread_dynamics/futex_view.sql").read_text())
    query = query_template.render({**template_variables(), "vfkey": vfkey, "pid_filter": pid_filter})
    result = db.custom_query(query)
    result["ts"] = result["ts"].dt.strftime('%Y-%m-%d %X')
    res = {
        "type": "futex",
        "inner": result.pivot(index="ts", columns="tid", values="total_time").replace({np.nan: 0}).reset_index().to_dict(orient="records")
    }
    return res

def request_handler_external(machine_id, pid, ext): 
    db = st.session_state.db

    pid_filter = f"(machine_id = {machine_id} AND pid = {pid})"
    query_template = Template((SQL_DIR / "thread_dynamics/external_view.sql").read_text())
    query = query_template.render({**template_variables(), "ext": 'ext-' + ext})
    result = db.custom_query(query)
    result = result.melt(
        id_vars=['machine_id', 'pid'], 
        var_name='attribute', 
        value_name='value'
    ).replace({np.nan: None})
    grouped = result.groupby(['machine_id', 'pid'])

    serialized_data = []

    for (m_id, pid), group in grouped:
        # Create a list of attribute/value pairs for this specific process
        attributes = group[['attribute', 'value']].to_dict(orient='records')
        
        serialized_data.append({
            "machine_id": int(m_id),
            "pid": int(pid),
            "attributes": attributes
        })
    res = { "type": "ext", "inner": serialized_data }

    return res

def request_handler_disk(machine_id, pid, part0): 
    db = st.session_state.db
    pid_filter = f"(machine_id = {machine_id} AND pid = {pid})"
    query_template = Template((SQL_DIR / "thread_dynamics/disk_view.sql").read_text())
    query = query_template.render({**template_variables(), "part0": part0, "pid_filter": pid_filter})
    result = db.custom_query(query)
    result["ts"] = result["ts"].dt.strftime('%Y-%m-%d %X')
    res = {
        "type": "disk",
        "inner": result.pivot(index="ts", columns="tid", values="sectors").replace({np.nan: 0}).reset_index().to_dict(orient="records")
    }
    return res

def request_handler_inet(machine_id, pid, vinet): 
    db = st.session_state.db

    query_template = Template((SQL_DIR / "thread_dynamics/inet_view.sql").read_text())
    query = query_template.render({**template_variables(),"machine_id": machine_id, "pid": pid, "vinet": vinet })
    result = db.custom_query(query)
    result["ts"] = result["ts"].dt.strftime('%Y-%m-%d %X')
    res = {
        "type": "inet",
        "inner": result.pivot(index="ts", columns="tid", values="total_time").replace({np.nan: 0}).reset_index().to_dict(orient="records")
    }
    return res

def request_handler_unix(machine_id, pid, vunix): 
    db = st.session_state.db

    query_template = Template((SQL_DIR / "thread_dynamics/unix_view.sql").read_text())
    query = query_template.render({**template_variables(),"machine_id": machine_id, "pid": pid, "vunix": vunix })
    result = db.custom_query(query)
    result["ts"] = result["ts"].dt.strftime('%Y-%m-%d %X')
    res = {
        "type": "unix",
        "inner": result.pivot(index="ts", columns="tid", values="total_time").replace({np.nan: 0}).reset_index().to_dict(orient="records")
    }
    return res

def request_handler_vfs(machine_id, pid, inode): 
    db = st.session_state.db

    query_template = Template((SQL_DIR / "thread_dynamics/vfs_view.sql").read_text())
    query = query_template.render({**template_variables(),"machine_id": machine_id, "pid": pid, "inode": 'vfs-' + inode })
    result = db.custom_query(query)
    result["ts"] = result["ts"].dt.strftime('%Y-%m-%d %X')
    res = {
        "type": "vfs",
        "inner": result.pivot(index="ts", columns="tid", values="total_time").replace({np.nan: 0}).reset_index().to_dict(orient="records")
    }
    return res

def request_handler_thread(machine_id, pid, tid): 
    db = st.session_state.db

    pid_filter = f"(machine_id = {machine_id} AND pid = {pid})"
    tid_filter = f"(machine_id = {machine_id} AND tid = {tid})"
    query_template = Template((SQL_DIR / "thread_dynamics/thread_view.sql").read_text())
    query = query_template.render({ "tid_filter": tid_filter, "pid_filter": pid_filter})
    result = db.custom_query(query)
    result["ts"] = result["ts"].dt.strftime('%Y-%m-%d %X')

    res = {
        "type": "thread",
        "inner": result.to_dict(orient="records")

    }
    return res

def request_dispatcher(machine_id, pid, request_type, request_arg):
    if request_type == "thread":
        return request_handler_thread(machine_id, pid, request_arg) 
    elif request_type == "contention":
        return request_handler_futex(machine_id, pid, request_arg)
    elif request_type == "schedule":
        return request_handler_futex(machine_id, pid, request_arg)
    elif request_type == "disk":
        return request_handler_disk(machine_id, pid, request_arg)
    elif request_type == "inet":
        return request_handler_inet(machine_id, pid, request_arg)
    elif request_type == "unix":
        return request_handler_unix(machine_id, pid, request_arg)
    elif request_type == "vfs":
        return request_handler_vfs(machine_id, pid, request_arg)
    elif request_type == "ext":
        return request_handler_external(machine_id, pid, request_arg)
    else:
        return {
            "type": request_type,
            "inner": {
                "id": request_arg,
            },
        }


def on_request_cb(machine_id, pid):
    def cb():
        graph_element_id = st.session_state["thread_dynamics_state"]["request"]
        request_type, request_arg = re.search(r"^(\w+)-(.*)$", graph_element_id).groups()
        st.session_state["thread_dynamics_state"]["response"] = request_dispatcher(machine_id, pid, request_type, request_arg)
    return cb

if "dynamics_init" not in st.session_state: 
    st.session_state.service_index = None

st.session_state.dynamics_init = True

def main():
    if ('db' not in st.session_state) or (st.session_state.db is None):
        st.info("You’re almost ready — connect to a database")

        if st.button("Connect to Database"):
            st.switch_page("pages/home.py")

        return

    if ('ripple_graph' not in st.session_state) or (st.session_state.ripple_graph is None):
        st.info("Create ripple graph")

        if st.button("Go to Ripple"):
            st.switch_page("pages/ripple.py")

        return

    db = st.session_state.db
    graph = st.session_state.ripple_graph
    services = [node for node, attr in graph.nodes().data() if attr["machine"] != -1]
    load_value("service_index")
    service = st.selectbox(
        "Service",
        services,
        index=None,
        key="_service_index",
        on_change=store_value,
        args=["service_index"],
        placeholder="Select a service from the ripple graph",
    )
    if service is None: 
        return 
    node = graph.nodes()[service]
    machine_id, pid = node["machine"], node["pid"]
    pid_filter = f"((machine_id = {machine_id}) AND (pid = {pid}))"

    query_template = Template((SQL_DIR / "dynamics_edges.sql").read_text())

    query = query_template.render({**template_variables(), "pid_filter": pid_filter, "pid": pid, "machine_id": machine_id})
    result = db.custom_query(query)
    nodes = list(set(result["source"].tolist() + result["target"].tolist()))
    edges = result.to_dict(orient="records")
    nodes.sort()
    edges.sort(key=lambda x: (x["source"], x["target"], x["edge_type"]))

    graph_data = {"nodes": nodes, "edges": edges}
    result = thread_dynamics(graph_data, on_request_cb(machine_id, pid), key="thread_dynamics_state")


st.set_page_config(page_title="Thread Dynamics", layout="wide")
st.markdown("""
    # Service Thread Dynamics
""")

main()
