from pathlib import Path
from jinja2 import Template

import json
import networkx as nx
import streamlit as st
import pandas as pd
import re

from src.components.thread_dynamics import thread_dynamics
from src.variables import template_variables


SQL_DIR = Path(__file__).parent / "../sql"


def store_value(key):
    st.session_state[key] = st.session_state["_"+key]

def load_value(key):
    st.session_state["_"+key] = st.session_state.get(key)

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
