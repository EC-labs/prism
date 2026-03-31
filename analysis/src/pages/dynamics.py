from pathlib import Path
from jinja2 import Template

import networkx as nx
import streamlit as st
import pandas as pd

from src.components.thread_dynamics import thread_dynamics
from src.variables import template_variables


def store_value(key):
    st.session_state[key] = st.session_state["_"+key]

def load_value(key):
    st.session_state["_"+key] = st.session_state.get(key)

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

    sql_dir = Path(__file__).parent / "../sql"
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

    query_template = Template((sql_dir / "dynamics_edges.sql").read_text())

    query = query_template.render({**template_variables(), "pid_filter": pid_filter, "pid": pid, "machine_id": machine_id})
    result = db.custom_query(query)
    nodes = list(set(result["source"].tolist() + result["target"].tolist()))
    edges = result.to_dict(orient="records")

    graph_data = {"nodes": nodes, "edges": edges}
    result = thread_dynamics(graph_data)



st.set_page_config(page_title="Thread Dynamics", layout="wide")
st.markdown("""
    # Service Thread Dynamics

    Display a process' thread interactions with kernel resources.    
""")

main()
