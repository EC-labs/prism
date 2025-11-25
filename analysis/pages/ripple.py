from typing import Tuple
from pathlib import Path
from collections import deque
from pyvis.network import Network

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import networkx as nx
import re

from database import DatabaseClient


db = DatabaseClient("../data/prism-2025-11-24T13:39:54.191391355+00:00.db3")

def bootstrap_undirected_graph(pid_connections: pd.DataFrame, bootstrap: Tuple[int, int]) -> nx.Graph:
    machine, pid = bootstrap
    graph = nx.Graph()
    queue, visited = deque([(machine, pid)]), set()
    while True:
        if len(queue) == 0:
            break
        machine, pid = queue.popleft()
        visited.add((machine, pid))
        edges = pid_connections.loc[
            ((pid_connections["machine1"]==machine) & (pid_connections["pid1"]==pid))
            | ((pid_connections["machine2"]==machine) & (pid_connections["pid2"]==pid))
        ]
        for _, edge in edges.iterrows():
            machine1, pid1, service1 = edge["machine1"], edge["pid1"], edge["service1"]
            machine2, pid2, service2 = edge["machine2"], edge["pid2"], edge["service2"]
            connections = edge["connections"]
            graph.add_edge((machine1, pid1, service1), (machine2, pid2, service2), weight=connections)

            if (machine1, pid1) not in visited:
                queue.append((machine1, pid1))
            if (machine2, pid2) not in visited:
                queue.append((machine2, pid2))
    print(graph.edges.data())
    return graph

st.set_page_config(page_title="Ripple", layout="wide")
st.title("Ripple")
st.markdown("""
    Application Service Dependency Graph
""")

if "ripple_init" not in st.session_state:
    query = Path("./sql/service_list.sql").read_text()
    st.session_state.service_list = db.custom_query(query)
    print(st.session_state.service_list)
    st.session_state.bootstrap = None

st.session_state.ripple_init = True

left, _ = st.columns([0.30, 0.7])
if st.session_state.service_list is not None:
    service_list = st.session_state.service_list
    options = service_list.index.astype(str) + " - " + service_list["service_name"] + " (" + service_list["machine_id"].astype(str) + " : " + service_list["pid"].astype(str) + ")"
    selection = st.session_state.bootstrap = left.selectbox("What service would you like to start from?", options, placeholder="[index] - [service_name] ([machine_id] : [pid])", index=None)
    if selection is not None:
        match = re.search(r"\d+", selection)
        if match is not None:
            index = int(match.group())
            st.session_state.bootstrap = service_list.iloc[index, :]


if st.session_state.bootstrap is not None:
    bootstrap = st.session_state.bootstrap
    st.write(bootstrap["machine_id"], bootstrap["pid"])
    pid_connections = db.custom_query(Path("./sql/pid_connections.sql").read_text())
    missing_discovery = db.custom_query(Path("./sql/missing_discovery.sql").read_text())
    unconnected_pids = db.custom_query(Path("./sql/unconnected_pids.sql").read_text())
    graph = bootstrap_undirected_graph(pid_connections, (bootstrap["machine_id"], bootstrap["pid"]))
    st.write(pid_connections)
