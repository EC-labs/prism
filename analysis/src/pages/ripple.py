from typing import Tuple
from pathlib import Path
from collections import deque, defaultdict
from matplotlib.patches import Wedge
from jinja2 import Template

import colorsys
import matplotlib.pyplot as plt
import streamlit as st
import pandas as pd
import networkx as nx
import numpy as np
import re


def normalise_angle_degrees(degrees: float) -> float:
    return degrees if degrees <= 180 else degrees - 360

def add_disconnected(graph: nx.Graph, disconnected: pd.DataFrame, pid: int):
    for _, row in disconnected.loc[disconnected["pid"] == pid, :].iterrows():
        machine, pid, service = row["machine_id"], row["pid"], row["service_name"]
        graph.add_node(f"{service}\n({machine}:{pid})", machine=machine, pid=pid, service=service)

def add_missing_discovery(graph: nx.Graph, missing_discovery: pd.DataFrame, max_nodes: int):
    for node, attr in list(graph.nodes.data()):
        pid = attr["pid"]
        missing_edges = missing_discovery.loc[missing_discovery["pid"] == pid]
        for _, edge in missing_edges.iterrows():
            dst = edge["dst_address"]
            connections = edge["connections"]

            if len(graph) < max_nodes:
                graph.add_node(dst, machine=-1, pid=-1, service=-1)

            if graph.has_node(node) and graph.has_node(dst):
                graph.add_edge(node, dst, connections=connections)

def bootstrap_undirected_graph(pid_connections: pd.DataFrame, bootstrap: Tuple[int, int], max_nodes: int) -> nx.Graph:
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
            if pid1 == pid2:
                continue

            s1_nid, s2_nid = f"{service1}\n({machine1}:{pid1})", f"{service2}\n({machine2}:{pid2})"
            if len(graph) < max_nodes:
                graph.add_node(s1_nid, machine=machine1, pid=pid1, service=service1)

            if len(graph) < max_nodes:
                graph.add_node(s2_nid, machine=machine2, pid=pid2, service=service2)

            if graph.has_node(s1_nid) and graph.has_node(s2_nid):
                graph.add_edge(s1_nid, s2_nid, connections=connections)

            if (machine1, pid1) not in visited:
                queue.append((machine1, pid1))
            if (machine2, pid2) not in visited:
                queue.append((machine2, pid2))
    return graph

def draw_network(graph: nx.Graph, bootstrap: int):
    machine_map = {}
    for node, attr in graph.nodes.data():
        machine_map[node] = attr["machine"]


    # Group services by machine
    machine_to_services = defaultdict(list)
    for service, machine in machine_map.items():
        machine_to_services[machine].append(service)

    # Generate machine colours
    machine_color = {}
    for i, m in enumerate(machine_to_services.keys()):
        h = i / len(machine_to_services)
        s = 0.70
        l = 0.60

        r, g, b = colorsys.hls_to_rgb(h, l, s)
        machine_color[m] = (r, g, b, 0.3)

    # Flatten services in order by machine
    clustered_services = []
    machine_angle_ranges = {}  # machine_id -> (start_idx, end_idx)
    angle_index = 0
    for machine in sorted(machine_to_services):
        services = sorted(set(machine_to_services[machine]))
        clustered_services.extend(services)
        machine_angle_ranges[machine] = (angle_index, angle_index + len(services) - 1)
        angle_index += len(services)

    # Assign positions on circle
    n = len(clustered_services)
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False)
    pos = {}
    for i, service in enumerate(clustered_services):
        angle = angles[i]
        pos[service] = (np.cos(angle), np.sin(angle))

    G = graph

    # Plot setup
    fig, ax = plt.subplots(figsize=(6, 6))

    slice_outer_radius = 1.07  # slightly larger than node radius 1
    slice_inner_radius = 0  # small hole in the center

    # Draw filled pie slices for each machine
    for machine, (start_idx, end_idx) in machine_angle_ranges.items():
        first_service_angle = normalise_angle_degrees(np.degrees(angles[start_idx].item()))
        previous_service_angle = normalise_angle_degrees(np.degrees(angles[(start_idx-1)%len(angles)].item()))
        last_service_angle = normalise_angle_degrees(np.degrees(angles[end_idx].item()))
        next_service_angle = normalise_angle_degrees(np.degrees(angles[(end_idx+1)%len(angles)].item()))

        theta_start = first_service_angle - (first_service_angle - previous_service_angle) / 2
        theta_end = last_service_angle + (next_service_angle - last_service_angle) / 2
        if theta_end <= theta_start:
            theta_end += 360


        # Draw the wedge (filled arc)
        wedge = Wedge(center=(0, 0),
                      r=slice_outer_radius,
                      theta1=theta_start,
                      theta2=theta_end,
                      width=slice_outer_radius - slice_inner_radius,
                      facecolor=machine_color[machine],
                      edgecolor="black",
                      linestyle="solid" if machine != -1 else "dashed",
                      linewidth=0.5)
        ax.add_patch(wedge)

        # Label in the middle of the arc, closer to the center
        mid_angle = (np.radians(theta_start) + np.radians(theta_end)) / 2
        label_radius = slice_inner_radius + (slice_outer_radius - slice_inner_radius) / 2
        label_x = label_radius * np.cos(mid_angle)
        label_y = label_radius * np.sin(mid_angle)
        ax.text(label_x, label_y, machine if machine != -1 else "?",
                fontsize=10, fontweight='bold',
                ha='center', va='center', color='white', bbox=dict(boxstyle=f"square", fc=(0, 0, 0, 0.5), linewidth=0))
    nx.draw_networkx_edges(G, pos, edgelist=G.edges, ax=ax, width=1.5, style="solid", edge_color="black",)
    nx.draw_networkx_nodes(
        G, pos, margins=0, ax=ax, nodelist=G.nodes,
        node_size=70, node_color=["white" if attr["pid"] != bootstrap else "#90ee90" for node, attr in G.nodes.data()],
        edgecolors="black", linewidths=1.2
    )

    # Radial labels outside nodes
    for node, (x, y) in pos.items():
        angle = np.arctan2(y, x)
        label_radius = 1.1  # outside slice radius now
        label_x = label_radius * np.cos(angle)
        label_y = label_radius * np.sin(angle)
        rotation = np.degrees(angle)
        text = node.split()
        text = "\n".join([text[0][:15] + "..." if len(text[0]) > 15 else text[0], text[1] if  len(text) > 1 else ""]).strip()
        if rotation < -90 or rotation > 90:
            rotation += 180
            ha = 'right'
        else:
            ha = 'left'
        ax.text(label_x, label_y, text, fontsize=9, rotation=rotation,
                ha=ha, va='center', rotation_mode='anchor')

    # Final plot tweaks
    ax.set_aspect('equal')
    plt.axis('off')
    plt.tight_layout()
    st.pyplot(fig, width=800)
    plt.close()


def main():
    st.set_page_config(page_title="Ripple", layout="centered")
    st.title("Ripple")
    st.markdown("""
        ## Application Service Dependency Graph

        If two processes interact with each other via tcp sockets, unix sockets, or pipes, their dependency will appear in the following graph
    """)

    if ('db' not in st.session_state) or (st.session_state.db is None):
        st.info("You’re almost ready — connect to a database")

        if st.button("Connect to Database"):
            st.switch_page("pages/home.py")

        return

    db = st.session_state.db
    sql_dir = Path(__file__).parent / "../sql"

    if "ripple_init" not in st.session_state:
        query = (sql_dir / "service_list.sql").read_text()
        st.session_state.service_list = db.custom_query(query)
        st.session_state.bootstrap = None
        st.session_state.ripple_max_nodes = 20
        st.session_state.ripple_use_compare = False
        st.session_state.compare_entries = None
        st.session_state.ripple_graph = None

    st.session_state.ripple_init = True

    left, middle, right = st.columns([0.6, 0.15, 0.25], vertical_alignment="bottom")
    if st.session_state.service_list is not None:
        service_list = st.session_state.service_list
        options = service_list.index.astype(str) + " - " + service_list["service_name"] + " (" + service_list["machine_id"].astype(str) + " : " + service_list["pid"].astype(str) + ")"

        index = (None
            if st.session_state.bootstrap is None
            else int(service_list.index[
                 (service_list["machine_id"] == st.session_state.bootstrap["machine_id"]) &
                 (service_list["pid"] == st.session_state.bootstrap["pid"])
        ][0]))
        selection = left.selectbox("What service would you like to start from?", options, placeholder="[index] - [service_name] ([machine_id] : [pid])", index=index)
        if selection is not None:
            match = re.search(r"\d+", selection)
            if match is not None:
                index = int(match.group())
                st.session_state.bootstrap = service_list.iloc[index, :]

        st.session_state.ripple_max_nodes = middle.number_input("Max nodes", value=st.session_state.ripple_max_nodes)

        tree = st.session_state.get("tree")
        compare_entries = pd.DataFrame({'start': pd.Series(dtype='datetime64[ns]'), 'end': pd.Series(dtype='datetime64[ns]'), 'range_type': pd.Series(dtype='str')})
        if tree is not None:
            for elem in tree:
                start, end, range_type = elem, tree[elem][0], tree[elem][1]
                if range_type != "compare":
                    continue
                row = pd.DataFrame([[start, end, range_type]], columns=compare_entries.columns)
                compare_entries = pd.concat([compare_entries, row], ignore_index=True)
        st.session_state.ripple_use_compare = right.toggle(
            "Use compare", 
            disabled=compare_entries.shape[0] == 0, 
            value=st.session_state.ripple_use_compare, 
            help="Define *compare* periods in the KPI page to use this feature."
        )
        st.session_state.compare_entries = compare_entries

    if st.session_state.bootstrap is not None:

        if (not st.session_state.ripple_use_compare) or (st.session_state.compare_entries is None) or (st.session_state.compare_entries.shape[0] == 0):
            compare_filter = "true"
        else:
            compare_filter = "(" + " OR ".join([f'(ts_s >= \'{row["start"]}\' AND ts_s <= \'{row["end"]}\')' for _, row in st.session_state.compare_entries.iterrows()]) + ")"
        pid_connections_query = Template((sql_dir / "pid_connections.sql").read_text()).render(vfs_ts_filter=compare_filter)
        pid_connections = db.custom_query(pid_connections_query)
        pid_connections = pid_connections.sort_values(list(pid_connections.columns))
        missing_discovery = db.custom_query((sql_dir / "missing_discovery.sql").read_text())
        missing_discovery = missing_discovery.sort_values(list(missing_discovery.columns))
        unconnected_pids = db.custom_query((sql_dir / "unconnected_pids.sql").read_text())

        bootstrap = st.session_state.bootstrap
        graph = bootstrap_undirected_graph(pid_connections, (bootstrap["machine_id"], bootstrap["pid"]), max_nodes=st.session_state.ripple_max_nodes)
        add_missing_discovery(graph, missing_discovery, max_nodes=st.session_state.ripple_max_nodes)
        add_disconnected(graph, unconnected_pids, bootstrap["pid"])
        st.session_state.ripple_graph = graph
        draw_network(graph, bootstrap["pid"])
main()
