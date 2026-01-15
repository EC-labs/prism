import streamlit as st
import pandas as pd
import numpy as np
import colorsys
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import matplotlib.cm as cm

from collections import defaultdict
from matplotlib.patches import Wedge
from pathlib import Path
from jinja2 import Template
from BTrees.OOBTree import OOBTree

from src.database import DatabaseClient
from src.variables import template_variables


SHARES = [
    {
        "share_type": "run",
        "file_path": "distributions/pid_run_share.sql",
    },
    {
        "share_type": "runqueue",
        "file_path": "distributions/pid_rq_share.sql",
    },
    {
        "share_type": "uninterruptible",
        "file_path": "distributions/pid_uninterruptible_share.sql",
    },
    {
        "share_type": "blkio",
        "file_path": "distributions/pid_blkio_share.sql",
    },
    {
        "share_type": "futex_schedule",
        "file_path": "distributions/pid_futex_total_schedule.sql",
    },
    {
        "share_type": "futex_contention",
        "file_path": "distributions/pid_futex_total_contention.sql",
    },
]

def hash_db_client(db: DatabaseClient): 
    return hash(db.conn)

def hash_graph(graph: nx.Graph): 
    nodes = list(graph.nodes)
    nodes.sort()
    return hash(tuple(nodes))

def hash_tree(tree: OOBTree): 
    return hash(tuple(tree))

def total_time_range(range_filter: str, tree: OOBTree) -> float | None:
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
    sql_dir = Path(__file__).parent / "../sql"
    for share in SHARES:
        share_type, query_path = share["share_type"], sql_dir / share["file_path"]
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
            if baseline < 0.01:
                score = compare
            else:
                score = (compare-baseline)/baseline * compare
            if score < 0.001:
                score = 0.0
        elif "compare" in stats and "baseline" not in stats:
            score = stats["compare"]/total_time_compare
        res[share_type] = score

    return res

@st.cache_data(hash_funcs={DatabaseClient: hash_db_client, nx.Graph: hash_graph, OOBTree: hash_tree}, show_spinner=False)
def compute_scores(db, graph, range_tree, _status) -> pd.DataFrame | None:
    total_time_compare, total_time_baseline = total_time_range("compare", range_tree), total_time_range("baseline", range_tree)
    if total_time_compare is None or total_time_baseline is None: 
        return

    graph_len = len(graph.nodes)
    scores = pd.DataFrame(columns=["service", "run", "runqueue", "uninterruptible", "blkio", "futex_schedule", "futex_contention"])
    for i, node in enumerate(graph):
        machine_id, pid = graph.nodes[node]["machine"], graph.nodes[node]["pid"],
        _status.update(label=f"⏳Computing shares {i}/{graph_len}", expanded=False)
        pid_shares = process_shares(machine_id, pid, total_time_compare, total_time_baseline, db)
        pid_shares["service"] = node
        scores = pd.concat([scores, pid_shares])
        
    scores.insert(1, "score", np.linalg.norm(scores.loc[:, ["run", "runqueue", "uninterruptible", "blkio", "futex_schedule", "futex_contention"]], axis=1))
    scores.sort_values(by="score", ascending=False, inplace=True)
    scores.reset_index(drop=True, inplace=True)
    return scores

def normalise_angle_degrees(degrees: float) -> float:
    return degrees if degrees <= 180 else degrees - 360

def draw_network(graph: nx.Graph, service_scores: pd.DataFrame):
    machine_map = {}
    for node, attr in graph.nodes.data():
        machine_map[node] = attr["machine"]

    cmap = cm.get_cmap("copper")

    norm = mcolors.Normalize(
        vmin=service_scores["score"].min(),
        vmax=service_scores["score"].max()
    )

    service_scores["color_hex"] = service_scores["score"].apply(
        lambda v: mcolors.to_hex(cmap(norm(v)))
    )

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
                      facecolor="white",
                      width=slice_outer_radius - slice_inner_radius,
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
        node_size=70, node_color=[service_scores.loc[service_scores["service"] == node, "color_hex"].iloc[0] for node in G.nodes],
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

def cb():
    print("Selected")

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

    if ('tree' not in st.session_state) or (st.session_state.ripple_graph is None):
        st.info("Specify compare and baseline periods")

        if st.button("Go to KPI"):
            st.switch_page("pages/kpi.py")

        return

    db = st.session_state.db
    graph = st.session_state.ripple_graph
    tree = st.session_state.tree
    status = st.status("⏳ Computing shares", expanded=False)
    scores = compute_scores(db, graph, tree, status)
    status.update(label=f"✅️ Complete", state="complete", expanded=False)
    if scores is None: 
        return

    styler = scores.style.background_gradient(
        subset=["score"],
        cmap="copper"
    )
    event = st.dataframe(styler, on_select=cb, selection_mode='single-row')
    draw_network(graph, scores.loc[:, ["service", "score"]])

st.set_page_config(page_title="Degradation", layout="centered")
st.markdown("""
    # Distributed System Performance Degradation Analysis

    Given a distributed service graph (Ripple), and baseline (application operating under normal conditions) and compare (application operating under degraded conditions) ranges, this page computes the degradation score for each service present in the service graph provided by Ripple.
""")

main()
