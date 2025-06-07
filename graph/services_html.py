import duckdb
import networkx as nx
import pandas as pd
import random

from graphviz import Graph
from pyvis.network import Network
from pathlib import Path

conn = duckdb.connect(database=':memory:')

conn.execute("""ATTACH 'data/gijs2.db3' as gijs2""")
conn.execute("""ATTACH 'data/gijs3.db3' as gijs3""")

connections = conn.execute("""
    WITH 
        tcp_discovery AS (
            SELECT * FROM gijs2.tcp_discovery tcp
            WHERE tcp.remote_inode_id <> 0
            UNION ALL
            SELECT * FROM gijs3.tcp_discovery tcp
            WHERE tcp.remote_inode_id <> 0
        ),
        process_context AS (
            SELECT 2 as machine_id, * FROM gijs2.process_context
            UNION ALL
            SELECT 3 as machine_id, * FROM gijs3.process_context
        ),
        docker AS (
            SELECT 2 as machine_id, * FROM gijs2.docker
            UNION ALL
            SELECT 3 as machine_id, * FROM gijs3.docker
        ),
        k8s AS (
            SELECT 2 as machine_id, * FROM gijs2.k8s
            UNION ALL
            SELECT 3 as machine_id, * FROM gijs3.k8s
        ),
        pids AS (
            SELECT DISTINCT
                2 as machine_id,
                pid, 
                inode_id,
            FROM 
                gijs2.vfs vfs
            WHERE 
                vfs.fs_magic = 1397703499
            UNION ALL
            SELECT DISTINCT
                3 as machine_id,
                pid, 
                inode_id,
            FROM 
                gijs3.vfs vfs
            WHERE 
                vfs.fs_magic = 1397703499
        )
    SELECT DISTINCT
        tcp.local_machine_id, 
        lpids.pid as lpid,
        COALESCE(lk8s.pod_name, ldock.name, lpc.cgroup) as lcgroup,
        tcp.remote_machine_id,
        tcp.remote_inode_id, 
        rpids.pid as rpid,
        COALESCE(rk8s.pod_name, rdock.name, rpc.cgroup) as rcgroup,
        COUNT(*) as num_connections, 
    FROM
        tcp_discovery tcp
    LEFT JOIN
        pids as lpids
        ON lpids.inode_id = tcp.local_inode_id
        AND lpids.machine_id = tcp.local_machine_id
    LEFT JOIN 
        process_context lpc
        ON lpc.pid = lpids.pid
        AND lpc.machine_id = tcp.local_machine_id
    LEFT JOIN
        docker ldock
        ON ldock.cgroup = lpc.cgroup
        AND ldock.machine_id = tcp.local_machine_id
    LEFT JOIN
        k8s lk8s
        ON lk8s.cgroup = lpc.cgroup
        AND lk8s.machine_id = tcp.local_machine_id
    LEFT JOIN
        pids as rpids
        ON rpids.inode_id = tcp.remote_inode_id
        AND rpids.machine_id = tcp.remote_machine_id
    LEFT JOIN 
        process_context rpc
        ON rpc.pid = rpids.pid
        AND rpc.machine_id = tcp.remote_machine_id
    LEFT JOIN 
        docker rdock
        ON rdock.cgroup = rpc.cgroup
        AND rdock.machine_id = tcp.remote_machine_id
    LEFT JOIN 
        k8s rk8s
        ON rk8s.cgroup = rpc.cgroup
        AND rk8s.machine_id = tcp.remote_machine_id
    WHERE 
        lpids.pid IS NOT NULL 
        AND rpids.pid IS NOT NULL
    GROUP BY 
        tcp.local_machine_id, 
        lpids.pid,
        lk8s.pod_name, 
        ldock.name, 
        lpc.cgroup,
        tcp.remote_machine_id,
        tcp.remote_inode_id, 
        rpids.pid,
        rk8s.pod_name, 
        rdock.name,
        rpc.cgroup,
    ORDER BY
        lcgroup
""").df()

nodes = connections.loc[:, ["local_machine_id", "lpid", "lcgroup"]].drop_duplicates()


def random_color(seed_str):
    random.seed(seed_str)
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))


def build_graph_with_clusters(connections: pd.DataFrame) -> nx.Graph:
    """
    Build an undirected graph from a DataFrame with columns:
    - local_machine_id
    - lpid
    - lcgroup
    - remote_machine_id
    - rpid
    """

    G = nx.Graph()

    # Store node metadata to assign consistent colors per lcgroup
    color_map = {}

    for _, row in connections.iterrows():
        src_machine = row["local_machine_id"]
        src_pid = row["lpid"]
        src_group = row["lcgroup"]
        dst_machine = row["remote_machine_id"]
        dst_pid = row["rpid"]
        dst_group = row["rcgroup"]
        num_connections = row["num_connections"]

        src = f"{src_machine}-{src_pid}"
        dst = f"{dst_machine}-{dst_pid}"

        # Assign colors per lcgroup
        if src_machine not in color_map:
            color_map[src_machine] = random_color(str(src_machine))
        if dst_machine not in color_map:
            color_map[dst_machine] = random_color(str(dst_machine))


        # Add source and destination nodes with visual info
        for node, machine, pid, group in [
            (src, src_machine, src_pid, src_group),
            (dst, dst_machine, dst_pid, dst_group),
        ]:
            if node not in G:
                G.add_node(
                    node,
                    label=f"{group}\n{pid}",
                    title=f"Machine: {machine}\nGroup: {group}",
                    color=lighten_color(color_map[machine], factor=0.35),
                    shape="dot",
                    size=20,
                    font={"size": 12, "multi": "html"},  # enable <br> rendering
                )

        # Add undirected edge
        G.add_edge(src, dst, color='rgba(150,150,150,0.6)')#, label=f"{num_connections}")

    return G

def lighten_color(hex_color, factor=0.5):
    """Blend the hex color with white. Factor 0.0 = original, 1.0 = white."""
    hex_color = hex_color.lstrip("#")
    rgb = [int(hex_color[i:i+2], 16) for i in (0, 2, 4)]
    light_rgb = [int(c + (255 - c) * factor) for c in rgb]
    return "#{:02x}{:02x}{:02x}".format(*light_rgb)

def write_html(graph: nx.Graph, outfile: Path, launch=True):
    net = Network(height="800px", width="100%", directed=False, bgcolor="#ffffff")
    net.from_nx(graph)
    net.toggle_physics(False)
    net.options.edges.smooth.enabled = False

    html_path = str(outfile)
    net.write_html(html_path, notebook=False)

    # Inject JS for Save + Load + Auto-load
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    js_extension = """
    <div style="position:fixed;top:10px;right:10px;z-index:9999;">
        <button onclick="downloadGraph()">Save Graph</button>
        <input type="file" id="upload" onchange="uploadGraph()" style="display:none;" />
        <button onclick="document.getElementById('upload').click();">Load Graph</button>
    </div>
    <script>
    function downloadGraph() {
        var positions = network.getPositions();
        var blob = new Blob([JSON.stringify(positions, null, 2)], {type : 'application/json'});
        var link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        link.download = 'graph-positions.json';
        link.click();
    }

    function uploadGraph() {
        var fileInput = document.getElementById('upload');
        var file = fileInput.files[0];
        var reader = new FileReader();
        reader.onload = function(event) {
            var positions = JSON.parse(event.target.result);
            for (const [nodeId, pos] of Object.entries(positions)) {
                network.moveNode(nodeId, pos.x, pos.y);
            }
        };
        if (file) {
            reader.readAsText(file);
        }
    }

    </script>
    </body>
    """

    html = html.replace("</body>", js_extension)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

G = build_graph_with_clusters(connections)
write_html(G, Path("services.html"))
