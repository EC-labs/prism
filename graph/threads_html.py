import duckdb
import networkx as nx
import pandas as pd
import random
import sys

from graphviz import Graph
from pyvis.network import Network
from pathlib import Path


def random_color(seed_str):
    random.seed(seed_str)
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

def build_graph_with_clusters(tid_futex: pd.DataFrame) -> nx.Graph:
    """
    Build an undirected graph from a DataFrame with columns:
    - local_machine_id
    - lpid
    - lcgroup
    - remote_machine_id
    - rpid
    """

    G = nx.DiGraph()

    # Store node metadata to assign consistent colors per lcgroup
    color_map = {
        "tid": random_color("tid"),
        "futex": random_color("futex"),
    }

    schedule = tid_futex.loc[tid_futex["futex_type"] == "schedule", :]
    for _, row in schedule.iterrows():
        waits = row["waits"] 
        wakes = row["wakes"] 
        for tid in [waits, wakes]:
            if tid in G:
                continue
            G.add_node(
                tid,
                label=f"{tid}",
                title=f"-{tid}-",
                color=lighten_color(color_map["tid"], factor=0.35),
                shape="dot",
                size=20,
                font={"size": 12, "multi": "html"},  # enable <br> rendering
            )
        G.add_edge(wakes, waits)

    contention = tid_futex.loc[tid_futex["futex_type"] == "contention", :]    
    for _, row in contention.iterrows():
        waits = row["waits"]
        wakes = row["wakes"]
        futex_key = f'{row["futex_key_addr"]}-{row["futex_key_word"]}-{row["futex_key_offset"]}'

        # Add source and destination nodes with visual info
        for tid in [waits, wakes]:
            if tid in G:
                continue
            G.add_node(
                tid,
                label=f"{tid}",
                title=f"-{tid}-",
                color=lighten_color(color_map["tid"], factor=0.35),
                shape="dot",
                size=20,
                font={"size": 12, "multi": "html"},  # enable <br> rendering
            )

        if futex_key not in G:
            G.add_node(
                futex_key,
                label=f"{futex_key}",
                title=f"-{futex_key}-",
                color=lighten_color(color_map["futex"], factor=0.35),
                shape="dot",
                size=20,
                font={"size": 12, "multi": "html"},  # enable <br> rendering
            )

        G.add_edge(wakes, futex_key, color='rgba(150,150,150,0.6)')#, label=f"{num_connections}")
        G.add_edge(futex_key, waits, color='rgba(150,150,150,0.6)')#, label=f"{num_connections}")

    return G

def lighten_color(hex_color, factor=0.5):
    """Blend the hex color with white. Factor 0.0 = original, 1.0 = white."""
    hex_color = hex_color.lstrip("#")
    rgb = [int(hex_color[i:i+2], 16) for i in (0, 2, 4)]
    light_rgb = [int(c + (255 - c) * factor) for c in rgb]
    return "#{:02x}{:02x}{:02x}".format(*light_rgb)

def write_html(graph: nx.Graph, outfile: Path, launch=True):
    net = Network(height="800px", width="100%", directed=True, bgcolor="#ffffff")
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


if len(sys.argv) != 2: 
    usage = f"Usage: {sys.argv[0]} <duckdb-databse>"
    print(usage)
    sys.exit(0)

db = Path(sys.argv[1])
conn = duckdb.connect(database=db)

tid_futex = conn.execute("""
    WITH 
        fwake AS (
            SELECT DISTINCT
                fwake.pid,
                fwake.tid, 
                'wake' as op,
                fwake.futex_key_addr, 
                fwake.futex_key_word, 
                fwake.futex_key_offset 
            FROM 
                futex_wake as fwake
        ),
        fwait AS (
            SELECT DISTINCT
                fwait.pid,
                fwait.tid, 
                'wait' as op,
                fwait.futex_key_addr, 
                fwait.futex_key_word, 
                fwait.futex_key_offset 
            FROM 
                futex_wait as fwait
        ),
        process_meta AS (
            SELECT DISTINCT
                *
            FROM
                process_context pc
            LEFT JOIN 
                (SELECT DISTINCT pid, comm FROM taskstats_view WHERE pid = tid) as pcomm
                ON pc.pid = pcomm.pid
            LEFT JOIN
                docker dock
                ON dock.cgroup = pc.cgroup
            LEFT JOIN
                k8s
                ON k8s.cgroup = pc.cgroup
        ),
        matched_futexes AS (
            SELECT DISTINCT
                fwait.futex_key_addr,
                fwait.futex_key_word,
                fwait.futex_key_offset
            FROM
                fwait
            LEFT JOIN
                fwake
                ON fwait.futex_key_addr = fwake.futex_key_addr
                AND fwait.futex_key_word = fwake.futex_key_word
                AND fwait.futex_key_offset = fwake.futex_key_offset
            WHERE 
                fwake.tid IS NOT NULL
        ),
        unmatched_waits AS (
            SELECT DISTINCT
                fwait.futex_key_addr,
                fwait.futex_key_word,
                fwait.futex_key_offset
            FROM
                fwait
            LEFT JOIN
                fwake
                ON fwait.futex_key_addr = fwake.futex_key_addr
                AND fwait.futex_key_word = fwake.futex_key_word
                AND fwait.futex_key_offset = fwake.futex_key_offset
            WHERE 
                fwake.tid IS NULL
        ),
        unmatched_wakes AS (
            SELECT DISTINCT
                fwake.futex_key_addr,
                fwake.futex_key_word,
                fwake.futex_key_offset
            FROM 
                fwake
            LEFT JOIN
                fwait
                ON fwake.futex_key_addr = fwait.futex_key_addr
                AND fwake.futex_key_word = fwait.futex_key_word
                AND fwake.futex_key_offset = fwait.futex_key_offset
            WHERE 
                fwait.tid IS NULL
        ),
        contention_futexes AS (
            SELECT
                mf.*
            FROM
                matched_futexes mf
            LEFT JOIN
                fwait 
                ON mf.futex_key_addr = fwait.futex_key_addr
                AND mf.futex_key_word = fwait.futex_key_word
                AND mf.futex_key_offset = fwait.futex_key_offset
            LEFT JOIN
                fwake 
                ON mf.futex_key_addr = fwake.futex_key_addr
                AND mf.futex_key_word = fwake.futex_key_word
                AND mf.futex_key_offset = fwake.futex_key_offset
            WHERE 
                fwait.tid = fwake.tid
        ),
        schedule_futexes AS (
            SELECT * FROM matched_futexes
            EXCEPT ALL 
            SELECT * FROM contention_futexes
        ), 
        futex_by_type AS (
            SELECT DISTINCT *, 'schedule' AS futex_type
            FROM schedule_futexes
            UNION ALL 
            SELECT DISTINCT *, 'contention' AS futex_type
            FROM contention_futexes
        )
    SELECT ft.*, fwait.tid as waits, fwake.tid as wakes
    FROM futex_by_type ft
    LEFT JOIN fwait
        ON ft.futex_key_addr = fwait.futex_key_addr
        AND ft.futex_key_word = fwait.futex_key_word
        AND ft.futex_key_offset = fwait.futex_key_offset
    LEFT JOIN fwake
        ON ft.futex_key_addr = fwake.futex_key_addr
        AND ft.futex_key_word = fwake.futex_key_word
        AND ft.futex_key_offset = fwake.futex_key_offset
    ORDER BY 
        ft.futex_key_addr,
        ft.futex_key_word,
        ft.futex_key_offset,
        waits,
        wakes
""").df()

G = build_graph_with_clusters(tid_futex)
write_html(G, Path("threads.html"))
