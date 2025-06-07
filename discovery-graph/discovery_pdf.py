import duckdb
from graphviz import Graph

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
        rpids.pid as rpid,
        COALESCE(rk8s.pod_name, rdock.name, rpc.cgroup) as rcgroup,
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
    ORDER BY
        lcgroup
""").df()

nodes = connections.loc[:, ["local_machine_id", "lpid", "lcgroup"]].drop_duplicates()


g = Graph("G")
g.attr(splines="true")

machines = nodes["local_machine_id"].unique()
for machine in machines:
    with g.subgraph(name=f"cluster_{machine}") as machine_group:
        machine_group.attr(style="rounded", color="blue", label=f"{machine}")
        
        machine_nodes = nodes.loc[nodes["local_machine_id"] == machine, :]
        machine_cgroups = machine_nodes["lcgroup"].unique()
        for cgroup in machine_cgroups:
            with machine_group.subgraph(name=f'cluster_{machine}_{cgroup}') as cgroup_group:
                cgroup_group.attr(style="rounded", color="blue", label=f'{cgroup}')

                cgroup_pids = machine_nodes.loc[machine_nodes["lcgroup"] == cgroup, :]
                cgroup_pids = cgroup_pids["lpid"]
                for pid in cgroup_pids: 
                    print(machine, cgroup, pid)
                    cgroup_group.node(f"{machine}-{pid}", label=f"{pid}")

for _, connection in connections.iterrows():
    src = f'{connection["local_machine_id"]}-{connection["lpid"]}'
    dst = f'{connection["remote_machine_id"]}-{connection["rpid"]}'
    g.edge(src, dst)

g.render("graph", format='svg', view=True)
