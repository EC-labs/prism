Get completed circuit tcp sockets:
```sql
SELECT 
    hex(local_machine_id),
    local_inode_id,
    hex(remote_machine_id),
    remote_inode_id,
FROM 
    tcp_discovery
WHERE
    remote_machine_id <> 0
    AND remote_inode_id <> 0;
```

Get pids that wrote to sockets:
```sql
SELECT 
    DISTINCT pid, 
    inode_id 
FROM 
    vfs
WHERE 
    fs_magic = 1397703499;
```

Get the local processes that wrote to sockets:
```
WITH 
    local_sockets AS (
        SELECT 
            local_machine_id,
            local_inode_id,
            remote_machine_id,
            remote_inode_id,
        FROM 
            tcp_discovery
        WHERE
            remote_machine_id <> 0
            AND remote_inode_id <> 0
    ),
    pid_socks AS (
        SELECT 
            DISTINCT pid, 
            inode_id 
        FROM 
            vfs
        WHERE 
            fs_magic = 1397703499
    )
SELECT DISTINCT
    --ls.local_machine_id,
    lp.pid, 
    --ls.local_inode_id,
FROM
    local_sockets ls
LEFT JOIN
    pid_socks lp /* lp = local pid */
    ON ls.local_inode_id = lp.inode_id
```


```sql
WITH 
    complete_socks AS (
        SELECT 
            local_machine_id,
            local_inode_id,
            remote_machine_id,
            remote_inode_id
        FROM 
            tcp_discovery
        WHERE
            remote_machine_id <> 0
            AND remote_inode_id <> 0
    ),
    pid_socks AS (
        SELECT 
            DISTINCT pid, 
            inode_id 
        FROM 
            vfs
        WHERE 
            fs_magic = 1397703499
    )
SELECT
    ps.pid,
    cs.remote_machine_id,
    cs.remote_inode_id
FROM 
    complete_socks cs
LEFT JOIN
    pid_socks ps
    ON ps.inode_id = cs.local_inode_id
WHERE 
    cs.remote_machine_id <> cs.local_machine_id
```


What are the processes communicating with one another between 2 machines (gijs2, gijs3)?
```sql
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
    num_connections
```

Search for connections that don't have a matching recv event:
```sql
SELECT DISTINCT
    *
FROM 
    tcp_discovery send
LEFT JOIN
    tcp_discovery recv
    ON recv.remote_inode_id <> 0
    AND send.remote_inode_id = 0 
    AND send.local_inode_id = recv.local_inode_id 
WHERE 
    send.remote_inode_id = 0
    AND recv.remote_inode_id IS NULL
```

Get the addresses of the sockets that we don't have a matching receive discovery event:
```sql
WITH 
    missing_recv AS (
        SELECT DISTINCT
            *
        FROM 
            tcp_discovery send
        LEFT JOIN
            tcp_discovery recv
            ON recv.remote_inode_id <> 0
            AND send.remote_inode_id = 0 
            AND send.local_inode_id = recv.local_inode_id 
        WHERE 
            send.remote_inode_id = 0
            AND recv.remote_inode_id IS NULL
    )
SELECT 
    si.*
FROM
    missing_recv rcv
LEFT JOIN
    socket_inet si
    ON rcv.local_inode_id = si.inode_id
```

How many sockets have we performed vfs operations on that we haven't sent out or received tcp_discovery events for? 
```sql
SELECT DISTINCT
    si.*,
    td.local_inode_id
FROM 
    vfs
LEFT JOIN
    socket_context sc
    ON sc.inode_id = vfs.inode_id
LEFT JOIN
    socket_inet si
    ON sc.family IN (2, 10) AND sc.inode_id = si.inode_id
LEFT JOIN
    tcp_discovery td
    ON si.inode_id = td.local_inode_id
WHERE 
    fs_magic = 1397703499
    AND td.local_inode_id IS NULL
    AND sc.protocol = 6
```

How many sockets have we received events for that we haven't performed any vfs operations on?
```sql
SELECT DISTINCT
    td.*
FROM 
    tcp_discovery td
LEFT JOIN
    vfs
    ON vfs.inode_id = td.local_inode_id 
    AND vfs.fs_magic = 1397703499
WHERE 
    vfs.inode_id IS NULL;
```

```sql
WITH 
    tasks AS (
        SELECT DISTINCT
            pc.*
        FROM
            process_context pc
        LEFT JOIN
            docker dock
            ON dock.cgroup = pc.cgroup
        LEFT JOIN
            k8s
            ON k8s.cgroup = pc.cgroup
        WHERE 
            pc.argv LIKE '%example%'
    ),
    fwait AS (
        SELECT DISTINCT
            fwait.tid, 
            'wait' as op,
            fwait.futex_key_addr, 
            fwait.futex_key_word, 
            fwait.futex_key_offset 
        FROM 
            tasks
        LEFT JOIN
            futex_wait as fwait
            ON tasks.tid = fwait.tid
        WHERE 
            fwait.tid IS NOT NULL
    ),
    fwake AS (
        SELECT DISTINCT
            fwake.tid, 
            'wake' as op,
            fwake.futex_key_addr, 
            fwake.futex_key_word, 
            fwake.futex_key_offset 
        FROM 
            tasks
        LEFT JOIN
            futex_wake as fwake
            ON tasks.tid = fwake.tid
        WHERE 
            fwake.tid IS NOT NULL
    )
SELECT DISTINCT 
    *
FROM (
    SELECT * FROM fwake
    UNION ALL 
    SELECT * FROM fwait
)
ORDER BY 
    futex_key_addr, 
    futex_key_word, 
    futex_key_offset
```

```sql
WITH 
    futex AS (
        SELECT DISTINCT
            fwake.pid,
            fwake.tid, 
            'wake' as op,
            fwake.futex_key_addr, 
            fwake.futex_key_word, 
            fwake.futex_key_offset 
        FROM 
            futex_wake as fwake
        UNION ALL 
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
            docker dock
            ON dock.cgroup = pc.cgroup
        LEFT JOIN
            k8s
            ON k8s.cgroup = pc.cgroup
    )
SELECT
    pm.argv, f.*
FROM 
    process_meta pm
LEFT JOIN
    futex f
    ON pm.pid = f.pid
WHERE 
    pm.argv LIKE '%mysqld%' 
ORDER BY
    futex_key_addr, 
    futex_key_word,
    futex_key_offset,
    op,
    f.tid
```


```sql
WITH 
    fwake AS (
        SELECT DISTINCT
            fwake.pid,
            fwake.tid, 
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
    )
SELECT 
    fw.futex_key_addr,
    fw.futex_key_word,
    fw.futex_key_offset,
    SUM(successful_count) as successful_count
FROM
    unmatched_wakes uw
LEFT JOIN 
    futex_wake fw
    ON uw.futex_key_addr = fw.futex_key_addr
    AND uw.futex_key_word = fw.futex_key_word
    AND uw.futex_key_offset = fw.futex_key_offset
GROUP BY
    fw.futex_key_addr,
    fw.futex_key_word,
    fw.futex_key_offset
ORDER BY 
    successful_count
```

```sql
WITH 
    fwake AS (
        SELECT DISTINCT
            fwake.pid,
            fwake.tid, 
            "wake" as op,
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
            "wait" as op,
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
    )
SELECT 
    mf.*, fwait.tid as waits, fwake.tid as wakes
FROM 
    matched_futexes mf
LEFT JOIN
    fwait
    ON fwait.futex_key_addr = mf.futex_key_addr
    AND fwait.futex_key_word = mf.futex_key_word
    AND fwait.futex_key_offset = mf.futex_key_offset
LEFT JOIN
    fwake
    ON fwake.futex_key_addr = mf.futex_key_addr
    AND fwake.futex_key_word = mf.futex_key_word
    AND fwake.futex_key_offset = mf.futex_key_offset
ORDER BY 
    mf.futex_key_addr,
    mf.futex_key_word,
    mf.futex_key_offset,
    waits, 
    wakes
```

```sql
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
    )
SELECT DISTINCT * FROM (
    SELECT * FROM fwait
    UNION ALL
    SELECT * FROM fwake
)
ORDER BY futex_key_addr, futex_key_word, futex_key_offset, pid, tid, op
```

```sql
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
        SELECT *, 'schedule' AS futex_type
        FROM schedule_futexes
        UNION ALL 
        SELECT *, 'contention' AS futex_type
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
```
