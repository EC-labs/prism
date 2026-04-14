SELECT DISTINCT
    COALESCE(k.pod_name, d.name, tv.comm) AS service_name,
    COALESCE(pc.machine_id, tv.machine_id) machine_id,
    COALESCE(pc.pid, tv.pid) pid, 
    pc.exe
FROM process_context pc
LEFT JOIN docker d USING (machine_id, cgroup)
LEFT JOIN k8s k USING(machine_id, cgroup)
RIGHT JOIN (
    SELECT DISTINCT machine_id, pid, tid, comm FROM (
        SELECT 
            machine_id, 
            pid,
            tid, 
            comm, 
            ROW_NUMBER() OVER(PARTITION BY machine_id, pid, tid ORDER BY ts DESC) AS rn
        FROM (
            SELECT 
                machine_id, pid, tid, comm, max(ts) AS ts
            FROM taskstats 
            WHERE pid = tid 
            GROUP BY machine_id, pid, tid, comm
        )
    )
    WHERE rn = 1 
) tv 
    ON (pc.pid = tv.pid) and (pc.pid = tv.tid) and (pc.machine_id = tv.machine_id)
