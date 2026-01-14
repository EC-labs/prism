SELECT DISTINCT
    COALESCE(k.pod_name, d.name, tv.comm) AS service_name,
    pc.machine_id,
    pc.pid, 
    pc.exe
FROM process_context pc
LEFT JOIN docker d USING (machine_id, cgroup)
LEFT JOIN k8s k USING(machine_id, cgroup)
LEFT JOIN 
    (SELECT DISTINCT machine_id, pid, tid, comm from taskstats_view where pid = tid) tv 
    ON (pc.pid = tv.pid) and (pc.pid = tv.tid) and (pc.machine_id = tv.machine_id)
