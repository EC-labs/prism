SELECT *
FROM (
    SELECT DISTINCT
        COALESCE(pc.machine_id, tv.machine_id) machine_id,
        COALESCE(pc.pid, tv.pid) pid, 
        tv.comm,
        pc.exe AS process_exe, 
        pc.argv AS process_argv, 
        pc.cgroup AS process_cgroup,
        k.id AS k8s_id, 
        k.namespace AS k8s_namespace, 
        k.pod_name AS k8s_pod_name, 
        k.container_name AS k8s_container_name, 
        k.image_name AS k8s_image, 
        d.id AS docker_id, 
        d.name AS docker_name, 
        d.image_name AS docker_image, 
        d.image_hash AS docker_hash
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
)
WHERE '{{ ext }}' = 'ext-' || machine_id || '-' || pid
