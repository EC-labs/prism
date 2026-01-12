WITH 
  pid_sock AS (
    SELECT DISTINCT machine_id, pid, inode_id
    FROM vfs 
    LEFT JOIN linux_consts lc ON vfs.fs_magic = lc.value and lc.const_type = 'fs_magic'
    WHERE lc.const_name = 'SOCKFS_MAGIC'
        AND {{vfs_ts_filter}}
  ),
  unix_sock_map AS (
    SELECT DISTINCT 
        machine_id,
        LEAST(sock1_inode_id, sock2_inode_id) sock1, 
        GREATEST(sock1_inode_id, sock2_inode_id) sock2
    FROM socket_map
  ),
  -- enhance socket map data with information on the pids interacting with the socket
  unix_sock_pids AS (
    SELECT DISTINCT
      us.machine_id lmachine,
      lusp.pid lpid,
      us.sock1 lsock,
      us.machine_id rmachine,
      rusp.pid rpid,
      us.sock2 rsock
    FROM unix_sock_map us
    INNER JOIN pid_sock lusp -- left unix socket pid
      ON us.machine_id = lusp.machine_id AND us.sock1 = lusp.inode_id
    INNER JOIN pid_sock rusp -- right unix socket pid
      ON us.machine_id = rusp.machine_id AND us.sock2 = rusp.inode_id
    WHERE lpid IS NOT NULL AND rpid IS NOT NULL
  ),
  -- get the number of unix connections between 2 pids
  pid_map_unix_connections AS (
    SELECT
        CASE WHEN (lmachine, lpid) <= (rmachine, rpid) THEN lmachine ELSE rmachine END AS machine1,
        CASE WHEN (lmachine, lpid) <= (rmachine, rpid) THEN lpid     ELSE rpid     END AS pid1,
        CASE WHEN (lmachine, lpid) >  (rmachine, rpid) THEN lmachine ELSE rmachine END AS machine2,
        CASE WHEN (lmachine, lpid) >  (rmachine, rpid) THEN lpid     ELSE rpid     END AS pid2,
        COUNT(*) connections
    FROM unix_sock_pids
    GROUP BY 1,2,3,4
  ),

  tcp_sock_map AS (
      SELECT DISTINCT
        CASE WHEN (local_machine_id, local_inode_id) <= (remote_machine_id, remote_inode_id) THEN local_machine_id ELSE remote_machine_id END AS machine1,
        CASE WHEN (local_machine_id, local_inode_id) <= (remote_machine_id, remote_inode_id) THEN local_inode_id   ELSE remote_inode_id   END AS sock1,
        CASE WHEN (local_machine_id, local_inode_id) > (remote_machine_id, remote_inode_id)  THEN local_machine_id ELSE remote_machine_id END AS machine2,
        CASE WHEN (local_machine_id, local_inode_id) > (remote_machine_id, remote_inode_id)  THEN local_inode_id   ELSE remote_inode_id   END AS sock2,
      FROM tcp_discovery
      WHERE remote_machine_id <> 0
  ),
  -- enhance tcp socket map data with information on the pids interacting with the socket
  tcp_sock_pids AS (
    SELECT 
      ts.machine1 lmachine, pid1.pid lpid, ts.sock1, 
      ts.machine2 rmachine, pid2.pid rpid, ts.sock2 
    FROM tcp_sock_map ts
    INNER JOIN pid_sock pid1 ON ts.machine1 = pid1.machine_id and ts.sock1 = pid1.inode_id
    INNER JOIN pid_sock pid2 ON ts.machine2 = pid2.machine_id and ts.sock2 = pid2.inode_id
  ),
  -- get the number of tcp connections between 2 pids
  pid_map_tcp_connections AS (
    SELECT
        CASE WHEN (lmachine, lpid) <= (rmachine, rpid) THEN lmachine ELSE rmachine END AS machine1,
        CASE WHEN (lmachine, lpid) <= (rmachine, rpid) THEN lpid     ELSE rpid     END AS pid1,
        CASE WHEN (lmachine, lpid) >  (rmachine, rpid) THEN lmachine ELSE rmachine END AS machine2,
        CASE WHEN (lmachine, lpid) >  (rmachine, rpid) THEN lpid     ELSE rpid     END AS pid2,
        COUNT(*) connections
    FROM tcp_sock_pids
    GROUP BY 1,2,3,4
  ),

  pid_pipe AS (
    SELECT DISTINCT vfs.machine_id, vfs.pid, vfs.inode_id, lcf.const_name as fs_magic_desc 
    FROM vfs
    LEFT JOIN linux_consts lcf ON lcf.const_type = 'fs_magic' AND lcf.value = vfs.fs_magic
    WHERE fs_magic_desc = 'PIPEFS_MAGIC'
        AND {{ vfs_ts_filter }}
    ORDER BY vfs.inode_id
  ),
  -- get the pids interacting via the same pipe
  pid_map_pipe_connections AS (
    SELECT lpp.machine_id machine1, lpp.pid pid1, rpp.machine_id machine2, rpp.pid pid2, COUNT(*) connections
    FROM pid_pipe lpp
    LEFT JOIN pid_pipe rpp 
      ON lpp.machine_id = rpp.machine_id AND lpp.inode_id = rpp.inode_id AND lpp.pid <> rpp.pid
    WHERE rpp.pid IS NOT NULL
    GROUP BY 1, 2, 3, 4
  ),

  pid_connections AS (
    SELECT *, 'tcp' as connection_type FROM pid_map_tcp_connections
    UNION 
    SELECT *, 'unix' as connection_type FROM pid_map_unix_connections
    UNION
    SELECT *, 'pipe' as connection_type FROM pid_map_pipe_connections
  ),
  service_context AS (
    SELECT DISTINCT
        COALESCE(k.pod_name, d.name, tv.comm) AS service_name,
        COALESCE(pc.machine_id, tv.machine_id) machine_id,
        COALESCE(pc.pid, tv.pid) pid, 
        pc.exe
    FROM process_context pc
    LEFT JOIN docker d USING (machine_id, cgroup)
    LEFT JOIN k8s k USING(machine_id, cgroup)
    RIGHT JOIN 
        (SELECT DISTINCT machine_id, pid, tid, comm from taskstats where pid = tid) tv 
        ON (pc.pid = tv.pid) and (pc.pid = tv.tid) and (pc.machine_id = tv.machine_id)
  ),
  -- pids that do not have any connections to other processes
  unconnected_pids AS (
    SELECT machine_id, pid, sc.service_name
    FROM service_context sc
    LEFT JOIN pid_connections pc ON (sc.machine_id = pc.machine1 AND sc.pid = pc.pid1) OR (sc.machine_id = pc.machine2 and sc.pid = pc.pid2)
    WHERE pc.connections IS NULL
  ),
  -- tcp connections without successful discovery
  missing_discovery AS (
    SELECT 
      ps.machine_id, 
      ps.pid, 
      ps.inode_id, 
      si.dst_address, 
      si.dst_port
    FROM pid_sock ps
    LEFT JOIN socket_context sc ON sc.machine_id = ps.machine_id and sc.inode_id = ps.inode_id
    LEFT JOIN linux_consts proto -- socket protocol context
      ON sc.protocol = proto.value AND proto.const_type = 'family_protocol'
    LEFT JOIN tcp_sock_map tsm ON (ps.machine_id = tsm.machine1 AND ps.inode_id = tsm.sock1) OR (ps.machine_id = tsm.machine2 AND ps.inode_id = tsm.sock2)
    LEFT JOIN socket_inet si ON si.machine_id = ps.machine_id and si.inode_id = ps.inode_id
    WHERE 
      proto.const_name = 'IPPROTO_TCP' AND tsm.machine1 IS NULL AND (si.dst_port <> 0)
  )

SELECT 
    machine1, pid1, lsvc.service_name service1, 
    machine2, pid2, rsvc.service_name service2,
    SUM(pc.connections) as connections
FROM pid_connections pc
LEFT JOIN service_context lsvc
    ON lsvc.machine_id = pc.machine1 AND lsvc.pid = pc.pid1
LEFT JOIN service_context rsvc
    ON rsvc.machine_id = pc.machine2 AND rsvc.pid = pc.pid2
GROUP BY
    machine1, pid1, service1, 
    machine2, pid2, service2,
