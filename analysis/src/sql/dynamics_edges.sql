WITH 
    threads AS (
        SELECT 
            tid,
            LAST(comm ORDER BY ts) AS comm,
            MAX(ts) AS max_ts,
            MIN(ts) AS min_ts
        FROM taskstats_view
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts") }}
        GROUP BY tid
    ),
    disks AS (
        SELECT DISTINCT
            tid, part0
        FROM iowait io
        WHERE {{ pid_filter }}
    ),

    -- Contention and schedule futexes 
    fwake_ AS (
        SELECT DISTINCT
            tid, 
            futex_key_addr || '-' || futex_key_word || '-' || futex_key_offset AS fkey
        FROM futex_wake
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts_s") }}
    ),
    fwait_ AS (
        SELECT DISTINCT
            tid, 
            futex_key_addr || '-' || futex_key_word || '-' || futex_key_offset AS fkey
        FROM futex_wait
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts_s") }}
    ),
    fkey_signature AS (
        SELECT 
            fkey,
            STRING_AGG(tid || ':' || op, ',' ORDER BY tid, op) AS signature
        FROM (
            SELECT  
                fkey,
                tid,
                'wait' as op
            FROM fwait_
            UNION ALL
            SELECT  
                fkey,
                tid,
                'wake'
            FROM fwake_
        )
        GROUP BY fkey
    ),
    signature_id AS (
        SELECT 
            ROW_NUMBER() OVER (ORDER BY signature) AS vfkey, 
            signature
        FROM fkey_signature
        GROUP BY signature
    ),
    fwait AS (
        SELECT DISTINCT tid, vfkey 
        FROM fwait_
        LEFT JOIN fkey_signature USING (fkey)
        LEFT JOIN signature_id USING (signature)
    ),
    fwake AS (
        SELECT DISTINCT tid, vfkey 
        FROM fwake_
        LEFT JOIN fkey_signature USING (fkey)
        LEFT JOIN signature_id USING (signature)
    ),
    all_futexes AS (
        SELECT DISTINCT vfkey
        FROM (
            SELECT vfkey FROM fwait
            UNION
            SELECT vfkey FROM fwake
        )
    ),
    contention AS (
        SELECT DISTINCT vfkey
        FROM fwait
        INNER JOIN fwake USING (tid, vfkey)
    ),
    schedule AS (
        SELECT * FROM all_futexes
        EXCEPT ALL
        SELECT * FROM contention
    ),
    direct_schedulers AS (
        SELECT vfkey, COUNTIF(type = 'wait') AS waiters, COUNTIF(type = 'wake') AS wakers
        FROM (
            SELECT  
                fwait.*, 'wait' AS type
            FROM fwait
            INNER JOIN schedule USING (vfkey)
            UNION ALL 
            SELECT 
                fwake.*, 'wake' AS type
            FROM fwake
            INNER JOIN schedule USING (vfkey)
        )
        GROUP BY vfkey
        HAVING waiters = 1 AND wakers = 1
    ),

    -- SOCKETS
    socket_context_ AS (
        SELECT sc.machine_id AS machine_id, sc.inode_id, fdesc.const_name as family_desc, tdesc.const_name as type_desc, pdesc.const_name as protocol_desc 
        FROM socket_context sc
        LEFT JOIN linux_consts fdesc
            ON fdesc.const_type = 'socket_family' AND fdesc.value = sc.family
        LEFT JOIN linux_consts tdesc
            ON tdesc.const_type = 'socket_type' AND tdesc.value = sc.type
        LEFT JOIN linux_consts pdesc
            ON pdesc.const_type = 'family_protocol' AND pdesc.value = sc.protocol
    ),
    sockets_vfs AS (
        SELECT DISTINCT
            vfs.machine_id AS machine_id, pid, tid, op, fs_desc.const_name as fs_desc, device_id, vfs.inode_id
        FROM vfs
        LEFT JOIN linux_consts fs_desc
            ON fs_desc.const_type = 'fs_magic' AND fs_desc.value = vfs.fs_magic
        WHERE {{ compare_filter("ts_s") }}
    ),
    -- AF_INET[6] sockets
    sockets_inet AS (
        SELECT DISTINCT
            svfs.machine_id, svfs.pid, svfs.inode_id, family_desc, protocol_desc
        FROM sockets_vfs svfs
        LEFT JOIN socket_context_ sc
            ON sc.machine_id = svfs.machine_id AND sc.inode_id = svfs.inode_id AND svfs.fs_desc = 'SOCKFS_MAGIC'
        WHERE sc.machine_id = {{ machine_id }} AND svfs.pid = {{ pid }}
            AND family_desc LIKE 'AF_INET%'       
    ),
    inet_mapping AS (
        SELECT 
            si.machine_id AS local_machine_id, 
            si.pid AS local_pid, 
            si.inode_id AS local_inode_id, 
            td.remote_machine_id, 
            rpid.pid as remote_pid, 
            td.remote_inode_id, 
            si.family_desc,
            si.protocol_desc,
            sic.src_address, 
            sic.src_port, 
            sic.dst_address,
            sic.dst_port,
            CASE 
                WHEN protocol_desc = 'IPPROTO_TCP' THEN
                    CASE 
                        WHEN local_pid = remote_pid THEN 'inet-tcp-internal-' || local_inode_id || '-' || remote_inode_id
                        WHEN remote_pid IS NOT NULL THEN 'inet-tcp-mapped-' || remote_pid
                    WHEN dst_address NOT IN ('0', '::') THEN 'inet-tcp-unmapped-' || dst_address
                        ELSE 'inet-tcp-listen-' || src_address || '-' || src_port
                    END
                WHEN protocol_desc = 'IPPROTO_UDP' THEN 'inet-udp-' || src_address || ':' || src_port || '-' || dst_address || ':' || dst_port
                ELSE 'inet-' || src_address || ':' || src_port || '-' || dst_address || ':' || dst_port
            END AS signature
        FROM sockets_inet si
        LEFT JOIN (SELECT * FROM tcp_discovery WHERE remote_machine_id <> 0 AND remote_inode_id <> 0) td
            ON si.machine_id = td.local_machine_id AND si.inode_id = td.local_inode_id
        LEFT JOIN (SELECT DISTINCT machine_id, pid, inode_id FROM vfs WHERE {{ compare_filter("ts_s") }}) rpid
            ON td.remote_machine_id = rpid.machine_id AND td.remote_inode_id = rpid.inode_id 
        LEFT JOIN socket_inet sic
            ON si.machine_id = sic.machine_id AND si.inode_id = sic.inode_id
    ),
    signature_vinet AS (
        SELECT 
            signature, 
            ROW_NUMBER() OVER (ORDER BY signature) AS vinet
        FROM inet_mapping
        GROUP BY signature
    ),
    inet_mapping_vinet AS (
        SELECT * 
        FROM inet_mapping im
        LEFT JOIN signature_vinet sv
            USING (signature)
    ),
    -- AF_UNIX sockets
    sockets_unix AS (
        SELECT DISTINCT
            svfs.machine_id, svfs.pid, svfs.inode_id, family_desc, protocol_desc
        FROM sockets_vfs svfs
        LEFT JOIN socket_context_ sc
            ON sc.machine_id = svfs.machine_id AND sc.inode_id = svfs.inode_id AND svfs.fs_desc = 'SOCKFS_MAGIC'
        WHERE sc.machine_id = {{ machine_id }} AND svfs.pid = {{ pid }}
            AND family_desc LIKE 'AF_UNIX%'       
    ),
    unix_mapping AS (
        SELECT 
            su.machine_id AS local_machine_id, 
            su.pid AS local_pid, 
            su.inode_id AS local_inode_id, 
            sm.sock2_inode_id AS remote_inode_id,
            sv.pid AS remote_pid,
            CASE
                WHEN remote_pid IS NOT NULL THEN 'unix-mapped-' || remote_pid
                ELSE 'unix-unmapped-' || local_inode_id
            END AS signature
        FROM sockets_unix su
        LEFT JOIN socket_map sm
            ON su.machine_id = sm.machine_id AND su.inode_id = sm.sock1_inode_id
        LEFT JOIN (SELECT DISTINCT machine_id, pid, inode_id FROM sockets_vfs) sv
            ON su.machine_id = sv.machine_id AND sm.sock2_inode_id = sv.inode_id
    ),
    signature_vunix AS (
        SELECT 
            signature, 
            ROW_NUMBER() OVER (ORDER BY signature) AS vunix
        FROM unix_mapping
        GROUP BY signature
    ),
    unix_mapping_vunix AS (
        SELECT * 
        FROM unix_mapping um
        LEFT JOIN signature_vunix sv
            USING (signature)
    )

    -- -- VFS inodes
    -- vfs AS (
    --     SELECT DISTINCT
    --         tid, op, lc.const_name as fs_desc, device_id, inode_id
    --     FROM vfs
    --     LEFT JOIN linux_consts lc
    --         ON const_type = 'fs_magic' AND lc.value = vfs.fs_magic
    --     WHERE {{ pid_filter }}
    --         AND {{ compare_filter("ts_s") }}
    -- ),
    -- sockets AS (
    --     SELECT DISTINCT
    --         fs_desc, device_id, inode_id
    --     FROM vfs
    --     LEFT JOIN socket_context sc
    --         USING (inode_id)
    --     WHERE fs_desc = 'SOCKFS_MAGIC'
    -- ),
    -- other_vfs AS (
    --     SELECT DISTINCT fs_desc, device_id, inode_id FROM vfs
    --     EXCEPT ALL 
    --     SELECT DISTINCT fs_desc, device_id, inode_id FROM sockets
    -- )

-- disk
SELECT  
    'thread-' || tid AS source,
    'disk-' || part0 AS target,
    'undirected' as edge_type
FROM disks

UNION ALL

-- contention
SELECT  
    'contention-' || vfkey AS source,
    'thread-' || tid AS target,
    'directed' as edge_type
FROM fwait
INNER JOIN contention USING (vfkey)
UNION ALL
SELECT  
    'thread-' || tid AS source,
    'contention-' || vfkey AS target,
    'directed' as edge_type
FROM fwake
INNER JOIN contention USING (vfkey)

UNION ALL

-- futex schedule
-- direct scheduling (futex is used by a single waker and single waiter)
SELECT 
    'thread-' || fwake.tid AS source,
    'thread-' || fwait.tid AS target, 
    'directed' 
FROM fwait
INNER JOIN direct_schedulers USING (vfkey)
INNER JOIN fwake USING (vfkey)

UNION ALL

SELECT  
    'schedule-' || vfkey AS source,
    'thread-' || tid AS target,
    'directed' as edge_type
FROM fwait
INNER JOIN schedule USING (vfkey)
LEFT JOIN direct_schedulers direct USING (vfkey)
WHERE direct.vfkey IS NULL
UNION ALL
SELECT  
    'thread-' || tid AS source,
    'schedule-' || vfkey AS target,
    'directed' as edge_type
FROM fwake
INNER JOIN schedule USING (vfkey)
LEFT JOIN direct_schedulers direct USING (vfkey)
WHERE direct.vfkey IS NULL

UNION ALL

-- AF_INET sockets
SELECT DISTINCT 
    'inet-' || vinet AS source, 
    'thread-' || tid AS target,
    'directed' AS edge_type
FROM sockets_vfs v
INNER JOIN inet_mapping_vinet im
    ON v.machine_id = im.local_machine_id AND v.pid = im.local_pid AND v.inode_id = im.local_inode_id
WHERE pid = {{ pid }}
    AND machine_id = {{ machine_id }}
    AND op = 0 OR op = 2 -- read and listen

UNION ALL

SELECT DISTINCT 
    'thread-' || tid AS source,
    'inet-' || vinet AS target, 
    'directed' AS edge_type
FROM sockets_vfs v
INNER JOIN inet_mapping_vinet im
    ON v.machine_id = im.local_machine_id AND v.pid = im.local_pid AND v.inode_id = im.local_inode_id
WHERE pid = {{ pid }}
    AND machine_id = {{ machine_id }}
    AND op = 1

UNION ALL

SELECT DISTINCT 
    'inet-' || LEAST(s.vinet, t.vinet) AS source, 
    'inet-' || GREATEST(s.vinet, t.vinet) AS target,
    'undirected' AS edge_type
FROM inet_mapping_vinet s
INNER JOIN inet_mapping_vinet t
    ON s.local_machine_id = t.remote_machine_id AND s.local_inode_id = t.remote_inode_id

UNION ALL

SELECT DISTINCT
    'inet-' || vinet AS source,
    'ext-' || remote_machine_id || '-' || remote_pid AS target,
    'undirected' AS edge_type
FROM inet_mapping_vinet s
WHERE local_machine_id <> remote_machine_id OR local_pid <> remote_pid

UNION ALL

SELECT DISTINCT
    'inet-' || vinet AS source,
    'ext-' || dst_address AS target,
    'undirected' AS edge_type
FROM inet_mapping_vinet s
WHERE 
remote_pid IS NULL AND dst_address NOT IN ('0', '::') AND protocol_desc = 'IPPROTO_TCP'

UNION ALL 

-- AF_UNIX sockets
SELECT DISTINCT 
    'unix-' || vunix AS source, 
    'thread-' || tid AS target,
    'directed' AS edge_type
FROM sockets_vfs v
INNER JOIN unix_mapping_vunix um
    ON v.machine_id = um.local_machine_id AND v.pid = um.local_pid AND v.inode_id = um.local_inode_id
WHERE pid = {{ pid }}
    AND machine_id = {{ machine_id }}
    AND op = 0 OR op = 2 -- read and listen

UNION ALL 

SELECT DISTINCT 
    'thread-' || tid AS source,
    'unix-' || vunix AS target, 
    'directed' AS edge_type
FROM sockets_vfs v
INNER JOIN unix_mapping_vunix um
    ON v.machine_id = um.local_machine_id AND v.pid = um.local_pid AND v.inode_id = um.local_inode_id
WHERE pid = {{ pid }}
    AND machine_id = {{ machine_id }}
    AND op = 1

UNION ALL 

SELECT DISTINCT 
    'unix-' || s.vunix AS source,
    'unix-' || t.vunix AS target, 
    'undirected' AS edge_type
FROM unix_mapping_vunix s
INNER JOIN unix_mapping_vunix t
    ON s.local_machine_id = t.local_machine_id AND s.remote_inode_id = t.local_inode_id
WHERE s.local_pid = s.remote_pid

UNION ALL

SELECT DISTINCT
    'unix-' || vunix AS source,
    'ext-' || local_machine_id || '-' || remote_pid AS target, 
    'undirected' AS edge_type
FROM unix_mapping_vunix
WHERE local_pid <> remote_pid

-- -- sockets
-- SELECT 
--     'socket-' || v.inode_id AS source,
--     'thread-' || v.tid AS target,
--     'directed' AS edge_type
-- FROM vfs v
-- INNER JOIN sockets s
--     ON s.inode_id = v.inode_id AND v.fs_desc = s.fs_desc
-- WHERE op = 0 -- READ
-- UNION ALL
-- SELECT 
--     'thread-' || v.tid AS source,
--     'socket-' || v.inode_id AS target,
--     'directed' AS edge_type
-- FROM vfs v
-- INNER JOIN sockets s
--     ON s.inode_id = v.inode_id AND v.fs_desc = s.fs_desc
-- WHERE op = 1 -- WRITE

-- UNION ALL

-- -- other vfs
-- SELECT 
--     'vfs-' || v.inode_id AS source,
--     'thread-' || v.tid AS target,
--     'directed' AS edge_type
-- FROM vfs v
-- INNER JOIN other_vfs o
--     ON o.inode_id = v.inode_id AND v.fs_desc = o.fs_desc
-- WHERE op = 0 -- READ
-- UNION ALL
-- SELECT 
--     'thread-' || v.tid AS source,
--     'vfs-' || v.inode_id AS target,
--     'directed' AS edge_type
-- FROM vfs v
-- INNER JOIN other_vfs o
--     ON o.inode_id = v.inode_id AND v.fs_desc = o.fs_desc
-- WHERE op = 1 -- WRITE
