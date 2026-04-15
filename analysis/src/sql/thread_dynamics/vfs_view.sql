WITH
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
            vfs.machine_id AS machine_id, pid, tid, op, fs_magic, fs_desc.const_name as fs_desc, device_id, vfs.inode_id
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
                WHEN protocol_desc = 'IPPROTO_UDP' THEN 'inet-udp-' || src_address || '-' || dst_address
                ELSE 'inet-unknown' || src_address || ':' || src_port || '-' || dst_address || ':' || dst_port
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
    ),
    -- VFS resources other than AF_INET[6] and AF_UNIX sockets
    other_inodes AS (
        SELECT DISTINCT
            vfs.machine_id, vfs.fs_magic, lc.const_name AS 'fs_desc', vfs.device_id, vfs.inode_id
        FROM vfs
        LEFT JOIN linux_consts lc
            ON lc.const_type = 'fs_magic' AND vfs.fs_magic = lc.value
        -- AF_UNIX and AF_INET sockets
        LEFT JOIN
        (
            SELECT machine_id, inode_id
            FROM sockets_inet
            UNION ALL
            SELECT machine_id, inode_id
            FROM sockets_unix
        ) sin ON lc.const_name = 'SOCKFS_MAGIC' AND vfs.machine_id = sin.machine_id AND vfs.inode_id = sin.inode_id
        WHERE
            vfs.machine_id = {{ machine_id }}
            AND vfs.pid = {{ pid }}
            AND {{ compare_filter("vfs.ts_s") }}
            AND (sin.machine_id IS NULL AND sin.inode_id IS NULL)
    )
SELECT ts, tid, SUM(total_time)/1e9 AS total_time
FROM (
    SELECT date_trunc('second', ts_s) AS ts, tid, total_time
    FROM other_inodes
    INNER JOIN vfs USING (machine_id, fs_magic, device_id, inode_id)
    WHERE '{{ inode }}' = 'vfs-' || vfs.device_id || '-' || vfs.inode_id
        AND pid = {{ pid }} AND machine_id = {{ machine_id }}
)
GROUP BY ts, tid
ORDER BY ts, tid
