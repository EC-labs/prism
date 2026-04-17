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
    )
SELECT 
    ts, 
    tid, 
    SUM(total_time)/1e9 AS total_time
FROM (
    SELECT 
        date_trunc('second', ts_s) AS ts, machine_id, pid, tid, inode_id, total_time
    FROM inet_mapping_vinet imv
    INNER JOIN vfs
        ON vfs.machine_id = imv.local_machine_id AND vfs.pid = imv.local_pid AND vfs.inode_id = imv.local_inode_id
    LEFT JOIN linux_consts sockfs_desc
        ON vfs.fs_magic = sockfs_desc.value AND sockfs_desc.const_type = 'fs_magic' AND sockfs_desc.const_name = 'SOCKFS_MAGIC'
    WHERE vinet = {{ vinet }} 
        AND sockfs_desc.const_name IS NOT NULL
)
GROUP BY ts, tid
ORDER BY ts, tid
