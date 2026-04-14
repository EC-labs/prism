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
SELECT ts, tid, SUM(total_time)/1e9 AS total_time
FROM (
    SELECT 
        date_trunc('second', ts_s) AS ts, machine_id, pid, tid, inode_id, total_time
    FROM unix_mapping_vunix imv
    INNER JOIN vfs
        ON vfs.machine_id = imv.local_machine_id AND vfs.pid = imv.local_pid AND vfs.inode_id = imv.local_inode_id
    LEFT JOIN linux_consts sockfs_desc
        ON vfs.fs_magic = sockfs_desc.value AND sockfs_desc.const_type = 'fs_magic' AND sockfs_desc.const_name = 'SOCKFS_MAGIC'
    WHERE vunix = {{ vunix }} 
        AND sockfs_desc.const_name IS NOT NULL
)
GROUP BY ts, tid
ORDER BY ts, tid
