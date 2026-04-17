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
            part0
        FROM iowait io
        WHERE {{ pid_filter }}
    ),

    -- Contention and schedule futexes 
    fwake AS (
        SELECT DISTINCT
            fwake.tid, 
            fwake.futex_key_addr, 
            fwake.futex_key_word, 
            fwake.futex_key_offset 
        FROM futex_wake AS fwake
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts_s") }}
    ),
    fwait AS (
        SELECT DISTINCT
            fwait.tid, 
            fwait.futex_key_addr, 
            fwait.futex_key_word, 
            fwait.futex_key_offset 
        FROM futex_wait AS fwait
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts_s") }}
    ),
    all_futexes AS (
        SELECT DISTINCT futex_key_addr, futex_key_word, futex_key_offset
        FROM (
            SELECT futex_key_addr, futex_key_word, futex_key_offset FROM fwait
            UNION
            SELECT futex_key_addr, futex_key_word, futex_key_offset FROM fwake
        ) s
    ),
    contention AS (
        SELECT DISTINCT futex_key_addr, futex_key_word, futex_key_offset
        FROM fwait
        INNER JOIN fwake USING (tid, futex_key_addr, futex_key_word, futex_key_offset)
    ),
    schedule AS (
        SELECT * FROM all_futexes
        EXCEPT ALL
        SELECT * FROM contention
    ),

    -- VFS inodes
    vfs AS (
        SELECT DISTINCT
            lc.const_name as fs_magic, device_id, inode_id
        FROM vfs
        LEFT JOIN linux_consts lc
            ON const_type = 'fs_magic' AND const_name = 'SOCKFS_MAGIC'
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts_s") }}
    ),
    sockets AS (
        SELECT * 
        FROM vfs
        LEFT JOIN socket_context sc
            USING (inode_id)
        WHERE fs_magic = 'SOCKFS_MAGIC'
    ),
    other_vfs AS (
        SELECT fs_magic, device_id, inode_id FROM vfs
        EXCEPT ALL 
        SELECT fs_magic, device_id, inode_id FROM sockets
    )
SELECT 
    'thread' AS node_type, 
    tid AS node_id
FROM threads
UNION ALL
SELECT 
    'disk' AS node_type, 
    part0 AS node_id
FROM disks
UNION ALL
SELECT 
    'futex_contention' AS node_type, 
    futex_key_addr || '-' || futex_key_word || '-' || futex_key_offset AS node_id
FROM contention
UNION ALL
SELECT 
    'futex_schedule' AS node_type, 
    futex_key_addr || '-' || futex_key_word || '-' || futex_key_offset AS node_id
FROM schedule
UNION ALL
SELECT 
    'vfs' AS node_type, 
    fs_magic || '-' || device_id || '-' || inode_id AS node_id
FROM other_vfs
UNION ALL
SELECT 
    'socket' AS node_type, 
    inode_id AS node_id
FROM sockets
