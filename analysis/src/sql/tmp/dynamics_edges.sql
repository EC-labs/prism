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

    -- VFS inodes
    vfs AS (
        SELECT DISTINCT
            tid, op, lc.const_name as fs_desc, device_id, inode_id
        FROM vfs
        LEFT JOIN linux_consts lc
            ON const_type = 'fs_magic' AND const_name = 'SOCKFS_MAGIC'
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts_s") }}
    ),
    sockets AS (
        SELECT DISTINCT
            fs_desc, device_id, inode_id
        FROM vfs
        LEFT JOIN socket_context sc
            USING (inode_id)
        WHERE fs_desc = 'SOCKFS_MAGIC'
    ),
    other_vfs AS (
        SELECT DISTINCT fs_desc, device_id, inode_id FROM vfs
        EXCEPT ALL 
        SELECT DISTINCT fs_desc, device_id, inode_id FROM sockets
    )

-- disk
SELECT  
    'thread-' || tid as from,
    'disk-' || part0 as to,
    'undirected' as edge_type
FROM disks

UNION ALL

-- contention
SELECT  
    'contention-' || vfkey as from,
    'thread-' || tid as to,
    'directed' as edge_type
FROM fwait
INNER JOIN contention USING (vfkey)
UNION ALL
SELECT  
    'thread-' || tid as from,
    'contention-' || vfkey AS to,
    'directed' as edge_type
FROM fwake
INNER JOIN contention USING (vfkey)

UNION ALL

-- futex schedule
-- direct scheduling (futex is used by a single waker and single waiter)
SELECT 
    'thread-' || fwake.tid AS from,
    'thread-' || fwait.tid AS to, 
    'directed' 
FROM fwait
INNER JOIN direct_schedulers USING (vfkey)
INNER JOIN fwake USING (vfkey)

UNION ALL

SELECT  
    'schedule-' || vfkey as from,
    'thread-' || tid as to,
    'directed' as edge_type
FROM fwait
INNER JOIN schedule USING (vfkey)
LEFT JOIN direct_schedulers direct USING (vfkey)
WHERE direct.vfkey IS NULL
UNION ALL
SELECT  
    'thread-' || tid as from,
    'schedule-' || vfkey AS to,
    'directed' as edge_type
FROM fwake
INNER JOIN schedule USING (vfkey)
LEFT JOIN direct_schedulers direct USING (vfkey)
WHERE direct.vfkey IS NULL

UNION ALL

-- sockets
SELECT 
    'socket-' || v.inode_id as from,
    'thread-' || v.tid as to,
    'directed' AS edge_type
FROM vfs v
INNER JOIN sockets s
    ON s.inode_id = v.inode_id AND v.fs_desc = s.fs_desc
WHERE op = 0 -- READ
UNION ALL
SELECT 
    'thread-' || v.tid as from,
    'socket-' || v.inode_id as to,
    'directed' AS edge_type
FROM vfs v
INNER JOIN sockets s
    ON s.inode_id = v.inode_id AND v.fs_desc = s.fs_desc
WHERE op = 1 -- WRITE

UNION ALL

-- other vfs
SELECT 
    'vfs-' || v.inode_id as from,
    'thread-' || v.tid as to,
    'directed' AS edge_type
FROM vfs v
INNER JOIN other_vfs o
    ON o.inode_id = v.inode_id AND v.fs_desc = o.fs_desc
WHERE op = 0 -- READ
UNION ALL
SELECT 
    'thread-' || v.tid as from,
    'vfs-' || v.inode_id as to,
    'directed' AS edge_type
FROM vfs v
INNER JOIN other_vfs o
    ON o.inode_id = v.inode_id AND v.fs_desc = o.fs_desc
WHERE op = 1 -- WRITE
