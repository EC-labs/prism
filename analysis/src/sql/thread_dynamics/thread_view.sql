WITH 
    sched_states AS (
        SELECT 
            tid, 
            date_trunc('second', ts) AS ts,
            run_share AS run_share, 
            rq_share AS rq_share, 
            uninterruptible_share AS uninterruptible_share,
            interruptible_share AS interruptible_share
        FROM taskstats_view
        WHERE {{ tid_filter }}
    ),

    -- futex
    fwake_ AS (
        SELECT DISTINCT
            tid,
            futex_key_addr || '-' || futex_key_word || '-' || futex_key_offset AS fkey
        FROM futex_wake
        WHERE {{ pid_filter }}
    ),
    fwait_ AS (
        SELECT DISTINCT
            tid,
            futex_key_addr || '-' || futex_key_word || '-' || futex_key_offset AS fkey
        FROM futex_wait
        WHERE {{ pid_filter }}
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
    contention_state AS (
        SELECT
            tid, 
            date_trunc('second', ts_s) AS ts,
            total_time as contention_share
        FROM (
            SELECT ts_s, tid, SUM(total_time)/1e9 AS total_time
            FROM contention
            INNER JOIN signature_id
                USING (vfkey)
            INNER JOIN fkey_signature fsig
                USING (signature) 
            INNER JOIN futex_wait fw
                ON fsig.fkey = fw.futex_key_addr || '-' || fw.futex_key_word || '-' || fw.futex_key_offset
            WHERE {{ tid_filter }}
            GROUP BY ts_s, tid
        )
    ),
    schedule_state AS (
        SELECT
            tid, 
            date_trunc('second', ts_s) AS ts,
            total_time as schedule_share
        FROM (
            SELECT ts_s, tid, SUM(total_time)/1e9 AS total_time
            FROM schedule
            INNER JOIN signature_id
                USING (vfkey)
            INNER JOIN fkey_signature fsig
                USING (signature) 
            INNER JOIN futex_wait fw
                ON fsig.fkey = fw.futex_key_addr || '-' || fw.futex_key_word || '-' || fw.futex_key_offset
            WHERE {{ tid_filter }}
            GROUP BY ts_s, tid
        )
    ),

    vfs_state AS (
        SELECT
            tid, 
            date_trunc('second', ts_s) AS ts, 
            total_time as vfs_share
        FROM (
            SELECT ts_s, tid, SUM(total_time)/1e9 as total_time
            FROM vfs
            WHERE {{ tid_filter }}
            GROUP BY ts_s, tid
        )
    ),
    muxio_state AS (
        SELECT
            tid, 
            date_trunc('second', ts_s) AS ts, 
            total_time as muxio_share
        FROM (
            SELECT ts_s, tid, SUM(total_time)/1e9 as total_time
            FROM muxio_wait
            WHERE {{ tid_filter }}
            GROUP BY ts_s, tid
        )
    ),
    aio_state AS (
        SELECT
            tid, 
            date_trunc('second', ts_s) AS ts, 
            total_time as aio_share
        FROM (
            SELECT ts_s, tid, SUM(total_time)/1e9 as total_time
            FROM aio_getevents
            WHERE {{ tid_filter }}
            GROUP BY ts_s, tid
        )
    ),
    thread_states AS (
        SELECT 
            *,
            run_share 
                + rq_share 
                + uninterruptible_share 
                + contention_share 
                + schedule_share 
                + vfs_share 
                + muxio_share 
                + aio_share as total
        FROM (
            SELECT 
                tid, 
                ts, 
                COALESCE(run_share, 0) AS run_share,
                COALESCE(rq_share, 0) AS rq_share,
                COALESCE(uninterruptible_share, 0) AS uninterruptible_share,
                COALESCE(interruptible_share, 0) AS interruptible_share,
                COALESCE(contention_share, 0) AS contention_share,
                COALESCE(schedule_share, 0) AS schedule_share,
                COALESCE(vfs_share, 0) AS vfs_share,
                COALESCE(muxio_share, 0) AS muxio_share,
                COALESCE(aio_share, 0) AS aio_share
            FROM sched_states
            FULL JOIN contention_state
                USING (tid, ts)
            FULL JOIN schedule_state
                USING (tid, ts)
            -- FULL JOIN futex_state
            --     USING (tid, ts)
            FULL JOIN vfs_state
                USING (tid, ts)
            FULL JOIN muxio_state
                USING (tid, ts)
            FULL JOIN aio_state
                USING (tid, ts)
        )
    )
SELECT 
    ts,
    tid, 
    run_share,
    rq_share, 
    uninterruptible_share, 
    contention_share, 
    schedule_share, 
    vfs_share, 
    muxio_share, 
    aio_share
FROM thread_states
ORDER BY ts
