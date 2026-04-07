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
    futex_state AS (
        SELECT
            tid, 
            date_trunc('second', ts_s) AS ts,
            total_time as futex_share
        FROM (
            SELECT ts_s, tid, SUM(total_time)/1e9 as total_time
            FROM futex_wait
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
                + futex_share 
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
                COALESCE(futex_share, 0) AS futex_share,
                COALESCE(vfs_share, 0) AS vfs_share,
                COALESCE(muxio_share, 0) AS muxio_share,
                COALESCE(aio_share, 0) AS aio_share
            FROM sched_states
            FULL JOIN futex_state
                USING (tid, ts)
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
    futex_share, 
    vfs_share, 
    muxio_share, 
    aio_share
FROM thread_states
ORDER BY ts
