WITH 
    sched_states AS (
        SELECT 
            tid, 
            AVG(run_share) AS run_share, 
            AVG(rq_share) AS rq_share, 
            AVG(uninterruptible_share) AS uninterruptible_share,
            AVG(interruptible_share) AS interruptible_share
        FROM taskstats_view
        WHERE pid = 1337657
        GROUP BY tid
    ),
    futex_state AS (
        SELECT
            tid, AVG(total_time/1e9) as futex_share
        FROM (
            SELECT ts_s, tid, SUM(total_time) as total_time
            FROM futex_wait
            WHERE pid = 1337657
            GROUP BY ts_s, tid
        )
        GROUP BY tid
    ),
    vfs_state AS (
        SELECT 
            tid, AVG(total_time/1e9) as vfs_share    
        FROM (    
            SELECT ts_s, tid, SUM(total_time) as total_time
            FROM vfs
            WHERE pid = 1337657
            GROUP BY ts_s, tid
        )
        GROUP BY tid
    ),
    muxio_state AS (
        SELECT
            tid, AVG(total_time/1e9) as muxio_share
        FROM (
            SELECT ts_s, tid, SUM(total_time) as total_time
            FROM muxio_wait
            WHERE pid = 1337657
            GROUP BY ts_s, tid
        )
        GROUP BY tid
    ),
    aio_state AS (
        SELECT
            tid, AVG(total_time/1e9) as aio_share
        FROM (
            SELECT ts_s, tid, SUM(total_time) as total_time
            FROM aio_getevents
            WHERE pid = 1337657
            GROUP BY ts_s, tid
        )
        GROUP BY tid
    ),
    thread_states AS (
        SELECT 
            tid,
            ss.run_share,
            ss.rq_share, 
            ss.uninterruptible_share,
            CASE WHEN fs.futex_share IS NOT NULL THEN
                fs.futex_share
            ELSE                    0
            END AS futex_share, 
            CASE WHEN vs.vfs_share IS NOT NULL THEN
                vs.vfs_share
            ELSE
                0
            END AS vfs_share,
            CASE WHEN ms.muxio_share IS NOT NULL THEN
                ms.muxio_share
            ELSE
                0
            END AS muxio_share,
            CASE WHEN aio.aio_share IS NOT NULL THEN
                aio.aio_share
            ELSE
                0
            END AS aio_share
        FROM sched_states ss
        LEFT JOIN futex_state fs 
            USING (tid)
        LEFT JOIN vfs_state vs 
            USING (tid)
        LEFT JOIN muxio_state ms 
            USING (tid)
        LEFT JOIN aio_state aio 
            USING (tid)
    )
SELECT 
    *,
    run_share + rq_share + uninterruptible_share + futex_share + vfs_share + muxio_share + aio_share AS total_time 
FROM thread_states
ORDER BY total_time DESC, tid ASC
