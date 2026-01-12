WITH 
    fwake AS (
        SELECT DISTINCT
            fwake.tid, 
            fwake.futex_key_addr, 
            fwake.futex_key_word, 
            fwake.futex_key_offset 
        FROM futex_wake AS fwake
        WHERE pid = 1340807
          AND ts_s > '2025-12-08 11:20:00'
          AND ts_s < '2025-12-08 11:23:00'
    ),

    fwait AS (
        SELECT DISTINCT
            fwait.tid, 
            fwait.futex_key_addr, 
            fwait.futex_key_word, 
            fwait.futex_key_offset 
        FROM futex_wait AS fwait
        WHERE pid = 1340807
          AND ts_s > '2025-12-08 11:20:00'
          AND ts_s < '2025-12-08 11:23:00'
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

    -- 1. Generate per-second timestamp series
    seconds AS (
        SELECT * as ts_s
        FROM generate_series(
            TIMESTAMP '2025-12-08 11:20:00',
            TIMESTAMP '2025-12-08 11:23:00',
            INTERVAL 1 SECOND
        ) AS ts_s
    ),
    schedule_thread_wait AS (
        SELECT 
            ts_s, pid, tid, SUM(total_time)/1e9 AS total_time
        FROM futex_wait
        INNER JOIN schedule 
            USING (futex_key_addr, futex_key_word, futex_key_offset)
        WHERE pid = 1340807
        GROUP BY ts_s, pid, tid
        ORDER BY ts_s
    ),
    schedule_thread_wait_hist AS (
        SELECT 
            ts_s,
            pid,
            tid,  
            CASE WHEN total_time >= 0.01 and total_time < 0.1 THEN 1 ELSE 0 END AS hist0,
            CASE WHEN total_time >= 0.1 and total_time < 0.2 THEN 1 ELSE 0 END AS hist1,
            CASE WHEN total_time >= 0.2 and total_time < 0.3 THEN 1 ELSE 0 END AS hist2,
            CASE WHEN total_time >= 0.3 and total_time < 0.4 THEN 1 ELSE 0 END AS hist3,
            CASE WHEN total_time >= 0.4 and total_time < 0.5 THEN 1 ELSE 0 END AS hist4,
            CASE WHEN total_time >= 0.5 and total_time < 0.6 THEN 1 ELSE 0 END AS hist5,
            CASE WHEN total_time >= 0.6 and total_time < 0.7 THEN 1 ELSE 0 END AS hist6,
            CASE WHEN total_time >= 0.7 and total_time < 0.8 THEN 1 ELSE 0 END AS hist7,
            CASE WHEN total_time >= 0.8 AND total_time < 0.9 THEN 1 ELSE 0 END AS hist8,
            CASE WHEN total_time >= 0.9 THEN 1 ELSE 0 END as hist9
        FROM schedule_thread_wait
    )
SELECT 
    hist0/total AS "0-10%", 
    hist1/total AS "10-20%", 
    hist2/total AS "20-30%", 
    hist3/total AS "30-40%", 
    hist4/total AS "40-50%", 
    hist5/total AS "50-60%", 
    hist6/total AS "60-70%", 
    hist7/total AS "70-80%", 
    hist8/total AS "80-90%",
    hist9/total AS "90-100%",
    total,
    type
FROM (
    SELECT hist0, hist1, hist2, hist3, hist4, hist5, hist6, hist7, hist8, hist9, hist0 + hist1 + hist2 + hist3 + hist4 + hist5 + hist6 + hist7 + hist8 + hist9 as total, type
    FROM (
        SELECT SUM(hist0) hist0, SUM(hist1) hist1, SUM(hist2) hist2, SUM(hist3) hist3, SUM(hist4) hist4, SUM(hist5) hist5, SUM(hist6) hist6, SUM(hist7) hist7, SUM(hist8) hist8, SUM(hist9) hist9, 'BASELINE' as type
        FROM schedule_thread_wait_hist
        WHERE ts_s > '2025-12-08 11:20:50' AND ts_s < '2025-12-08 11:21:50'
        GROUP BY pid
        UNION ALL
        SELECT SUM(hist0), SUM(hist1), SUM(hist2), SUM(hist3), SUM(hist4), SUM(hist5), SUM(hist6), SUM(hist7), SUM(hist8), SUM(hist9), 'COMPARE' as type
        FROM schedule_thread_wait_hist
        WHERE ts_s > '2025-12-08 11:21:50' AND ts_s < '2025-12-08 11:23:00'
        GROUP BY pid
    )
)
