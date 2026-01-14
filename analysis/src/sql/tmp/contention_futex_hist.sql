WITH 
    fwake AS (
        SELECT DISTINCT
            fwake.tid, 
            fwake.futex_key_addr, 
            fwake.futex_key_word, 
            fwake.futex_key_offset 
        FROM futex_wake AS fwake
        WHERE pid = 1340830
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
        WHERE pid = 1340830
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
    )
SELECT hist0/total, hist1/total, hist2/total, hist3/total, hist4/total, hist5/total, hist6/total, hist7/total, type 
FROM (
    SELECT SUM(hist0) AS hist0, SUM(hist1) as hist1, SUM(hist2) as hist2, SUM(hist3) as hist3, SUM(hist4) as hist4, SUM(hist5) as hist5, SUM(hist6) as hist6, SUM(hist7) as hist7, SUM(hist0) + SUM(hist1) + SUM(hist2) + SUM(hist3) + SUM(hist4) + SUM(hist5) + SUM(hist6) + SUM(hist7) as total, 'BASELINE' as type FROM (
      SELECT 
        COALESCE(hist0, 0) as hist0, 
        COALESCE(hist1, 0) as hist1,
        COALESCE(hist2, 0) as hist2, 
        COALESCE(hist3, 0) as hist3, 
        COALESCE(hist4, 0) as hist4, 
        COALESCE(hist5, 0) as hist5, 
        COALESCE(hist6, 0) as hist6,
        CASE WHEN hist7 is NULL AND total_time > 0 THEN
          1
        ELSE 
          0
        END AS hist7
      FROM futex_wait
      INNER JOIN contention c 
        USING (futex_key_addr, futex_key_word, futex_key_offset)
      WHERE pid=1340830 AND ts_s > '2025-12-08 11:20:50' AND ts_s < '2025-12-08 11:21:52'
    )
    UNION ALL
    SELECT SUM(hist0), SUM(hist1), SUM(hist2), SUM(hist3), SUM(hist4), SUM(hist5), SUM(hist6), SUM(hist7), SUM(hist0) + SUM(hist1) + SUM(hist2) + SUM(hist3) + SUM(hist4) + SUM(hist5) + SUM(hist6) + SUM(hist7) as total, 'COMPARE' as type FROM (
      SELECT 
        COALESCE(hist0, 0) as hist0, 
        COALESCE(hist1, 0) as hist1,
        COALESCE(hist2, 0) as hist2, 
        COALESCE(hist3, 0) as hist3, 
        COALESCE(hist4, 0) as hist4, 
        COALESCE(hist5, 0) as hist5, 
        COALESCE(hist6, 0) as hist6,
        CASE WHEN hist7 is NULL AND total_time > 0 THEN
          1
        ELSE 
          0
        END AS hist7
      FROM futex_wait
      INNER JOIN contention c 
        USING (futex_key_addr, futex_key_word, futex_key_offset)
      WHERE pid=1340830 AND ts_s > '2025-12-08 11:21:52' AND ts_s < '2025-12-08 11:22:52'
    )
)
