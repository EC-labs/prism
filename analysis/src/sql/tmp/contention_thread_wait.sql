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
    )
SELECT 
    ts_s, tid, SUM(total_time)/1e9 AS total_time
FROM futex_wait
INNER JOIN contention 
    USING (futex_key_addr, futex_key_word, futex_key_offset)
WHERE ts_s > '2025-12-08 11:20:50' AND ts_s < '2025-12-08 11:23:00' and tid in (SELECT DISTINCT fwait.tid from fwait inner join contention USING (futex_key_addr, futex_key_word, futex_key_offset) ORDER BY tid LIMIT 1 OFFSET 15)
GROUP BY ts_s, tid
ORDER BY ts_s
