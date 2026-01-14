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
    ),

    -- 2. Cross-join each futex with each second
    futex_wait_ AS (
        SELECT *
        FROM seconds s
        CROSS JOIN fwait
    )

-- SELECT DISTINCT tid FROM fwait
SELECT fw_.ts_s, fw_.tid, fw_.futex_key_addr, fw_.futex_key_word, fw_.futex_key_offset, LEAST(COALESCE(fw.total_time, 0)/1e9, 1) as share
FROM futex_wait_ fw_
LEFT JOIN futex_wait fw
    ON fw_.ts_s = date_trunc('second', fw.ts_s)
    AND fw_.futex_key_addr = fw.futex_key_addr
    AND fw_.futex_key_word = fw.futex_key_word
    AND fw_.futex_key_offset = fw.futex_key_offset
INNER JOIN schedule as s
    ON fw_.futex_key_addr = s.futex_key_addr
    AND fw_.futex_key_word = s.futex_key_word
    AND fw_.futex_key_offset = s.futex_key_offset
WHERE 
    fw_.tid in (SELECT DISTINCT tid from fwait ORDER BY tid LIMIT 1 OFFSET 0)
ORDER BY fw_.ts_s
