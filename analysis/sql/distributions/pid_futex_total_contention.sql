WITH 
    fwake AS (
        SELECT DISTINCT
            fwake.tid, 
            fwake.futex_key_addr, 
            fwake.futex_key_word, 
            fwake.futex_key_offset 
        FROM futex_wake AS fwake
        WHERE {{ pid_filter }}
          AND ({{ compare_filter("ts_s") }} OR {{ baseline_filter("ts_s") }})
    ),

    fwait AS (
        SELECT DISTINCT
            fwait.tid, 
            fwait.futex_key_addr, 
            fwait.futex_key_word, 
            fwait.futex_key_offset 
        FROM futex_wait AS fwait
        WHERE {{ pid_filter }}
          AND ({{ compare_filter("ts_s") }} OR {{ baseline_filter("ts_s") }})
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
    )

SELECT ts_s, tid, SUM(total_time)/1e9 as total_time, 'baseline' as type
FROM futex_wait
INNER JOIN contention
    USING (futex_key_addr, futex_key_word, futex_key_offset)
WHERE 
    {{ pid_filter }}
    AND {{ baseline_filter("ts_s") }}
GROUP BY ts_s, tid
UNION ALL 
SELECT ts_s, tid, SUM(total_time)/1e9 as total_time, 'compare' as type
FROM futex_wait
INNER JOIN contention
    USING (futex_key_addr, futex_key_word, futex_key_offset)
WHERE 
    {{ pid_filter }}
    AND {{ compare_filter("ts_s") }}
GROUP BY ts_s, tid
