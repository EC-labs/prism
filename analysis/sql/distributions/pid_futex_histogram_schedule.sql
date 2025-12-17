WITH 
    fwake AS (
        SELECT DISTINCT
            fwake.tid, 
            fwake.futex_key_addr, 
            fwake.futex_key_word, 
            fwake.futex_key_offset 
        FROM futex_wake AS fwake
        WHERE {{ pid_filter }}
          AND ({{ compare filter }} OR {{ baseline_filter }})
    ),

    fwait AS (
        SELECT DISTINCT
            fwait.tid, 
            fwait.futex_key_addr, 
            fwait.futex_key_word, 
            fwait.futex_key_offset 
        FROM futex_wait AS fwait
        WHERE {{ pid_filter }}
          AND ({{ compare filter }} OR {{ baseline_filter }})
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

UNPIVOT (
    SELECT 
        hist0/total_seconds as "<1us", 
        hist1/total_seconds as "1us-10us", 
        hist2/total_seconds as "10us-100us", 
        hist3/total_seconds as "100us-1ms", 
        hist4/total_seconds as "1ms-10ms", 
        hist5/total_seconds as  "10ms-100ms", 
        hist6/total_seconds as "100ms-1s", 
        hist7/total_seconds as ">1s",
        'baseline' as type
    FROM (
        SELECT 
            pid, 
            SUM(hist0) AS hist0, 
            SUM(hist1) AS hist1, 
            SUM(hist2) AS hist2, 
            SUM(hist3) AS hist3, 
            SUM(hist4) AS hist4, 
            SUM(hist5) AS hist5, 
            SUM(hist6) AS hist6,
            SUM(hist7) AS hist7,
            {{ total_baseline_seconds }} AS total_seconds
        FROM futex_wait
        INNER JOIN schedule
            USING (futex_key_addr, futex_key_word, futex_key_offset)
        WHERE
            {{ pid_filter }}
            AND {{ baseline_filter }}
        GROUP BY pid
    )
)
ON "<1us", "1us-10us", "10us-100us", "100us-1ms", "1ms-10ms", "10ms-100ms", "100ms-1s", ">1s"
INTO 
    NAME bin
    VALUE cnt
UNION ALL
UNPIVOT (
    SELECT 
        hist0/total_seconds as "<1us", 
        hist1/total_seconds as "1us-10us", 
        hist2/total_seconds as "10us-100us", 
        hist3/total_seconds as "100us-1ms", 
        hist4/total_seconds as "1ms-10ms", 
        hist5/total_seconds as  "10ms-100ms", 
        hist6/total_seconds as "100ms-1s", 
        hist7/total_seconds as ">1s",
        'compare' as type
    FROM (
        SELECT 
            pid, 
            SUM(hist0) AS hist0, 
            SUM(hist1) AS hist1, 
            SUM(hist2) AS hist2, 
            SUM(hist3) AS hist3, 
            SUM(hist4) AS hist4, 
            SUM(hist5) AS hist5, 
            SUM(hist6) AS hist6,
            SUM(hist7) AS hist7,
            {{ total_compare_seconds }} as total_seconds
        FROM futex_wait
        INNER JOIN schedule
            USING (futex_key_addr, futex_key_word, futex_key_offset)
        WHERE
            {{ pid_filter }}
            AND {{ compare_filter }}
        GROUP BY pid
    )
)
ON "<1us", "1us-10us", "10us-100us", "100us-1ms", "1ms-10ms", "10ms-100ms", "100ms-1s", ">1s"
INTO 
    NAME bin
    VALUE cnt
