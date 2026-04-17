WITH
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
    )
SELECT ts, tid, SUM(total_time)/1e9 AS total_time
FROM (
    SELECT date_trunc('second', fw.ts_s) AS ts, fw.tid, fw.total_time
    FROM signature_id si
    INNER JOIN fkey_signature fsig
        USING (signature)
    INNER JOIN futex_wait fw 
        ON fsig.fkey = fw.futex_key_addr || '-' || fw.futex_key_word || '-' || fw.futex_key_offset
    WHERE si.vfkey = {{ vfkey }}
)
GROUP BY ts, tid
ORDER BY ts, tid
