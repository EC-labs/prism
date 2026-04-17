SELECT ts, tid, SUM(sector_cnt) AS sectors
FROM (
    SELECT 
        date_trunc('second', ts_s) AS ts, tid, sector_cnt
    FROM iowait
    WHERE {{ pid_filter }}
        AND part0 = {{ part0 }}
)
GROUP BY ts, tid
ORDER BY ts, tid
