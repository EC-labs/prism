SELECT ts_s, tid, total_time
FROM muxio_wait
WHERE 
    pid = 1337657
    and tid in (SELECT DISTINCT tid from muxio_wait where pid = 1337657 LIMIT 5 OFFSET 0)
ORDER BY 
    ts_s
