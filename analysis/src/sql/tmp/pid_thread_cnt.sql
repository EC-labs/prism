SELECT pid, count(distinct tid), 'BASELINE' AS type
FROM taskstats_view 
WHERE pid=1337657 AND ts > '2025-12-08 11:20:50' AND ts < '2025-12-08 11:21:52'
GROUP BY pid
UNION ALL
SELECT pid, count(DISTINCT tid), 'COMPARE' AS type
FROM taskstats_view 
WHERE pid=1337657 AND ts > '2025-12-08 11:21:52' AND ts < '2025-12-08 11:23:00'
GROUP BY pid
