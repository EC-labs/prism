SELECT SUM(hist0) as "<1us", SUM(hist1) as "1us-10us", SUM(hist2)  as "10us-100us", SUM(hist3) as "100us-1ms", SUM(hist4) as "1ms-10ms", SUM(hist5) as  "10ms-100ms", SUM(hist6) as "100ms-1s", SUM(hist7) as ">1s", 'BASELINE' as type
FROM iowait 
WHERE pid=1337657 AND ts_s > '2025-12-08 11:20:50' AND ts_s < '2025-12-08 11:21:52'
GROUP by pid
UNION ALL
SELECT SUM(hist0), SUM(hist1), SUM(hist2), SUM(hist3), SUM(hist4), SUM(hist5), SUM(hist6), SUM(hist7), 'COMPARE' as type
FROM iowait 
WHERE pid=1337657 AND ts_s > '2025-12-08 11:21:52' AND ts_s < '2025-12-08 11:23:00'
GROUP BY pid
