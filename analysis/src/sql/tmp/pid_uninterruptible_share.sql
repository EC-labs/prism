WITH 
    uninterruptible_share_histogram AS (
        SELECT 
            ts, 
            pid, 
            tid, 
            CASE WHEN uninterruptible_share >= 0.01 and uninterruptible_share < 0.1 THEN 1 ELSE 0 END AS hist0,
            CASE WHEN uninterruptible_share >= 0.1 and uninterruptible_share < 0.2 THEN 1 ELSE 0 END AS hist1,
            CASE WHEN uninterruptible_share >= 0.2 and uninterruptible_share < 0.3 THEN 1 ELSE 0 END AS hist2,
            CASE WHEN uninterruptible_share >= 0.3 and uninterruptible_share < 0.4 THEN 1 ELSE 0 END AS hist3,
            CASE WHEN uninterruptible_share >= 0.4 and uninterruptible_share < 0.5 THEN 1 ELSE 0 END AS hist4,
            CASE WHEN uninterruptible_share >= 0.5 and uninterruptible_share < 0.6 THEN 1 ELSE 0 END AS hist5,
            CASE WHEN uninterruptible_share >= 0.6 and uninterruptible_share < 0.7 THEN 1 ELSE 0 END AS hist6,
            CASE WHEN uninterruptible_share >= 0.7 and uninterruptible_share < 0.8 THEN 1 ELSE 0 END AS hist7,
            CASE WHEN uninterruptible_share >= 0.8 AND uninterruptible_share < 0.9 THEN 1 ELSE 0 END AS hist8,
            CASE WHEN uninterruptible_share >= 0.9 THEN 1 ELSE 0 END as hist9
        FROM taskstats_view
    )
SELECT 
    pid, 
    SUM(hist0) AS "0-10%", 
    SUM(hist1) AS "10-20%", 
    SUM(hist2) AS "20-30%", 
    SUM(hist3) AS "30-40%", 
    SUM(hist4) AS "40-50%", 
    SUM(hist5) AS "50-60%", 
    SUM(hist6) AS "60-70%", 
    SUM(hist7) AS "70-80%", 
    SUM(hist8) AS "80-90%", 
    SUM(hist9) AS "90-100%",
    'BASELINE' AS type
FROM uninterruptible_share_histogram
WHERE pid=1337657 AND ts > '2025-12-08 11:20:50' AND ts < '2025-12-08 11:21:52'
GROUP BY pid
UNION ALL
SELECT 
    pid, 
    SUM(hist0) AS "0-10%", 
    SUM(hist1) AS "10-20%", 
    SUM(hist2) AS "20-30%", 
    SUM(hist3) AS "30-40%", 
    SUM(hist4) AS "40-50%", 
    SUM(hist5) AS "50-60%", 
    SUM(hist6) AS "60-70%", 
    SUM(hist7) AS "70-80%", 
    SUM(hist8) AS "80-90%", 
    SUM(hist9) AS "90-100%",
    'COMPARE' AS type
FROM uninterruptible_share_histogram
WHERE pid=1337657 AND ts > '2025-12-08 11:21:52' AND ts < '2025-12-08 11:23:00'
GROUP BY pid
