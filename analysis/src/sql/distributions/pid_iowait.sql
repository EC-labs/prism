UNPIVOT (
    SELECT
        hist0/total as "<1us", 
        hist1/total as "1us-10us", 
        hist2/total as "10us-100us", 
        hist3/total as "100us-1ms", 
        hist4/total as "1ms-10ms", 
        hist5/total as  "10ms-100ms", 
        hist6/total as "100ms-1s", 
        hist7/total as ">1s",
        'baseline' as type
    FROM (
        SELECT 
            SUM(hist0) as hist0, 
            SUM(hist1) as hist1, 
            SUM(hist2) as hist2, 
            SUM(hist3) as hist3, 
            SUM(hist4) as hist4, 
            SUM(hist5) as hist5, 
            SUM(hist6) as hist6, 
            SUM(hist7) as hist7, 
            SUM(hist0) + SUM(hist1) + SUM(hist2) + SUM(hist3) + SUM(hist4) + SUM(hist5) + SUM(hist6) + SUM(hist7) as total,
        FROM iowait 
        WHERE {{ pid_filter }}
            AND {{ baseline_filter("ts_s") }}
        GROUP by pid
    )
)
ON "<1us", "1us-10us", "10us-100us", "100us-1ms", "1ms-10ms", "10ms-100ms", "100ms-1s", ">1s"
INTO 
    NAME bin
    VALUE cnt
UNION ALL
UNPIVOT (
    SELECT
        hist0/total as "<1us", 
        hist1/total as "1us-10us", 
        hist2/total as "10us-100us", 
        hist3/total as "100us-1ms", 
        hist4/total as "1ms-10ms", 
        hist5/total as  "10ms-100ms", 
        hist6/total as "100ms-1s", 
        hist7/total as ">1s",
        'compare' as type
    FROM (
        SELECT 
            SUM(hist0) as hist0, 
            SUM(hist1) as hist1, 
            SUM(hist2) as hist2, 
            SUM(hist3) as hist3, 
            SUM(hist4) as hist4, 
            SUM(hist5) as hist5, 
            SUM(hist6) as hist6, 
            SUM(hist7) as hist7, 
            SUM(hist0) + SUM(hist1) + SUM(hist2) + SUM(hist3) + SUM(hist4) + SUM(hist5) + SUM(hist6) + SUM(hist7) as total,
        FROM iowait 
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts_s") }}
        GROUP by pid
    )
)
ON "<1us", "1us-10us", "10us-100us", "100us-1ms", "1ms-10ms", "10ms-100ms", "100ms-1s", ">1s"
INTO 
    NAME bin
    VALUE cnt
