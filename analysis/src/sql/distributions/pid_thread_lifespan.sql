WITH 
    baseline_time_range AS (
        SELECT MAX(ts) AS upper, MIN(ts) AS lower, EXTRACT(EPOCH FROM (upper - lower)) AS range_delta
        FROM taskstats_view
        WHERE {{ pid_filter }}
            AND {{ baseline_filter("ts") }}
    ),

    compare_time_range AS (
        SELECT MAX(ts) AS upper, MIN(ts) AS lower, EXTRACT(EPOCH FROM (upper - lower)) AS range_delta
        FROM taskstats_view
        WHERE {{ pid_filter }}
            AND {{ compare_filter("ts") }}
    )

SELECT 
    tid, 
    MIN(ts) AS first,
    MAX(ts) AS last,
    EXTRACT(EPOCH FROM (last - first))/range_delta AS lifespan,
    'baseline' AS type,
FROM taskstats_view 
LEFT JOIN baseline_time_range ON true
WHERE {{ pid_filter }}
    AND {{ baseline_filter("ts") }}
GROUP BY tid, comm, range_delta

UNION ALL 

SELECT 
    tid, 
    MIN(ts) AS first,
    MAX(ts) AS last,
    EXTRACT(EPOCH FROM (last - first))/range_delta AS lifespan,
    'compare'
FROM taskstats_view 
LEFT JOIN compare_time_range ON true
WHERE {{ pid_filter }}
    AND {{ compare_filter("ts") }}
GROUP BY tid, comm, range_delta
