SELECT ts, pid, tid, blkio_share, 'baseline' as type
FROM taskstats_view 
WHERE {{ pid_filter }}
  AND {{ baseline_filter("ts") }}
  AND blkio_share > 0.01
UNION ALL
SELECT ts, pid, tid, blkio_share, 'compare' AS type
FROM taskstats_view 
WHERE {{ pid_filter }}
  AND {{ compare_filter("ts") }}
  AND blkio_share > 0.01
