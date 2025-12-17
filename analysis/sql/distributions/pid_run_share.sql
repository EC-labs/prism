SELECT ts, pid, tid, run_share, 'baseline' as type
FROM taskstats_view 
WHERE {{ pid_filter }}
  AND {{ baseline_filter }}
  AND run_share > 0.01
UNION ALL
SELECT ts, pid, tid, run_share, 'compare' AS type
FROM taskstats_view 
WHERE {{ pid_filter }}
  AND {{ compare_filter }}
  AND run_share > 0.01
