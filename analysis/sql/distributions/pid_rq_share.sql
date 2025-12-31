SELECT ts, pid, tid, rq_share as share, 'baseline' as type
FROM taskstats_view 
WHERE {{ pid_filter }}
  AND {{ baseline_filter("ts") }}
  AND rq_share > 0.01
UNION ALL
SELECT ts, pid, tid, rq_share, 'compare' AS type
FROM taskstats_view 
WHERE {{ pid_filter }}
  AND {{ compare_filter("ts") }}
  AND rq_share > 0.01
