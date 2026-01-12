SELECT ts, uninterruptible_share 
FROM taskstats_view
WHERE {{ tid_filter }}
ORDER BY ts
