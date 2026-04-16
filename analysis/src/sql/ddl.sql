CREATE TABLE IF NOT EXISTS linux_consts (
    const_type VARCHAR,
    const_name VARCHAR,
    value UINTEGER,
);
CREATE TABLE IF NOT EXISTS iowait (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    pid UINTEGER,
    tid UINTEGER,
    part0 UBIGINT,
    bdev UBIGINT,
    total_time UBIGINT,
    sector_cnt UINTEGER,
    total_requests UINTEGER,
    hist0 UINTEGER,
    hist1 UINTEGER,
    hist2 UINTEGER,
    hist3 UINTEGER,
    hist4 UINTEGER,
    hist5 UINTEGER,
    hist6 UINTEGER,
    hist7 UINTEGER,
);

CREATE TABLE IF NOT EXISTS aio_getevents (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    pid UINTEGER,
    tid UINTEGER,
    aioctx UBIGINT,
    total_time UBIGINT,
    total_requests UBIGINT,
);

CREATE TABLE IF NOT EXISTS aio_submit (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    pid UINTEGER,
    tid UINTEGER,
    aioctx UBIGINT,
    total_requests UBIGINT,
);

CREATE TABLE IF NOT EXISTS aio_file (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    aioctx UBIGINT,
    isreg UTINYINT,
    fs_magic UINTEGER,
    device_id UINTEGER,
    inode_id UBIGINT,
    part0 UBIGINT,
    bdev UBIGINT,
    mode UTINYINT,
    hist0 UINTEGER,
    hist1 UINTEGER,
    hist2 UINTEGER,
    hist3 UINTEGER,
    hist4 UINTEGER,
    hist5 UINTEGER,
    hist6 UINTEGER,
    hist7 UINTEGER,
);

CREATE TABLE IF NOT EXISTS tcp_discovery (
    local_machine_id    UINTEGER,
    local_inode_id      UBIGINT,
    remote_machine_id   UINTEGER,
    remote_inode_id     UBIGINT,
    inserted_at         TIMESTAMP,
);

CREATE TABLE IF NOT EXISTS vfs (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    pid UINTEGER,
    tid UINTEGER,
    fs_magic UINTEGER,
    device_id UINTEGER,
    inode_id UBIGINT,
    op UTINYINT,
    total_time UBIGINT,
    total_requests UINTEGER,
    hist0 UINTEGER,
    hist1 UINTEGER,
    hist2 UINTEGER,
    hist3 UINTEGER,
    hist4 UINTEGER,
    hist5 UINTEGER,
    hist6 UINTEGER,
    hist7 UINTEGER,
);

CREATE TABLE IF NOT EXISTS futex_wait (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    pid UINTEGER,
    tid UINTEGER,
    futex_key_addr UBIGINT,
    futex_key_word UBIGINT,
    futex_key_offset UINTEGER,
    total_requests UBIGINT,
    total_time UBIGINT,
    hist0 UINTEGER,
    hist1 UINTEGER,
    hist2 UINTEGER,
    hist3 UINTEGER,
    hist4 UINTEGER,
    hist5 UINTEGER,
    hist6 UINTEGER,
    hist7 UINTEGER,
);

CREATE TABLE IF NOT EXISTS futex_wake (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    pid UINTEGER,
    tid UINTEGER,
    futex_key_addr UBIGINT,
    futex_key_word UBIGINT,
    futex_key_offset UINTEGER,
    total_requests UBIGINT,
    successful_count UBIGINT,
);

CREATE TABLE IF NOT EXISTS muxio_wait (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    pid UINTEGER,
    tid UINTEGER,
    is_epoll BOOLEAN,
    poll_id UBIGINT,
    total_time UBIGINT,
    total_requests UBIGINT,
);

CREATE TABLE IF NOT EXISTS muxio_file (
    machine_id UINTEGER,
    ts_s TIMESTAMP,
    poll_id UBIGINT,
    fs_magic UINTEGER,
    device_id UINTEGER,
    inode_id UBIGINT,
    mode UTINYINT,
    hist0 UINTEGER,
    hist1 UINTEGER,
    hist2 UINTEGER,
    hist3 UINTEGER,
    hist4 UINTEGER,
    hist5 UINTEGER,
    hist6 UINTEGER,
    hist7 UINTEGER,
);

CREATE TABLE IF NOT EXISTS socket_context (
    machine_id UINTEGER,
    inode_id UBIGINT,
    family          USMALLINT, 
    type            USMALLINT, 
    protocol        USMALLINT, 
);

CREATE TABLE IF NOT EXISTS socket_inet (
    machine_id UINTEGER,
    inode_id        UBIGINT,
    netns_cookie    UBIGINT,
    src_address     VARCHAR,
    src_port        USMALLINT, 
    dst_address     VARCHAR,
    dst_port        USMALLINT, 
);

CREATE TABLE IF NOT EXISTS socket_map (
    machine_id UINTEGER,
    sock1_inode_id UBIGINT,
    sock2_inode_id UBIGINT,
);

CREATE TABLE IF NOT EXISTS taskstats (
    machine_id      UINTEGER,
    ts              TIMESTAMP,
    pid             UINTEGER,
    tid             UINTEGER,
    comm            VARCHAR,
    nvcsw           UBIGINT,
    nivcsw           UBIGINT,
    run_time_total  UBIGINT,
    rq_time_total   UBIGINT,
    rq_count        UBIGINT,
    blkio_time_total    UBIGINT,
    blkio_count         UBIGINT,
    uninterruptible_total   UBIGINT,
    freepages_time_total    UBIGINT,
    freepages_count         UBIGINT,
    thrashing_time_total    UBIGINT,
    thrashing_count         UBIGINT,
    swapin_time_total    UBIGINT,
    swapin_count         UBIGINT,
);

CREATE VIEW IF NOT EXISTS taskstats_view AS 
SELECT 
    machine_id,
    ts, 
    time_diff,
    pid,
    tid,
    comm,
    run_time/time_diff as run_share, 
    rq_time/time_diff as rq_share,
    uninterruptible_time/time_diff as uninterruptible_share,
    blkio_time/time_diff as blkio_share,
    greatest((time_diff - (run_time + rq_time + uninterruptible_time))/time_diff, 0) as interruptible_share
FROM (
    SELECT 
        machine_id,
        ts, 
        epoch_ns(ts - ts_last) as time_diff,
        pid,
        tid, 
        comm,
        run_time_curr - run_time_last AS run_time,
        rq_time_curr - rq_time_last AS rq_time,
        uninterruptible_time_curr - uninterruptible_time_last AS uninterruptible_time,
        blkio_time_curr - blkio_time_last AS blkio_time,
    FROM (
        SELECT 
            machine_id,
            ts, 
            lag(ts, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as ts_last,
            pid,
            tid, 
            comm,
            run_time_total as run_time_curr, 
            lag(run_time_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as run_time_last,
            rq_time_total as rq_time_curr, 
            lag(rq_time_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as rq_time_last,
            uninterruptible_total as uninterruptible_time_curr, 
            lag(uninterruptible_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as uninterruptible_time_last,
            blkio_time_total as blkio_time_curr, 
            lag(blkio_time_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as blkio_time_last,
        FROM taskstats
    )
)
WHERE 
    time_diff IS NOT NULL;


CREATE TABLE IF NOT EXISTS docker (
    machine_id UINTEGER,
    cgroup          VARCHAR,
    id              VARCHAR,
    name            VARCHAR,
    image_name      VARCHAR,
    image_hash      VARCHAR,
);
CREATE TABLE IF NOT EXISTS k8s (
    machine_id UINTEGER,
    cgroup          VARCHAR,
    id              VARCHAR,
    namespace       VARCHAR,
    pod_name        VARCHAR,
    container_name  VARCHAR,
    image_name      VARCHAR,
);

CREATE TABLE IF NOT EXISTS process_context (
    machine_id UINTEGER,
    pid         UINTEGER,
    cgroup      VARCHAR,
    argv        VARCHAR,
    exe         VARCHAR,
);
