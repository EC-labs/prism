CREATE TABLE IF NOT EXISTS default.docker_local
ON CLUSTER default
(
    machine_id  UInt32,
    cgroup      VARCHAR,
    id          VARCHAR,
    name        Nullable(VARCHAR),
    image_name  Nullable(VARCHAR),
    image_hash  Nullable(VARCHAR)
) ENGINE = MergeTree
PARTITION BY machine_id;

CREATE TABLE IF NOT EXISTS default.docker 
ON CLUSTER default 
AS default.docker_local
ENGINE = Distributed(default, default, docker_local, machine_id);

CREATE TABLE IF NOT EXISTS default.linux_consts
ON CLUSTER default
(
    const_type  VARCHAR,
    const_name  VARCHAR,
    `value`     UInt32
) ENGINE = ReplicatedMergeTree()
ORDER BY (const_type, const_name);

CREATE TABLE IF NOT EXISTS default.iowait_local
ON CLUSTER default
(
    machine_id  UInt32,
    ts_s        DateTime64,
    pid         UInt32,
    tid         UInt32,
    part0       UInt64,
    bdev        UInt64,
    total_time  UInt64,
    sector_cnt  UInt32,
    total_requests UInt32,
    hist0 UInt32, hist1 UInt32, hist2 UInt32, hist3 UInt32,
    hist4 UInt32, hist5 UInt32, hist6 UInt32, hist7 UInt32
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.iowait 
ON CLUSTER default
AS default.iowait_local
ENGINE = Distributed(default, default, iowait_local, machine_id);

CREATE TABLE IF NOT EXISTS default.k8s_local
ON CLUSTER default
(
    machine_id      UInt32,
    cgroup          VARCHAR,
    id              VARCHAR,
    namespace       Nullable(VARCHAR),
    pod_name        Nullable(VARCHAR),
    container_name  Nullable(VARCHAR),
    image_name      VARCHAR
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY id;

CREATE TABLE IF NOT EXISTS default.k8s 
ON CLUSTER default
AS default.k8s_local
ENGINE = Distributed(default, default, k8s_local, machine_id);

CREATE TABLE IF NOT EXISTS default.process_context_local
ON CLUSTER default
(
    machine_id  UInt32,
    pid         UInt32,
    cgroup      Nullable(VARCHAR),
    argv        VARCHAR,
    exe         Nullable(VARCHAR)
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY pid;

CREATE TABLE IF NOT EXISTS default.process_context 
ON CLUSTER default
AS default.process_context_local
ENGINE = Distributed(default, default, process_context_local, machine_id);

CREATE TABLE IF NOT EXISTS default.tcp_discovery_local
ON CLUSTER default
(
    local_machine_id    UInt32,
    local_inode_id      UInt64,
    remote_machine_id   UInt32,
    remote_inode_id     UInt64,
    inserted_at         DateTime64
) ENGINE = MergeTree
PARTITION BY local_machine_id
ORDER BY inserted_at;

CREATE TABLE IF NOT EXISTS default.tcp_discovery 
ON CLUSTER default
AS default.tcp_discovery_local
ENGINE = Distributed(default, default, tcp_discovery_local, local_machine_id);

CREATE TABLE IF NOT EXISTS default.vfs_local
ON CLUSTER default
(
    machine_id  UInt32,
    ts_s        DateTime64,
    pid         UInt32,
    tid         UInt32,
    fs_magic    UInt32,
    device_id   UInt32,
    inode_id    UInt64,
    op          UInt8,
    total_time  UInt64,
    total_requests UInt32,
    hist0 UInt32, hist1 UInt32, hist2 UInt32, hist3 UInt32,
    hist4 UInt32, hist5 UInt32, hist6 UInt32, hist7 UInt32
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.vfs 
ON CLUSTER default
AS default.vfs_local
ENGINE = Distributed(default, default, vfs_local, machine_id);

CREATE TABLE IF NOT EXISTS default.futex_wait_local
ON CLUSTER default
(
    machine_id          UInt32,
    ts_s                DateTime64,
    pid                 UInt32,
    tid                 UInt32,
    futex_key_addr      UInt64,
    futex_key_word      UInt64,
    futex_key_offset    UInt32,
    total_requests      UInt64,
    total_time          UInt64,
    hist0 UInt32, hist1 UInt32, hist2 UInt32, hist3 UInt32,
    hist4 UInt32, hist5 UInt32, hist6 UInt32, hist7 UInt32
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.futex_wait 
ON CLUSTER default
AS default.futex_wait_local
ENGINE = Distributed(default, default, futex_wait_local, machine_id);

CREATE TABLE IF NOT EXISTS default.futex_wake_local
ON CLUSTER default
(
    machine_id          UInt32,
    ts_s                DateTime64,
    pid                 UInt32,
    tid                 UInt32,
    futex_key_addr      UInt64,
    futex_key_word      UInt64,
    futex_key_offset    UInt32,
    total_requests      UInt64,
    successful_count    UInt64
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.futex_wake 
ON CLUSTER default
AS default.futex_wake_local
ENGINE = Distributed(default, default, futex_wake_local, machine_id);


CREATE TABLE IF NOT EXISTS default.socket_context_local
ON CLUSTER default
(
    machine_id  UInt32,
    inode_id    UInt64,
    family      UInt16,
    type        UInt16,
    protocol    UInt16
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY inode_id;

CREATE TABLE IF NOT EXISTS default.socket_context 
ON CLUSTER default
AS default.socket_context_local
ENGINE = Distributed(default, default, socket_context_local, machine_id);

CREATE TABLE IF NOT EXISTS default.socket_inet_local
ON CLUSTER default
(
    machine_id      UInt32,
    inode_id        UInt64,
    netns_cookie    UInt64,
    src_address     VARCHAR,
    src_port        UInt16,
    dst_address     VARCHAR,
    dst_port        UInt16
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY inode_id;

CREATE TABLE IF NOT EXISTS default.socket_inet 
ON CLUSTER default
AS default.socket_inet_local
ENGINE = Distributed(default, default, socket_inet_local, machine_id);

CREATE TABLE IF NOT EXISTS default.socket_map_local
ON CLUSTER default
(
    machine_id      UInt32,
    sock1_inode_id  UInt64,
    sock2_inode_id  UInt64
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY sock1_inode_id;

CREATE TABLE IF NOT EXISTS default.socket_map 
ON CLUSTER default
AS default.socket_map_local
ENGINE = Distributed(default, default, socket_map_local, machine_id);

CREATE TABLE IF NOT EXISTS default.muxio_wait_local
ON CLUSTER default
(
    machine_id      UInt32,
    ts_s            DateTime64,
    pid             UInt32,
    tid             UInt32,
    is_epoll        Boolean,
    poll_id         UInt64,
    total_time      UInt64,
    total_requests  UInt64
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.muxio_wait 
ON CLUSTER default
AS default.muxio_wait_local
ENGINE = Distributed(default, default, muxio_wait_local, machine_id);

CREATE TABLE IF NOT EXISTS default.muxio_file_local
ON CLUSTER default
(
    machine_id  UInt32,
    ts_s        DateTime64,
    poll_id     UInt64,
    fs_magic    UInt32,
    device_id   UInt32,
    inode_id    UInt64,
    mode        UInt8,
    hist0 UInt32, hist1 UInt32, hist2 UInt32, hist3 UInt32,
    hist4 UInt32, hist5 UInt32, hist6 UInt32, hist7 UInt32
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.muxio_file 
ON CLUSTER default
AS default.muxio_file_local
ENGINE = Distributed(default, default, muxio_file_local, machine_id);

CREATE TABLE IF NOT EXISTS default.aio_getevents_local
ON CLUSTER default
(
    machine_id      UInt32,
    ts_s            DateTime64,
    pid             UInt32,
    tid             UInt32,
    aioctx          UInt64,
    total_time      UInt64,
    total_requests  UInt64
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.aio_getevents 
ON CLUSTER default
AS default.aio_getevents_local
ENGINE = Distributed(default, default, aio_getevents_local, machine_id);

CREATE TABLE IF NOT EXISTS default.aio_submit_local
ON CLUSTER default
(
    machine_id      UInt32,
    ts_s            DateTime64,
    pid             UInt32,
    tid             UInt32,
    aioctx          UInt64,
    total_requests  UInt64
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.aio_submit 
ON CLUSTER default
AS default.aio_submit_local
ENGINE = Distributed(default, default, aio_submit_local, machine_id);

CREATE TABLE IF NOT EXISTS default.aio_file_local
ON CLUSTER default
(
    machine_id  UInt32,
    ts_s        DateTime64,
    aioctx      UInt64,
    isreg       UInt8,
    fs_magic    Nullable(UInt32),
    device_id   Nullable(UInt32),
    inode_id    Nullable(UInt64),
    part0       Nullable(UInt64),
    bdev        Nullable(UInt64),
    mode        UInt8,
    hist0 UInt32, hist1 UInt32, hist2 UInt32, hist3 UInt32,
    hist4 UInt32, hist5 UInt32, hist6 UInt32, hist7 UInt32
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts_s;

CREATE TABLE IF NOT EXISTS default.aio_file 
ON CLUSTER default
AS default.aio_file_local
ENGINE = Distributed(default, default, aio_file_local, machine_id);

CREATE TABLE IF NOT EXISTS default.taskstats_local
ON CLUSTER default
(
    machine_id      UInt32,
    ts              DateTime64,
    pid             UInt32,
    tid             UInt32,
    comm            VARCHAR,
    nvcsw           UInt64,
    nivcsw          UInt64,
    run_time_total  UInt64,
    rq_time_total   UInt64,
    rq_count        UInt64,
    blkio_time_total        UInt64,
    blkio_count             UInt64,
    uninterruptible_total   UInt64,
    freepages_time_total    UInt64,
    freepages_count         UInt64,
    thrashing_time_total    UInt64,
    thrashing_count         UInt64,
    swapin_time_total       UInt64,
    swapin_count            UInt64
) ENGINE = MergeTree
PARTITION BY machine_id
ORDER BY ts;

CREATE TABLE IF NOT EXISTS default.taskstats 
ON CLUSTER default
AS default.taskstats_local
ENGINE = Distributed(default, default, taskstats_local, machine_id);

CREATE OR REPLACE VIEW default.taskstats_view 
ON CLUSTER default
AS
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
        dateDiff('nanosecond', ts_last, ts) as time_diff,
        pid,
        tid, 
        comm,
        run_time_curr - run_time_last AS run_time,
        rq_time_curr - rq_time_last AS rq_time,
        uninterruptible_time_curr - uninterruptible_time_last AS uninterruptible_time,
        blkio_time_curr - blkio_time_last AS blkio_time
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
            lag(blkio_time_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as blkio_time_last
        FROM taskstats
    )
)
WHERE 
    time_diff IS NOT NULL;

INSERT INTO linux_consts (`const_type`, `const_name`, `value`) VALUES ('family_protocol', 'IPPROTO_AH', 51), ('family_protocol', 'IPPROTO_COMP', 108), ('family_protocol', 'IPPROTO_DCCP', 33), ('family_protocol', 'IPPROTO_EGP', 8), ('family_protocol', 'IPPROTO_ENCAP', 98), ('family_protocol', 'IPPROTO_GRE', 47), ('family_protocol', 'IPPROTO_ICMP', 1), ('family_protocol', 'IPPROTO_IDP', 22), ('family_protocol', 'IPPROTO_IGMP', 2), ('family_protocol', 'IPPROTO_IP', 0), ('family_protocol', 'IPPROTO_MPLS', 137), ('family_protocol', 'IPPROTO_RAW', 255), ('family_protocol', 'IPPROTO_RSVP', 46), ('family_protocol', 'IPPROTO_SMC', 256), ('family_protocol', 'IPPROTO_TP', 29), ('family_protocol', 'IPPROTO_UDPLITE', 136), ('fs_magic', 'AFS_FS_MAGIC', 1799439955), ('fs_magic', 'ANON_INODE_FS_MAGIC', 151263540), ('fs_magic', 'BINDERFS_SUPER_MAGIC', 1819242352), ('fs_magic', 'BINFMTFS_MAGIC', 1112100429), ('fs_magic', 'BTRFS_SUPER_MAGIC', 2435016766), ('fs_magic', 'BTRFS_TEST_MAGIC', 1936880249), ('fs_magic', 'CEPH_SUPER_MAGIC', 12805120), ('fs_magic', 'CGROUP_SUPER_MAGIC', 2613483), ('fs_magic', 'CODA_SUPER_MAGIC', 1937076805), ('fs_magic', 'DEBUGFS_MAGIC', 1684170528), ('fs_magic', 'DEVMEM_MAGIC', 1162691661), ('fs_magic', 'DEVPTS_SUPER_MAGIC', 7377), ('fs_magic', 'EFS_SUPER_MAGIC', 4278867), ('fs_magic', 'EXFAT_SUPER_MAGIC', 538032816), ('fs_magic', 'EXT3_SUPER_MAGIC', 61267), ('fs_magic', 'EXT4_SUPER_MAGIC', 61267), ('fs_magic', 'F2FS_SUPER_MAGIC', 4076150800), ('fs_magic', 'HPFS_SUPER_MAGIC', 4187351113), ('fs_magic', 'ISOFS_SUPER_MAGIC', 38496), ('fs_magic', 'JFFS2_SUPER_MAGIC', 29366), ('fs_magic', 'MINIX2_SUPER_MAGIC', 9336), ('fs_magic', 'MINIX3_SUPER_MAGIC', 19802), ('fs_magic', 'MSDOS_SUPER_MAGIC', 19780), ('fs_magic', 'MTD_INODE_FS_MAGIC', 288389204), ('fs_magic', 'NCP_SUPER_MAGIC', 22092), ('fs_magic', 'NILFS_SUPER_MAGIC', 13364), ('fs_magic', 'NSFS_MAGIC', 1853056627), ('fs_magic', 'OCFS2_SUPER_MAGIC', 1952539503), ('fs_magic', 'PID_FS_MAGIC', 1346978886), ('fs_magic', 'PSTOREFS_MAGIC', 1634035564), ('fs_magic', 'QNX6_SUPER_MAGIC', 1746473250), ('fs_magic', 'RAMFS_MAGIC', 2240043254), ('fs_magic', 'RDTGROUP_SUPER_MAGIC', 124082209), ('fs_magic', 'REISERFS_SUPER_MAGIC', 1382369651), ('fs_magic', 'SECURITYFS_MAGIC', 1935894131), ('fs_magic', 'SELINUX_MAGIC', 4185718668), ('fs_magic', 'SMB_SUPER_MAGIC', 20859), ('fs_magic', 'SOCKFS_MAGIC', 1397703499), ('fs_magic', 'SQUASHFS_MAGIC', 1936814952), ('fs_magic', 'TMPFS_MAGIC', 16914836), ('fs_magic', 'USBDEVICE_SUPER_MAGIC', 40866), ('fs_magic', 'V9FS_MAGIC', 16914839), ('fs_magic', 'XFS_SUPER_MAGIC', 1481003842), ('socket_family', 'AF_ALG', 38), ('socket_family', 'AF_ASH', 18), ('socket_family', 'AF_ATMSVC', 20), ('socket_family', 'AF_AX25', 3), ('socket_family', 'AF_BRIDGE', 7), ('socket_family', 'AF_CAIF', 37), ('socket_family', 'AF_ECONET', 19), ('socket_family', 'AF_IB', 27), ('socket_family', 'AF_INET', 2), ('socket_family', 'AF_INET6', 10), ('socket_family', 'AF_IPX', 4), ('socket_family', 'AF_KCM', 41), ('socket_family', 'AF_KEY', 15), ('socket_family', 'AF_LLC', 26), ('socket_family', 'AF_MAX', 46), ('socket_family', 'AF_MPLS', 28), ('socket_family', 'AF_NETBEUI', 13), ('socket_family', 'AF_NFC', 39), ('socket_family', 'AF_PACKET', 17), ('socket_family', 'AF_RXRPC', 33), ('socket_family', 'AF_SECURITY', 14), ('socket_family', 'AF_SNA', 22), ('socket_family', 'AF_UNSPEC', 0), ('socket_family', 'AF_WANPIPE', 25), ('socket_type', 'SOCK_DCCP', 6), ('socket_type', 'SOCK_DGRAM', 2), ('socket_type', 'SOCK_RDM', 4)
, ('family_protocol', 'IPPROTO_BEETPH', 94), ('family_protocol', 'IPPROTO_ESP', 50), ('family_protocol', 'IPPROTO_ETHERNET', 143), ('family_protocol', 'IPPROTO_IPIP', 4), ('family_protocol', 'IPPROTO_MAX', 263), ('family_protocol', 'IPPROTO_MTP', 92), ('family_protocol', 'IPPROTO_PUP', 12), ('family_protocol', 'IPPROTO_UDP', 17), ('fs_magic', 'ADFS_SUPER_MAGIC', 44533), ('fs_magic', 'AFFS_SUPER_MAGIC', 44543), ('fs_magic', 'AUTOFS_SUPER_MAGIC', 391), ('fs_magic', 'BDEVFS_MAGIC', 1650746742), ('fs_magic', 'BPF_FS_MAGIC', 3405662737), ('fs_magic', 'CGROUP2_SUPER_MAGIC', 1667723888), ('fs_magic', 'CIFS_SUPER_MAGIC', 4283649346), ('fs_magic', 'CRAMFS_MAGIC', 684539205), ('fs_magic', 'ECRYPTFS_SUPER_MAGIC', 61791), ('fs_magic', 'EROFS_SUPER_MAGIC', 3774210530), ('fs_magic', 'FUTEXFS_SUPER_MAGIC', 195894762), ('fs_magic', 'HOSTFS_SUPER_MAGIC', 12648430), ('fs_magic', 'HUGETLBFS_MAGIC', 2508478710), ('fs_magic', 'MINIX_SUPER_MAGIC', 5007), ('fs_magic', 'NFS_SUPER_MAGIC', 26985), ('fs_magic', 'OVERLAYFS_SUPER_MAGIC', 2035054128), ('fs_magic', 'SMACK_MAGIC', 1128357203), ('fs_magic', 'STACK_END_MAGIC', 1470918301), ('fs_magic', 'TRACEFS_MAGIC', 1953653091), ('fs_magic', 'XENFS_SUPER_MAGIC', 2881100148), ('socket_family', 'AF_APPLETALK', 5), ('socket_family', 'AF_ATMPVC', 8), ('socket_family', 'AF_BLUETOOTH', 31), ('socket_family', 'AF_CAN', 29), ('socket_family', 'AF_IRDA', 23), ('socket_family', 'AF_LOCAL', 1), ('socket_family', 'AF_PPPOX', 24), ('socket_family', 'AF_QIPCRTR', 42), ('socket_family', 'AF_RDS', 21), ('socket_family', 'AF_ROSE', 11), ('socket_family', 'AF_SMC', 43), ('socket_family', 'AF_TIPC', 30), ('socket_family', 'AF_VSOCK', 40), ('socket_family', 'AF_X25', 9), ('socket_family', 'AF_XDP', 44), ('socket_type', 'SOCK_PACKET', 10), ('socket_type', 'SOCK_STREAM', 1)
, ('family_protocol', 'IPPROTO_L2TP', 115), ('family_protocol', 'IPPROTO_MPTCP', 262), ('family_protocol', 'IPPROTO_PIM', 103), ('family_protocol', 'IPPROTO_TCP', 6), ('fs_magic', 'AAFS_MAGIC', 1513908720), ('fs_magic', 'CRAMFS_MAGIC', 1161678120), ('fs_magic', 'FUSE_SUPER_MAGIC', 1702057286), ('fs_magic', 'MINIX2_SUPER_MAGIC', 9320), ('fs_magic', 'OPENPROM_SUPER_MAGIC', 40865), ('fs_magic', 'PROC_SUPER_MAGIC', 40864), ('fs_magic', 'SECRETMEM_MAGIC', 1397048141), ('fs_magic', 'SMB2_SUPER_MAGIC', 4266872130), ('fs_magic', 'UDF_SUPER_MAGIC', 352400198), ('fs_magic', 'ZONEFS_MAGIC', 1515144787), ('socket_family', 'AF_DECnet', 12), ('socket_family', 'AF_ISDN', 34), ('socket_family', 'AF_NETROM', 6), ('socket_family', 'AF_PHONET', 35), ('socket_family', 'AF_ROUTE', 16), ('socket_type', 'SOCK_RAW', 3), ('socket_type', 'SOCK_SEQPACKET', 5)
, ('family_protocol', 'IPPROTO_IPV6', 41), ('family_protocol', 'IPPROTO_SCTP', 132), ('fs_magic', 'AFS_SUPER_MAGIC', 1397113167), ('fs_magic', 'BCACHEFS_SUPER_MAGIC', 3393526350), ('fs_magic', 'DAXFS_MAGIC', 1684300152), ('fs_magic', 'DMA_BUF_MAGIC', 1145913666), ('fs_magic', 'EFIVARFS_MAGIC', 3730735588), ('fs_magic', 'EXT2_SUPER_MAGIC', 61267), ('fs_magic', 'MINIX_SUPER_MAGIC', 4991), ('fs_magic', 'PIPEFS_MAGIC', 1346981957), ('fs_magic', 'QNX4_SUPER_MAGIC', 47), ('fs_magic', 'SYSFS_MAGIC', 1650812274), ('socket_family', 'AF_IEEE802154', 36), ('socket_family', 'AF_IUCV', 32), ('socket_family', 'AF_MCTP', 45), ('socket_family', 'AF_NETLINK', 16), ('socket_family', 'AF_UNIX', 1);
