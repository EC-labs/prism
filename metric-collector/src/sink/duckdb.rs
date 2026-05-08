use crate::event::Event;
use anyhow::Result;
use duckdb::{Appender, Connection, ToSql};
use libc::{geteuid, seteuid};
use log::{error, info, trace};
use std::sync::{mpsc::Receiver, Arc, Mutex};
use std::thread::JoinHandle;
use std::{env, path::Path, time::Duration};

pub struct DuckdbSink;

impl DuckdbSink {
    pub fn new(
        terminate_flag: Arc<Mutex<bool>>,
        path_string: &str,
        sink_rx: Receiver<Event>,
    ) -> Result<JoinHandle<Result<()>>> {
        let euid = unsafe { geteuid() };
        let uid = env::var("SUDO_UID")
            .unwrap_or(format!("{euid}"))
            .parse::<u32>()?;
        unsafe { seteuid(uid) };
        let path = Path::new(&*path_string);
        let prefix = path.parent().unwrap();
        info!("Duckdb database connection {path_string}");
        std::fs::create_dir_all(prefix).unwrap();
        let conn = Connection::open(&*path_string)?;
        unsafe { seteuid(euid) };
        Self::init_schema(&conn)?;

        Ok(std::thread::spawn(move || {
            let mut appender = DuckdbAppender::new(&conn)?;
            loop {
                let Ok(msg) = sink_rx.recv_timeout(Duration::from_millis(100)) else {
                    if *terminate_flag.lock().unwrap() {
                        break;
                    }
                    continue;
                };
                appender.produce(msg)?;
            }
            Ok(())
        }))
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
            CREATE OR REPLACE TABLE linux_consts (
                const_type VARCHAR,
                const_name VARCHAR,
                value UINTEGER,
            );
            CREATE OR REPLACE TABLE iowait (
                machine_id UINTEGER,
                ts_s TIMESTAMP,
                pid UINTEGER,
                tid UINTEGER,
                part0 UBIGINT,
                bdev UBIGINT,
                op UTINYINT,
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

            CREATE OR REPLACE TABLE aio_getevents (
                machine_id UINTEGER,
                ts_s TIMESTAMP,
                pid UINTEGER,
                tid UINTEGER,
                aioctx UBIGINT,
                total_time UBIGINT,
                total_requests UBIGINT,
            );

            CREATE OR REPLACE TABLE aio_submit (
                machine_id UINTEGER,
                ts_s TIMESTAMP,
                pid UINTEGER,
                tid UINTEGER,
                aioctx UBIGINT,
                total_requests UBIGINT,
            );

            CREATE OR REPLACE TABLE aio_file (
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

            CREATE OR REPLACE TABLE tcp_discovery (
                local_machine_id    UINTEGER,
                local_inode_id      UBIGINT,
                remote_machine_id   UINTEGER,
                remote_inode_id     UBIGINT,
                inserted_at         TIMESTAMP,
            );

            CREATE OR REPLACE TABLE vfs (
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

            CREATE OR REPLACE TABLE futex_wait (
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

            CREATE OR REPLACE TABLE futex_wake (
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

            CREATE OR REPLACE TABLE muxio_wait (
                machine_id UINTEGER,
                ts_s TIMESTAMP,
                pid UINTEGER,
                tid UINTEGER,
                is_epoll BOOLEAN,
                poll_id UBIGINT,
                total_time UBIGINT,
                total_requests UBIGINT,
            );

            CREATE OR REPLACE TABLE muxio_file (
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
            
            CREATE OR REPLACE TABLE socket_context (
                machine_id UINTEGER,
                inode_id UBIGINT,
                family          USMALLINT, 
                type            USMALLINT, 
                protocol        USMALLINT, 
            );

            CREATE OR REPLACE TABLE socket_inet (
                machine_id UINTEGER,
                inode_id        UBIGINT,
                netns_cookie    UBIGINT,
                src_address     VARCHAR,
                src_port        USMALLINT, 
                dst_address     VARCHAR,
                dst_port        USMALLINT, 
            );

            CREATE OR REPLACE TABLE socket_map (
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

            CREATE OR REPLACE VIEW taskstats_view AS 
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
            

            CREATE OR REPLACE TABLE docker (
                machine_id UINTEGER,
                cgroup          VARCHAR,
                id              VARCHAR,
                name            VARCHAR,
                image_name      VARCHAR,
                image_hash      VARCHAR,
            );
            CREATE OR REPLACE TABLE k8s (
                machine_id UINTEGER,
                cgroup          VARCHAR,
                id              VARCHAR,
                namespace       VARCHAR,
                pod_name        VARCHAR,
                container_name  VARCHAR,
                image_name      VARCHAR,
            );

            CREATE OR REPLACE TABLE process_context (
                machine_id UINTEGER,
                pid         UINTEGER,
                cgroup      VARCHAR,
                argv        VARCHAR,
                exe         VARCHAR,
            );
            ",
        )?;
        Ok(())
    }
}

pub struct DuckdbAppender<'conn> {
    linux_consts_appender: Appender<'conn>,
    iowait_appender: Appender<'conn>,
    aio_getevents_appender: Appender<'conn>,
    aio_submit_appender: Appender<'conn>,
    aio_file_appender: Appender<'conn>,
    tcp_discovery_appender: Appender<'conn>,
    vfs_appender: Appender<'conn>,
    futex_wait_appender: Appender<'conn>,
    futex_wake_appender: Appender<'conn>,
    muxio_wait_appender: Appender<'conn>,
    muxio_file_appender: Appender<'conn>,
    socket_context_appender: Appender<'conn>,
    socket_inet_appender: Appender<'conn>,
    socket_map_appender: Appender<'conn>,
    taskstats_appender: Appender<'conn>,
    docker_appender: Appender<'conn>,
    k8s_appender: Appender<'conn>,
    process_context_appender: Appender<'conn>,
}

unsafe impl Send for DuckdbAppender<'_> {}

impl<'conn> DuckdbAppender<'conn> {
    pub fn new(conn: &'conn Connection) -> Result<Self> {
        Ok(Self {
            linux_consts_appender: conn.appender("linux_consts")?,
            iowait_appender: conn.appender("iowait")?,
            aio_getevents_appender: conn.appender("aio_getevents")?,
            aio_submit_appender: conn.appender("aio_submit")?,
            aio_file_appender: conn.appender("aio_file")?,
            tcp_discovery_appender: conn.appender("tcp_discovery")?,
            vfs_appender: conn.appender("vfs")?,
            futex_wait_appender: conn.appender("futex_wait")?,
            futex_wake_appender: conn.appender("futex_wake")?,
            muxio_wait_appender: conn.appender("muxio_wait")?,
            muxio_file_appender: conn.appender("muxio_file")?,
            socket_context_appender: conn.appender("socket_context")?,
            socket_inet_appender: conn.appender("socket_inet")?,
            socket_map_appender: conn.appender("socket_map")?,
            taskstats_appender: conn.appender("taskstats")?,
            docker_appender: conn.appender("docker")?,
            k8s_appender: conn.appender("k8s")?,
            process_context_appender: conn.appender("process_context")?,
        })
    }

    fn produce(&mut self, event: Event) -> Result<()> {
        trace!("Store event {event:?}");
        match event {
            Event::LinuxConsts(e, _) => {
                self.linux_consts_appender.append_row([
                    &e.const_type as &dyn ToSql,
                    &e.const_name,
                    &e.value,
                ])?;
                Ok(())
            }
            Event::IoWait(e) => {
                self.iowait_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.pid,
                    &e.tid,
                    &e.part0,
                    &e.bdev,
                    &e.op,
                    &e.total_time,
                    &e.sector_cnt,
                    &e.total_requests,
                    &e.hist0,
                    &e.hist1,
                    &e.hist2,
                    &e.hist3,
                    &e.hist4,
                    &e.hist5,
                    &e.hist6,
                    &e.hist7,
                ])?;
                Ok(())
            }
            Event::AioGetevents(e) => {
                self.aio_getevents_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.pid,
                    &e.tid,
                    &e.aioctx,
                    &e.total_time,
                    &e.total_requests,
                ])?;
                Ok(())
            }
            Event::AioSubmit(e) => {
                self.aio_submit_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.pid,
                    &e.tid,
                    &e.aioctx,
                    &e.total_requests,
                ])?;
                Ok(())
            }
            Event::AioFile(e) => {
                self.aio_file_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.aioctx,
                    &e.isreg,
                    &e.fs_magic,
                    &e.device_id,
                    &e.inode_id,
                    &e.part0,
                    &e.bdev,
                    &e.mode,
                    &e.hist0,
                    &e.hist1,
                    &e.hist2,
                    &e.hist3,
                    &e.hist4,
                    &e.hist5,
                    &e.hist6,
                    &e.hist7,
                ])?;
                Ok(())
            }
            Event::TcpDiscovery(e) => {
                if let Err(e) = self.tcp_discovery_appender.append_row([
                    &e.local_machine_id as &dyn ToSql,
                    &e.local_inode_id,
                    &e.remote_machine_id,
                    &e.remote_inode_id,
                    &e.inserted_at,
                ]) {
                    error!("failed to append row");
                    panic!("{e}");
                };
                Ok(())
            }
            Event::Vfs(e) => {
                self.vfs_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.pid,
                    &e.tid,
                    &e.fs_magic,
                    &e.device_id,
                    &e.inode_id,
                    &e.op,
                    &e.total_time,
                    &e.total_requests,
                    &e.hist0,
                    &e.hist1,
                    &e.hist2,
                    &e.hist3,
                    &e.hist4,
                    &e.hist5,
                    &e.hist6,
                    &e.hist7,
                ])?;
                Ok(())
            }
            Event::FutexWait(e) => {
                self.futex_wait_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.pid,
                    &e.tid,
                    &e.futex_key_addr,
                    &e.futex_key_word,
                    &e.futex_key_offset,
                    &e.total_requests,
                    &e.total_time,
                    &e.hist0,
                    &e.hist1,
                    &e.hist2,
                    &e.hist3,
                    &e.hist4,
                    &e.hist5,
                    &e.hist6,
                    &e.hist7,
                ])?;
                Ok(())
            }
            Event::FutexWake(e) => {
                self.futex_wake_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.pid,
                    &e.tid,
                    &e.futex_key_addr,
                    &e.futex_key_word,
                    &e.futex_key_offset,
                    &e.total_requests,
                    &e.successful_count,
                ])?;
                Ok(())
            }
            Event::MuxioWait(e) => {
                self.muxio_wait_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.pid,
                    &e.tid,
                    &e.is_epoll,
                    &e.poll_id,
                    &e.total_time,
                    &e.total_requests,
                ])?;
                Ok(())
            }
            Event::MuxioFile(e) => {
                self.muxio_file_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts_s,
                    &e.poll_id,
                    &e.fs_magic,
                    &e.device_id,
                    &e.inode_id,
                    &e.mode,
                    &e.hist0,
                    &e.hist1,
                    &e.hist2,
                    &e.hist3,
                    &e.hist4,
                    &e.hist5,
                    &e.hist6,
                    &e.hist7,
                ])?;
                Ok(())
            }
            Event::SocketContext(e) => {
                self.socket_context_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.inode_id,
                    &e.family,
                    &e.type_,
                    &e.protocol,
                ])?;
                Ok(())
            }
            Event::SocketInet(e) => {
                self.socket_inet_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.inode_id,
                    &e.netns_cookie,
                    &e.src_address,
                    &e.src_port,
                    &e.dst_address,
                    &e.dst_port,
                ])?;
                Ok(())
            }
            Event::SocketMap(e) => {
                self.socket_map_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.sock1_inode_id,
                    &e.sock2_inode_id,
                ])?;
                Ok(())
            }
            Event::Taskstats(e) => {
                self.taskstats_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.ts,
                    &e.pid,
                    &e.tid,
                    &e.comm,
                    &e.nvcsw,
                    &e.nivcsw,
                    &e.run_time_total,
                    &e.rq_time_total,
                    &e.rq_count,
                    &e.blkio_time_total,
                    &e.blkio_count,
                    &e.uninterruptible_total,
                    &e.freepages_time_total,
                    &e.freepages_count,
                    &e.thrashing_time_total,
                    &e.thrashing_count,
                    &e.swapin_time_total,
                    &e.swapin_count,
                ])?;
                Ok(())
            }
            Event::Docker(e) => {
                self.docker_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.cgroup,
                    &e.id,
                    &e.name,
                    &e.image_name,
                    &e.image_hash,
                ])?;
                Ok(())
            }
            Event::K8s(e) => {
                self.k8s_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.cgroup,
                    &e.id,
                    &e.namespace,
                    &e.pod_name,
                    &e.container_name,
                    &e.image_name,
                ])?;
                Ok(())
            }
            Event::ProcessContext(e) => {
                self.process_context_appender.append_row([
                    &e.machine_id as &dyn ToSql,
                    &e.pid,
                    &e.cgroup,
                    &e.argv,
                    &e.exe,
                ])?;
                Ok(())
            }
        }
    }
}
