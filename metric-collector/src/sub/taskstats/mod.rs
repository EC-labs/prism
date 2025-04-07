use log::info;
use std::{
    collections::HashMap,
    ffi::CStr,
    io::Read,
    mem::MaybeUninit,
    ptr::NonNull,
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    libbpf_sys::{self, bpf_iter_attach_opts, bpf_iter_link_info, bpf_program__attach_iter},
    skel::{OpenSkel, SkelBuilder},
    AsRawLibbpf, Error, Iter, Link, MapCore, MapHandle, ProgramMut, RingBufferBuilder,
};
use log::debug;

mod taskstats {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/taskstats/bpf/taskstats.skel.rs"
    ));
}

mod bindings {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/taskstats/taskstats.bindings.rs"
    ));
}

use bindings::task_delay_acct;
use taskstats::TaskstatsSkelBuilder;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn validate_bpf_ret<T>(ptr: *mut T) -> libbpf_rs::Result<NonNull<T>> {
    // SAFETY: `libbpf_get_error` is always safe to call.
    match unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) } {
        0 => {
            debug_assert!(!ptr.is_null());
            // SAFETY: libbpf guarantees that if NULL is returned an
            //         error it set, so we will always end up with a
            //         valid pointer when `libbpf_get_error` returned 0.
            let ptr = unsafe { NonNull::new_unchecked(ptr) };
            Ok(ptr)
        }
        err => Err(Error::from_raw_os_error(-err as i32)),
    }
}

pub struct TaskStats<'conn> {
    links: HashMap<u32, Link>,
    link_rx: Receiver<(u32, Link)>,
    taskstats_appender: Appender<'conn>,
    pid_map: MapHandle,
}

impl<'conn> TaskStats<'conn> {
    pub fn new(pid_map: MapHandle, pid_rb: MapHandle, conn: &'conn Connection) -> Result<Self> {
        bump_memlock_rlimit()?;

        let (tx, rx) = mpsc::channel();
        let init_pids: Vec<u32> = pid_map
            .keys()
            .map(|pid| {
                let pid: [u8; 4] = pid.as_slice().try_into().unwrap();
                unsafe { std::mem::transmute::<_, u32>(pid) }
            })
            .collect();

        std::thread::spawn(move || {
            let mut open_object = MaybeUninit::uninit();
            let skel_builder = TaskstatsSkelBuilder::default();
            let open_skel = skel_builder.open(&mut open_object)?;
            let skel = open_skel.load()?;

            for pid in init_pids {
                let link = create_link_for_pid(pid, &skel.progs.get_tasks)?;
                let Ok(_) = tx.send((pid, link)) else {
                    return Err(mpsc::SendError("failed to send link").into());
                };
            }

            let mut builder = RingBufferBuilder::new();
            builder.add(&pid_rb as _, rb_callback(tx, skel.progs.get_tasks))?;
            let rb = builder.build()?;

            loop {
                if let Err(_e) = rb.poll(Duration::from_secs(1)) {
                    break;
                }
            }
            Ok(()) as Result<()>
        });

        Self::init_store(conn)?;
        Ok(Self {
            pid_map,
            links: HashMap::new(),
            link_rx: rx,
            taskstats_appender: conn.appender("taskstats")?,
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE taskstats (
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
                            ts, 
                            lag(ts, 1) OVER (PARTITION BY tid ORDER BY ts) as ts_last,
                            pid,
                            tid, 
                            comm,
                            run_time_total as run_time_curr, 
                            lag(run_time_total, 1) OVER (PARTITION BY tid ORDER BY ts) as run_time_last,
                            rq_time_total as rq_time_curr, 
                            lag(rq_time_total, 1) OVER (PARTITION BY tid ORDER BY ts) as rq_time_last,
                            uninterruptible_total as uninterruptible_time_curr, 
                            lag(uninterruptible_total, 1) OVER (PARTITION BY tid ORDER BY ts) as uninterruptible_time_last,
                            blkio_time_total as blkio_time_curr, 
                            lag(blkio_time_total, 1) OVER (PARTITION BY tid ORDER BY ts) as blkio_time_last,
                        FROM taskstats
                    )
                )
                WHERE 
                    time_diff IS NOT NULL;
            ",
        )?;
        Ok(())
    }

    fn store(&mut self, records: &[task_delay_acct]) -> Result<()> {
        debug!("store {} taskstats records", records.len());
        for record in records {
            let comm = unsafe { CStr::from_ptr(&record.comm as _).to_str()? };
            let ts = Duration::from_nanos(crate::extract::boot_to_epoch(record.ts));
            self.taskstats_appender.append_row([
                &ts as &dyn ToSql,
                &record.pid,
                &record.tid,
                &comm,
                &record.nvcsw,
                &record.nivcsw,
                &record.runtime_total,
                &record.rq_delay_total,
                &record.rq_count,
                &record.blkio_delay_total,
                &record.blkio_count,
                &record.uninterruptible_delay_total,
                &record.freepages_delay_total,
                &record.freepages_count,
                &record.thrashing_delay_total,
                &record.thrashing_count,
                &record.swapin_delay_total,
                &record.swapin_count,
            ])?;
        }
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        while let Ok((pid, link)) = self.link_rx.try_recv() {
            self.links.entry(pid).or_insert_with(|| {
                info!("discovered {pid}");
                link
            });
        }
        let mut remove = Vec::new();
        let mut buf = Vec::new();
        for (pid, link) in self.links.iter() {
            let mut iterator = Iter::new(link)?;
            let bytes = iterator.read_to_end(&mut buf);
            if bytes.is_err() || matches!(bytes, Ok(bytes) if bytes == 0) {
                remove.push(*pid);
                continue;
            }
        }

        for pid in remove {
            self.links.remove(&pid);
            self.pid_map.delete(&pid.to_ne_bytes())?;
            info!("remove {pid}");
        }

        if buf.len() == 0 {
            return Ok(());
        }

        let records = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr() as *const task_delay_acct,
                buf.len() / size_of::<task_delay_acct>(),
            )
        };

        self.store(records)?;

        Ok(())
    }
}

fn create_link_for_pid(pid: u32, get_tasks: &ProgramMut) -> Result<Link> {
    let mut linfo = bpf_iter_link_info::default();
    let mut opts = bpf_iter_attach_opts::default();
    linfo.task.pid = pid;
    opts.sz = size_of::<bpf_iter_attach_opts>() as _;
    opts.link_info = &mut linfo;
    opts.link_info_len = size_of::<bpf_iter_link_info>() as _;
    let ptr = unsafe { bpf_program__attach_iter(get_tasks.as_libbpf_object().as_ptr(), &opts) };
    let ptr = validate_bpf_ret(ptr).context("failed to attach iterator")?;
    Ok(unsafe { Link::from_ptr(ptr) })
}

fn rb_callback<'conn>(
    tx: Sender<(u32, Link)>,
    get_tasks: ProgramMut,
) -> impl FnMut(&[u8]) -> i32 + use<'_> {
    move |pid: &[u8]| {
        let pid: &[u8; 4] = pid.try_into().unwrap();
        let pid: &u32 = unsafe { std::mem::transmute::<_, _>(pid) };
        let link = create_link_for_pid(*pid, &get_tasks).unwrap();
        let Ok(_) = tx.send((*pid, link)) else {
            return 1;
        };
        0
    }
}
