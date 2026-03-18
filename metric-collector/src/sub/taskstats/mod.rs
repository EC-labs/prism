use log::{info, warn};
use std::{
    collections::HashMap,
    ffi::CStr,
    io::Read,
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd},
    ptr::NonNull,
    sync::mpsc::{self, Receiver, SendError, Sender},
    time::Duration,
};
use tokio::sync::broadcast;

use anyhow::{Context, Result};
use libbpf_rs::{
    libbpf_sys::{self, bpf_iter_attach_opts, bpf_iter_link_info, bpf_program__attach_iter},
    skel::{OpenSkel, Skel, SkelBuilder},
    AsRawLibbpf, Error, Iter, Link, MapCore, MapHandle, OpenObject, ProgramMut, RingBuffer,
    RingBufferBuilder,
};
use log::debug;

use crate::event::{Event, TaskstatsEvent};

mod taskstats_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/taskstats/bpf/taskstats.skel.rs"
    ));
}

mod bindings {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(clippy::redundant_static_lifetimes)]
    #![allow(clippy::unreadable_literal)]
    #![allow(clippy::cognitive_complexity)]
    #![allow(clippy::useless_transmute)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/taskstats/taskstats.bindings.rs"
    ));
}

use bindings::task_delay_acct;
use taskstats_skel::{TaskstatsSkel, TaskstatsSkelBuilder};

/// Check the returned pointer of a `libbpf` call, extracting any
/// reported errors and converting them.
/// https://github.com/libbpf/libbpf-rs/blob/068db5c5a194bd32596e67f42c4c8111dab7bf58/libbpf-rs/src/util.rs#L73C1-L88C2
fn validate_bpf_ret<T>(ptr: *mut T) -> libbpf_rs::Result<NonNull<T>> {
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

pub struct TaskStatsIter {
    links: HashMap<u32, Link>,
    link_rx: Receiver<(u32, Link)>,
    pid_map: MapHandle,
    pid_sender: broadcast::Sender<u32>,
    machine_id: u32,
    sink_tx: Sender<Event>,
}

impl TaskStatsIter {
    pub fn new(
        pid_map: MapHandle,
        pid_rb: MapHandle,
        sink_tx: Sender<Event>,
        pid_sender: broadcast::Sender<u32>,
        machine_id: u32,
    ) -> Result<Self> {
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
            let open_skel = skel_builder
                .open(&mut open_object)
                .expect("TaskStatsIter skel open failed");
            let skel = open_skel.load().expect("TaskStatsIter skel load failed");

            for pid in init_pids {
                let Ok(link) = create_link_for_pid(pid, &skel.progs.get_tasks) else {
                    warn!("Failed to create a link for pid `{pid}`");
                    continue;
                };
                let Ok(_) = tx.send((pid, link)) else {
                    return Err(mpsc::SendError("failed to send link").into());
                };
            }

            let mut builder = RingBufferBuilder::new();
            builder
                .add(&pid_rb as _, rb_callback(tx, skel.progs.get_tasks))
                .expect("TaskStatsIter failed to register pid_rb callback");
            let rb = builder
                .build()
                .expect("TaskStatsIter failed to build pid_rb handler");

            loop {
                if let Err(_e) = rb.poll(Duration::from_secs(1)) {
                    break;
                }
            }
            Ok(()) as Result<()>
        });

        Ok(Self {
            pid_map,
            pid_sender,
            machine_id,
            links: HashMap::new(),
            link_rx: rx,
            sink_tx,
        })
    }

    fn store(&mut self, records: &[task_delay_acct]) -> Result<(), SendError<Event>> {
        debug!("store {} taskstats records", records.len());
        for record in records {
            let comm = unsafe { CStr::from_ptr(&record.comm as _).to_str() };
            let comm = comm
                .inspect_err(|e| warn!("Failed to parse process comm {e}: {:?}", record.comm))
                .unwrap_or("");
            let ts = Duration::from_nanos(crate::extract::boot_to_epoch(record.ts));
            self.sink_tx.send(Event::Taskstats(TaskstatsEvent {
                machine_id: self.machine_id,
                ts: ts,
                pid: record.pid as u32,
                tid: record.tid as u32,
                comm: comm.to_string(),
                nvcsw: record.nvcsw,
                nivcsw: record.nivcsw,
                run_time_total: record.runtime_total,
                rq_time_total: record.rq_delay_total,
                rq_count: record.rq_count,
                blkio_time_total: record.blkio_delay_total,
                blkio_count: record.blkio_count,
                uninterruptible_total: record.uninterruptible_delay_total,
                freepages_time_total: record.freepages_delay_total,
                freepages_count: record.freepages_count,
                thrashing_time_total: record.thrashing_delay_total,
                thrashing_count: record.thrashing_count,
                swapin_time_total: record.swapin_delay_total,
                swapin_count: record.swapin_count,
            }))?;
        }
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        while let Ok((pid, link)) = self.link_rx.try_recv() {
            // We need to exclude pid 0 from our links map since its Link essentially traverses
            // all tasks in the system
            if pid == 0 {
                continue;
            }

            self.links.entry(pid).or_insert_with(|| {
                info!("discovered {pid}");
                self.pid_sender.send(pid).unwrap();
                link
            });
        }
        let mut remove = Vec::new();
        let mut buf = Vec::new();
        for (pid, link) in self.links.iter() {
            let mut iterator = match Iter::new(link) {
                Ok(iterator) => iterator,
                Err(e) => {
                    warn!("Failed to create Iter for pid `{pid}`: {e}");
                    continue;
                }
            };
            let bytes = iterator.read_to_end(&mut buf);
            if bytes.is_err() || matches!(bytes, Ok(bytes) if bytes == 0) {
                remove.push(*pid);
            }
        }

        for pid in remove {
            self.links.remove(&pid);
            if let Err(e) = self.pid_map.delete(&pid.to_ne_bytes()) {
                warn!("Failed to remove pid `{pid}` from pid_map: `{e}`");
            }
            info!("remove {pid}");
        }

        if buf.is_empty() {
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

pub struct TaskStatsTrace<'obj> {
    _skel: TaskstatsSkel<'obj>,
    taskstats_rb: RingBuffer<'obj>,
}

impl<'obj> TaskStatsTrace<'obj> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        sink_tx: Sender<Event>,
        pid_map: BorrowedFd,
        pid_rb: MapHandle,
        machine_id: u32,
    ) -> Result<Self> {
        let skel_builder = TaskstatsSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .expect("TaskStatsTrace skel open failed");
        open_skel
            .maps
            .pids
            .reuse_fd(pid_map)
            .expect("TaskStatsTrace pid_map reuse failed");
        open_skel
            .maps
            .pid_rb
            .reuse_fd(pid_rb.as_fd())
            .expect("TaskStatsTrace pid_rb reuse failed");
        let mut skel = open_skel.load().expect("TaskStatsTrace skel load failed");
        let mut builder = RingBufferBuilder::new();
        builder
            .add(
                &skel.maps.taskstats_rb,
                wrapped_callback(sink_tx.clone(), machine_id),
            )
            .expect("TaskStatsTrace failed to register taskstats_rb callback");
        let taskstats_rb = builder
            .build()
            .expect("TaskStatsTrace failed to build taskstats_rb handler");
        if let Err(e) = skel.attach() {
            warn!("Failed to attach TaskStatsTrace programs:\n{e}");
            return Err(e.into());
        }

        Ok(Self {
            _skel: skel,
            taskstats_rb,
        })
    }

    pub fn sample(&mut self) -> Result<(), SendError<Event>> {
        if let Err(e) = self.taskstats_rb.consume() {
            warn!("Unexpected error while consuming from taskstats_rb: {e}");
        };
        Ok(())
    }
}

/// Creates a libbpf_rs::link::Link for a pid
///
/// # Errors
///
/// This function propagates libbpf errors from resulting from `bpf_program__attach_iter`
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

fn rb_callback(
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

fn wrapped_callback(sink_tx: Sender<Event>, machine_id: u32) -> impl FnMut(&[u8]) -> i32 {
    move |data: &[u8]| {
        let data: &[u8; size_of::<task_delay_acct>()] =
            &data[..size_of::<task_delay_acct>()].try_into().unwrap();
        let record: &task_delay_acct = unsafe { std::mem::transmute(data) };
        let comm = unsafe { CStr::from_ptr(&record.comm as _).to_str().unwrap() };
        let ts = Duration::from_nanos(crate::extract::boot_to_epoch(record.ts));
        let res = sink_tx.send(Event::Taskstats(TaskstatsEvent {
            machine_id: machine_id,
            ts: ts,
            pid: record.pid as u32,
            tid: record.tid as u32,
            comm: comm.to_string(),
            nvcsw: record.nvcsw,
            nivcsw: record.nivcsw,
            run_time_total: record.runtime_total,
            rq_time_total: record.rq_delay_total,
            rq_count: record.rq_count,
            blkio_time_total: record.blkio_delay_total,
            blkio_count: record.blkio_count,
            uninterruptible_total: record.uninterruptible_delay_total,
            freepages_time_total: record.freepages_delay_total,
            freepages_count: record.freepages_count,
            thrashing_time_total: record.thrashing_delay_total,
            thrashing_count: record.thrashing_count,
            swapin_time_total: record.swapin_delay_total,
            swapin_count: record.swapin_count,
        }));

        match res {
            Err(_) => 1,
            Ok(()) => 0,
        }
    }
}
