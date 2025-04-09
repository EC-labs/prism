use anyhow::Result;
use dashmap::{DashMap, Map};
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC};
use log::{debug, error};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd},
    rc::Rc,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    time::Duration,
};

mod muxio {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/muxio/bpf/muxio.skel.rs"
    ));
}

mod bindings {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(clippy::const_static_lifetime)]
    #![allow(clippy::unreadable_literal)]
    #![allow(clippy::cyclomatic_complexity)]
    #![allow(clippy::useless_transmute)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/muxio/muxio.bindings.rs"
    ));
}

use bindings::*;
use muxio::*;

pub struct Muxio<'conn> {
    rx: Receiver<i64>,
    poll_state: PollState,
    sharded_events: Arc<DashMap<i64, BTreeMap<u64, Vec<MuxioEvent>>>>,
    muxio_appender: Appender<'conn>,
    muxio_file_appender: Appender<'conn>,
}

impl<'conn> Muxio<'conn> {
    pub fn new(pid_map: BorrowedFd, conn: &'conn Connection) -> Result<Self> {
        Self::init_store(conn)?;

        let (tx, rx) = mpsc::channel::<i64>();

        let sharded_events = Arc::new(DashMap::new());
        let pid_map = pid_map.try_clone_to_owned()?;

        let bpf_sharded_events = sharded_events.clone();
        std::thread::spawn(move || {
            let mut open_object = MaybeUninit::uninit();
            let skel_builder = MuxioSkelBuilder::default();
            let mut open_skel = skel_builder.open(&mut open_object)?;
            open_skel.maps.pids.reuse_fd(pid_map.as_fd())?;

            let mut skel = open_skel.load()?;
            let mut builder = RingBufferBuilder::new();
            let last_snapshot = Rc::new(RefCell::new(None));
            builder.add(
                &skel.maps.rb,
                rb_callback(bpf_sharded_events, tx.clone(), last_snapshot.clone()),
            )?;
            let rb = builder.build()?;
            skel.attach()?;

            loop {
                rb.poll(Duration::from_millis(100)).unwrap();
                let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
                unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
                let mut v = last_snapshot.borrow_mut();

                match *v {
                    None => {
                        let snapshot = ts.tv_sec - 2;
                        *v = Some(snapshot);
                        let Ok(_) = tx.send(snapshot) else {
                            break;
                        };
                    }
                    Some(last) => {
                        if last < ts.tv_sec - 2 {
                            let snapshot = last + 1;
                            *v = Some(snapshot);
                            let Ok(_) = tx.send(snapshot) else {
                                break;
                            };
                        }
                    }
                }
            }

            Ok(()) as Result<()>
        });

        Ok(Self {
            rx,
            sharded_events,
            muxio_appender: conn.appender("muxio_wait")?,
            muxio_file_appender: conn.appender("muxio_file_wait")?,
            poll_state: PollState::new(),
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE muxio_wait (
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    is_epoll BOOLEAN,
                    poll_id UBIGINT,
                    total_time UBIGINT,
                    total_requests UBIGINT,
                );

                CREATE OR REPLACE TABLE muxio_file_wait (
                    ts_s TIMESTAMP,
                    is_epoll BOOLEAN,
                    poll_id UBIGINT,
                    fs_magic UINTEGER,
                    device_id UINTEGER,
                    inode_id UBIGINT,
                    total_time UBIGINT,
                    count UBIGINT,
                );
            ",
        )?;
        Ok(())
    }

    fn store(&mut self, snapshot: HashMap<StatsKey, Stats>, snapshot_ts_s: u64) -> Result<()> {
        let ts_s = crate::extract::boot_to_epoch(snapshot_ts_s * 1_000_000_000);
        let snapshot_ts_s = Duration::from_nanos(ts_s);
        for (key, stats) in snapshot {
            use Stats::*;
            use StatsKey::*;
            match (&key, &stats) {
                (Poll { key, tgid, tid }, PollStats { total_time, count }) => {
                    let (is_epoll, id) = match key {
                        PollKey::Epoll(address) => (true, address),
                        PollKey::Poll(tgid_pid) => (false, tgid_pid),
                    };
                    self.muxio_appender.append_row([
                        &snapshot_ts_s as &dyn ToSql,
                        &tgid,
                        &tid,
                        &is_epoll,
                        &id,
                        total_time,
                        count,
                    ])?;
                }
                (PollFile(key, bri), BriStats { total_time, count }) => {
                    let (is_epoll, id) = match key {
                        PollKey::Epoll(address) => (true, address),
                        PollKey::Poll(tgid_pid) => (false, tgid_pid),
                    };
                    self.muxio_file_appender.append_row([
                        &snapshot_ts_s as &dyn ToSql,
                        &is_epoll,
                        &id,
                        &bri.magic,
                        &bri.i_rdev,
                        &bri.i_ino,
                        total_time,
                        count,
                    ])?;
                }
                _ => {
                    error!("unexpected key stat combination {:?} {:?}", key, stats);
                }
            }
        }
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        let mut snapshots = Vec::new();
        while let Ok(snapshot) = self.rx.try_recv() {
            snapshots.push(snapshot);
        }

        for snapshot in snapshots {
            let mut btree = self
                .sharded_events
                .remove(&snapshot)
                .map(|(_, btree)| btree)
                .unwrap_or_default();
            debug!("processing {} muxio events", btree.len());

            while let Some((_, events)) = btree.pop_first() {
                for event in events {
                    self.poll_state.process(event);
                }
            }

            let stats = self.poll_state.snapshot(snapshot as u64);
            self.store(stats, snapshot as u64)?;

            debug!("snapshot {}", snapshot);
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Bri {
    magic: u32,
    i_rdev: u32,
    i_ino: u64,
}

#[derive(Debug)]
enum MuxioEvent {
    EpollStart {
        ts: u64,
        tgid_pid: u64,
        ep_address: u64,
    },
    EpollEnd {
        ts: u64,
        tgid_pid: u64,
        ep_address: u64,
    },
    EpollInsert {
        ts: u64,
        ep_address: u64,
        bri: Bri,
    },
    EpollRemove {
        ts: u64,
        ep_address: u64,
        bri: Bri,
    },
    PollStart {
        ts: u64,
        tgid_pid: u64,
    },
    PollEnd {
        ts: u64,
        tgid_pid: u64,
    },
    PollFileRegister {
        ts: u64,
        tgid_pid: u64,
        bri: Bri,
    },
}

impl MuxioEvent {
    fn get_timestamp(&self) -> u64 {
        use MuxioEvent::*;
        match self {
            PollStart { ts, .. }
            | PollEnd { ts, .. }
            | PollFileRegister { ts, .. }
            | EpollStart { ts, .. }
            | EpollEnd { ts, .. }
            | EpollInsert { ts, .. }
            | EpollRemove { ts, .. } => *ts,
        }
    }
}

impl From<&poll_start_event> for MuxioEvent {
    fn from(value: &poll_start_event) -> Self {
        Self::PollStart {
            ts: value.ts,
            tgid_pid: value.tgid_pid,
        }
    }
}

impl From<&poll_end_event> for MuxioEvent {
    fn from(value: &poll_end_event) -> Self {
        Self::PollEnd {
            ts: value.ts,
            tgid_pid: value.tgid_pid,
        }
    }
}

impl From<&poll_register_file_event> for MuxioEvent {
    fn from(value: &poll_register_file_event) -> Self {
        Self::PollFileRegister {
            bri: Bri {
                magic: value.magic,
                i_rdev: value.i_rdev,
                i_ino: value.i_ino,
            },
            tgid_pid: value.tgid_pid,
            ts: value.ts,
        }
    }
}

impl From<&epoll_start_event> for MuxioEvent {
    fn from(value: &epoll_start_event) -> Self {
        Self::EpollStart {
            ts: value.ts,
            tgid_pid: value.tgid_pid,
            ep_address: value.ep_address,
        }
    }
}

impl From<&epoll_end_event> for MuxioEvent {
    fn from(value: &epoll_end_event) -> Self {
        Self::EpollEnd {
            ts: value.ts,
            tgid_pid: value.tgid_pid,
            ep_address: value.ep_address,
        }
    }
}

impl From<&epoll_register_file_event> for MuxioEvent {
    fn from(value: &epoll_register_file_event) -> Self {
        match value.event {
            0x5 => Self::EpollInsert {
                ts: value.ts,
                ep_address: value.ep_address,
                bri: Bri {
                    magic: value.magic,
                    i_rdev: value.i_rdev,
                    i_ino: value.i_ino,
                },
            },
            0x6 => Self::EpollRemove {
                ts: value.ts,
                ep_address: value.ep_address,
                bri: Bri {
                    magic: value.magic,
                    i_rdev: value.i_rdev,
                    i_ino: value.i_ino,
                },
            },
            _ => {
                error!(
                    "invalid event type from epoll_register_file_event {}",
                    value.event
                );
                panic!();
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum StatsKey {
    Poll { key: PollKey, tid: u32, tgid: u32 },
    PollFile(PollKey, Bri),
}

impl StatsKey {
    fn from_poll(poll: PollKey, tgid_pid: u64) -> Self {
        Self::Poll {
            key: poll,
            tgid: (tgid_pid >> 32) as u32,
            tid: (tgid_pid & ((1 << 32) - 1)) as u32,
        }
    }

    fn from_poll_file(poll_id: PollKey, file: Bri) -> Self {
        Self::PollFile(poll_id, file)
    }
}

#[derive(Debug)]
enum Stats {
    PollStats { total_time: u64, count: u64 },
    BriStats { total_time: u64, count: u64 },
}

impl Stats {
    fn acct(&mut self, elapsed_time: u64, inc_count: bool) {
        use Stats::*;
        match self {
            PollStats { total_time, count } | BriStats { total_time, count } => {
                *total_time += elapsed_time;
                if inc_count {
                    *count += 1;
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PollKey {
    /// Holds struct eventpoll *ep kernel address
    Epoll(u64),
    /// Is simply the tgid_pid value of the thread waiting for the fds
    Poll(u64),
}

struct EpollPending {
    count: u64,
    ts_start: u64,
}

struct PollState {
    /// Key:
    ///     the key is the kernel's struct eventpol *ep address
    /// Value:
    ///     A counter indicating the times this epoll resources has been waited for
    epoll_pending: HashMap<u64, EpollPending>,
    /// Tracks the start time of a poll/select/epoll start event
    poll_thread: HashMap<(u64, PollKey), u64>,
    /// Holds the files registered with each poll resource
    poll_files: HashMap<PollKey, HashMap<Bri, u64>>,
    /// As events are processed, this struct member is updated. This is also used to provide
    /// snapshots.
    stats: HashMap<StatsKey, Stats>,
}

impl PollState {
    fn new() -> Self {
        Self {
            epoll_pending: HashMap::new(),
            poll_files: HashMap::new(),
            stats: HashMap::new(),
            poll_thread: HashMap::new(),
        }
    }

    fn process(&mut self, event: MuxioEvent) {
        use MuxioEvent::*;
        match event {
            PollStart { ts, tgid_pid } => {
                self.poll_thread
                    .insert((tgid_pid, PollKey::Poll(tgid_pid)), ts);
            }
            PollFileRegister { tgid_pid, bri, ts } => {
                let poll_key = PollKey::Poll(tgid_pid);
                self.poll_files
                    .entry(poll_key)
                    .or_insert_with(|| HashMap::new())
                    .insert(bri, ts);
            }
            PollEnd { ts, tgid_pid } => {
                let poll_key = PollKey::Poll(tgid_pid);
                let Some(ts_start) = self.poll_thread.remove(&(tgid_pid, poll_key.clone())) else {
                    return;
                };
                let key = StatsKey::from_poll(poll_key.clone(), tgid_pid);
                let poll_stats = self.stats.entry(key).or_insert_with(|| Stats::PollStats {
                    total_time: 0,
                    count: 0,
                });
                let shard_start = ts / 1_000_000_000 * 1_000_000_000;
                let diff = u64::min(ts - ts_start, ts - shard_start);
                poll_stats.acct(diff, true);

                let Some(bris) = self.poll_files.remove(&poll_key) else {
                    return;
                };
                for (file, ts) in bris {
                    let key = StatsKey::from_poll_file(poll_key.clone(), file);
                    let bri_stats = self.stats.entry(key).or_insert_with(|| Stats::BriStats {
                        total_time: 0,
                        count: 0,
                    });
                    let diff = u64::min(ts - ts_start, ts - shard_start);
                    bri_stats.acct(diff, true);
                }
            }
            EpollStart {
                ts,
                tgid_pid,
                ep_address,
            } => {
                let ep_pending =
                    self.epoll_pending
                        .entry(ep_address)
                        .or_insert_with(|| EpollPending {
                            count: 0,
                            ts_start: ts,
                        });

                ep_pending.count += 1;
                let poll_key = PollKey::Epoll(ep_address);
                self.poll_thread.insert((tgid_pid, poll_key), ts);
            }
            EpollInsert {
                ts,
                ep_address,
                bri,
            } => {
                let poll_key = PollKey::Epoll(ep_address);
                self.poll_files
                    .entry(poll_key)
                    .or_insert_with(|| HashMap::new())
                    .entry(bri)
                    .or_insert(ts);
            }
            EpollRemove {
                ts,
                ep_address,
                bri,
            } => {
                let poll_key = PollKey::Epoll(ep_address);
                let Some(files) = self.poll_files.get_mut(&poll_key) else {
                    return;
                };

                let Some(EpollPending {
                    ts_start: ep_start, ..
                }) = self.epoll_pending.get(&ep_address)
                else {
                    return;
                };

                let Some(file_start) = files.remove(&bri) else {
                    return;
                };

                let ts_start = u64::max(file_start, *ep_start);

                let key = StatsKey::from_poll_file(poll_key, bri);
                let poll_stats = self.stats.entry(key).or_insert_with(|| Stats::BriStats {
                    total_time: 0,
                    count: 0,
                });

                let shard_start = ts / 1_000_000_000 * 1_000_000_000;
                let diff = u64::min(ts - ts_start, ts - shard_start);
                poll_stats.acct(diff, true);
            }
            EpollEnd {
                ts,
                tgid_pid,
                ep_address,
            } => {
                let poll_key = PollKey::Epoll(ep_address);
                let Some(ts_start) = self.poll_thread.remove(&(tgid_pid, poll_key.clone())) else {
                    return;
                };

                let key = StatsKey::from_poll(poll_key.clone(), tgid_pid);
                let poll_stats = self.stats.entry(key).or_insert_with(|| Stats::PollStats {
                    total_time: 0,
                    count: 0,
                });
                let shard_start = ts / 1_000_000_000 * 1_000_000_000;
                let diff = u64::min(ts - ts_start, ts - shard_start);
                poll_stats.acct(diff, true);

                let Some(EpollPending { count, .. }) = self.epoll_pending.get_mut(&ep_address)
                else {
                    return;
                };

                *count -= 1;
                if *count > 0 {
                    return;
                }

                let Some(EpollPending {
                    ts_start: ep_start, ..
                }) = self.epoll_pending.remove(&ep_address)
                else {
                    error!("expected epoll pending");
                    return;
                };

                let Some(bris) = self.poll_files.get(&poll_key) else {
                    return;
                };
                for (file, file_start) in bris {
                    let key = StatsKey::from_poll_file(poll_key.clone(), file.clone());
                    let bri_stats = self.stats.entry(key).or_insert_with(|| Stats::BriStats {
                        total_time: 0,
                        count: 0,
                    });
                    let ts_start = u64::max(ep_start, *file_start);
                    let diff = u64::min(ts - ts_start, ts - shard_start);
                    bri_stats.acct(diff, true);
                }
            }
        }
    }

    fn snapshot(&mut self, snapshot_s: u64) -> HashMap<StatsKey, Stats> {
        for ((tgid_pid, poll), ts_start) in self.poll_thread.iter() {
            let key = StatsKey::from_poll(poll.clone(), *tgid_pid);
            let poll_stats = self.stats.entry(key).or_insert_with(|| Stats::PollStats {
                total_time: 0,
                count: 0,
            });
            let diff = u64::min((snapshot_s + 1) * 1_000_000_000 - ts_start, 1_000_000_000);
            poll_stats.acct(diff, false);

            if let PollKey::Epoll(_) = poll {
                continue;
            }
            let Some(bris) = self.poll_files.get(poll) else {
                continue;
            };
            for (file, ts_start) in bris {
                let key = StatsKey::from_poll_file(poll.clone(), file.clone());
                let stats = self.stats.entry(key).or_insert_with(|| Stats::BriStats {
                    total_time: 0,
                    count: 0,
                });
                let diff = u64::min((snapshot_s + 1) * 1_000_000_000 - ts_start, 1_000_000_000);
                stats.acct(diff, false);
            }
        }

        for (ep_address, ep_pending) in self.epoll_pending.iter() {
            if ep_pending.count == 0 {
                error!("EpollPending count is 0 and it is still part of epoll_pending");
                continue;
            }

            let ep_start = ep_pending.ts_start;
            let poll_key = PollKey::Epoll(*ep_address);
            let Some(bris) = self.poll_files.get(&poll_key) else {
                continue;
            };

            for (file, file_start) in bris {
                let key = StatsKey::from_poll_file(poll_key.clone(), file.clone());
                let stats = self.stats.entry(key).or_insert_with(|| Stats::BriStats {
                    total_time: 0,
                    count: 0,
                });
                let ts_start = u64::max(ep_start, *file_start);
                let diff = u64::min((snapshot_s + 1) * 1_000_000_000 - ts_start, 1_000_000_000);
                stats.acct(diff, false);
            }
        }

        std::mem::replace(&mut self.stats, HashMap::new())
    }
}

fn rb_callback<'conn>(
    sharded_events: Arc<DashMap<i64, BTreeMap<u64, Vec<MuxioEvent>>>>,
    tx: Sender<i64>,
    last_snapshot: Rc<RefCell<Option<i64>>>,
) -> impl FnMut(&[u8]) -> i32 + use<'conn> {
    move |data: &[u8]| {
        let event = match data[0] {
            0x0 => {
                let data: &[u8; size_of::<poll_start_event>()] =
                    &data[..size_of::<poll_start_event>()].try_into().unwrap();
                let data: &poll_start_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            0x1 => {
                let data: &[u8; size_of::<poll_end_event>()] =
                    &data[..size_of::<poll_end_event>()].try_into().unwrap();
                let data: &poll_end_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            0x2 => {
                let data: &[u8; size_of::<poll_register_file_event>()] = &data
                    [..size_of::<poll_register_file_event>()]
                    .try_into()
                    .unwrap();
                let data: &poll_register_file_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            0x3 => {
                let data: &[u8; size_of::<epoll_start_event>()] =
                    &data[..size_of::<epoll_start_event>()].try_into().unwrap();
                let data: &epoll_start_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            0x4 => {
                let data: &[u8; size_of::<epoll_end_event>()] =
                    &data[..size_of::<epoll_end_event>()].try_into().unwrap();
                let data: &epoll_end_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            0x5 => {
                let data: &[u8; size_of::<epoll_register_file_event>()] = &data
                    [..size_of::<epoll_register_file_event>()]
                    .try_into()
                    .unwrap();
                let data: &epoll_register_file_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            0x6 => {
                let data: &[u8; size_of::<epoll_register_file_event>()] = &data
                    [..size_of::<epoll_register_file_event>()]
                    .try_into()
                    .unwrap();
                let data: &epoll_register_file_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            _ => {
                error!("unexpected event type {}", data[0]);
                return 0;
            }
        };

        let ts = event.get_timestamp();
        let shard = (ts / 1_000_000_000) as i64;
        let mut shard_events = sharded_events
            ._entry(shard)
            .or_insert_with(|| BTreeMap::new());
        shard_events
            .entry(ts)
            .or_insert_with(|| Vec::new())
            .push(event);
        let mut v = last_snapshot.borrow_mut();
        match *v {
            None => {
                let snapshot = shard - 2;
                *v = Some(snapshot);
                if let Err(_) = tx.send(snapshot) {
                    return 1;
                }
            }
            Some(last) => {
                if last < shard - 2 {
                    let snapshot = last + 1;
                    *v = Some(snapshot);
                    if let Err(_) = tx.send(snapshot) {
                        return 1;
                    }
                }
            }
        }

        0
    }
}
