use anyhow::{bail, Result};
use dashmap::{DashMap, Map};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC};
use log::{debug, error};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
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

use muxio::*;
const BATCH_SIZE: usize = 8192;
const SAMPLES: u64 = 10;

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

pub struct Muxio {
    rx: Receiver<i64>,
    poll_state: PollState,
    sharded_events: Arc<DashMap<i64, BTreeMap<u64, Vec<MuxioEvent>>>>,
}

impl Muxio {
    pub fn new(pid_map: BorrowedFd) -> Result<Self> {
        bump_memlock_rlimit()?;

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
                        tx.send(snapshot)?;
                    }
                    Some(last) => {
                        if last < ts.tv_sec - 2 {
                            let snapshot = last + 1;
                            *v = Some(snapshot);
                            tx.send(snapshot)?;
                        }
                    }
                }
            }

            Ok(()) as Result<()>
        });

        Ok(Self {
            rx,
            sharded_events,
            poll_state: PollState::new(),
        })
    }

    pub fn sample(&mut self) -> Result<()> {
        while let Ok(snapshot) = self.rx.try_recv() {
            let mut btree = self
                .sharded_events
                .remove(&snapshot)
                .map(|(_, btree)| btree)
                .unwrap_or_default();

            while let Some((_, events)) = btree.pop_first() {
                for event in events {
                    self.poll_state.process(event);
                }
            }

            let stats = self.poll_state.snapshot(snapshot as u64);
            for (key, stat) in stats {
                println!("{:?}: {:?}", key, stat);
            }

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
    PollStart { ts: u64, tgid_pid: u64 },
    PollEnd { ts: u64, tgid_pid: u64 },
    PollFileRegister { ts: u64, tgid_pid: u64, bri: Bri },
}

impl MuxioEvent {
    fn get_timestamp(&self) -> u64 {
        use MuxioEvent::*;
        match self {
            PollStart { ts, .. } | PollEnd { ts, .. } | PollFileRegister { ts, .. } => *ts,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct poll_start_event {
    event: u8,
    tgid_pid: u64,
    ts: u64,
}

impl From<&poll_start_event> for MuxioEvent {
    fn from(value: &poll_start_event) -> Self {
        Self::PollStart {
            ts: value.ts,
            tgid_pid: value.tgid_pid,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct poll_end_event {
    event: u8,
    tgid_pid: u64,
    ts: u64,
}

impl From<&poll_end_event> for MuxioEvent {
    fn from(value: &poll_end_event) -> Self {
        Self::PollEnd {
            ts: value.ts,
            tgid_pid: value.tgid_pid,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct poll_register_file_event {
    event: u8,
    magic: u32,
    i_rdev: u32,
    tgid_pid: u64,
    i_ino: u64,
    ts: u64,
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

#[derive(Debug, PartialEq, Eq, Hash)]
enum StatsKey {
    Poll(u64),
    Bri(Bri),
}

impl StatsKey {
    fn from_poll_u64(poll: u64) -> Self {
        Self::Poll(poll)
    }

    fn from_bri(bri: Bri) -> Self {
        Self::Bri(bri)
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

struct PollState {
    /// key:
    ///     * poll, select - the key will be the tgid_pid
    ///     * epoll - the key is the kernel's internal epoll resource address
    pending: HashMap<u64, u64>,
    /// holds the files registered with each poll resource
    poll_files: HashMap<u64, HashSet<Bri>>,
    stats: HashMap<StatsKey, Stats>,
}

impl PollState {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            poll_files: HashMap::new(),
            stats: HashMap::new(),
        }
    }

    fn process(&mut self, event: MuxioEvent) {
        use MuxioEvent::*;
        match event {
            PollStart { ts, tgid_pid } => {
                self.pending.insert(tgid_pid, ts);
            }
            PollFileRegister { tgid_pid, bri, .. } => {
                self.poll_files
                    .entry(tgid_pid)
                    .or_insert_with(|| HashSet::new())
                    .insert(bri);
            }
            PollEnd { ts, tgid_pid } => {
                let Some(ts_start) = self.pending.remove(&tgid_pid) else {
                    return;
                };
                let key = StatsKey::from_poll_u64(tgid_pid);
                let poll_stats = self.stats.entry(key).or_insert_with(|| Stats::PollStats {
                    total_time: 0,
                    count: 0,
                });
                let shard_start = ts / 1_000_000_000 * 1_000_000_000;
                let diff = u64::min(ts - ts_start, ts - shard_start);
                poll_stats.acct(diff, true);

                let Some(bris) = self.poll_files.remove(&tgid_pid) else {
                    return;
                };
                for bri in bris {
                    let key = StatsKey::from_bri(bri);
                    let bri_stats = self.stats.entry(key).or_insert_with(|| Stats::BriStats {
                        total_time: 0,
                        count: 0,
                    });
                    bri_stats.acct(diff, false);
                }
            }
            _ => {
                error!("PollState can't process event {:?}", event);
            }
        }
    }

    fn snapshot(&mut self, snapshot_s: u64) -> HashMap<StatsKey, Stats> {
        for (poll, ts_start) in self.pending.iter() {
            let key = StatsKey::from_poll_u64(*poll);
            let poll_stats = self.stats.entry(key).or_insert_with(|| Stats::PollStats {
                total_time: 0,
                count: 0,
            });
            let diff = u64::min((snapshot_s + 1) * 1_000_000_000 - ts_start, 1_000_000_000);
            poll_stats.acct(diff, false);

            let Some(bris) = self.poll_files.get(poll) else {
                continue;
            };
            for bri in bris {
                let key = StatsKey::from_bri(bri.clone());
                let stats = self.stats.entry(key).or_insert_with(|| Stats::BriStats {
                    total_time: 0,
                    count: 0,
                });
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
            0 => {
                let data: &[u8; size_of::<poll_start_event>()] =
                    &data[..size_of::<poll_start_event>()].try_into().unwrap();
                let data: &poll_start_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            1 => {
                let data: &[u8; size_of::<poll_end_event>()] =
                    &data[..size_of::<poll_end_event>()].try_into().unwrap();
                let data: &poll_end_event = unsafe { std::mem::transmute::<_, _>(data) };
                MuxioEvent::from(data)
            }
            2 => {
                let data: &[u8; size_of::<poll_register_file_event>()] = &data
                    [..size_of::<poll_register_file_event>()]
                    .try_into()
                    .unwrap();
                let data: &poll_register_file_event = unsafe { std::mem::transmute::<_, _>(data) };
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
                tx.send(snapshot);
            }
            Some(last) => {
                if last < shard - 2 {
                    let snapshot = last + 1;
                    *v = Some(snapshot);
                    tx.send(snapshot);
                }
            }
        }

        0
    }
}
