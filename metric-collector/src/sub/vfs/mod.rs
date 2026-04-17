use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME};
use log::{info, warn};
use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    mem::MaybeUninit,
    os::fd::BorrowedFd,
    sync::mpsc::{SendError, Sender},
    time::Duration,
};
use types::{inflight_key, inflight_value, to_update_key, to_update_value};

use crate::{
    event::{Event, VfsEvent},
    sub::{
        samples_init, AggregateSum, BPFKeyDefault, BootSampleSecond, IncrementStart, LastSample,
        TimeSinceBoot, UpdateEnd,
    },
};

mod vfs_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/vfs/bpf/vfs.skel.rs"
    ));
}

use vfs_skel::types::{granularity, stats};
use vfs_skel::*;

impl AggregateSum for stats {
    fn aggregate_sum(&mut self, other: &stats) {
        self.total_time += other.total_time;
    }
}

impl From<(TimeSinceBoot, Duration)> for stats {
    fn from((boot_sample, increment): (TimeSinceBoot, Duration)) -> Self {
        let mut st: Self = unsafe { MaybeUninit::zeroed().assume_init() };
        st.ts_s = boot_sample.as_secs();
        st.total_time = increment.as_nanos() as u64;
        st
    }
}

impl BootSampleSecond for stats {
    fn boot_sample_second(&self) -> TimeSinceBoot {
        TimeSinceBoot::from_secs(self.ts_s)
    }
}

impl LastSample for to_update_value {
    fn last_sample(&self) -> TimeSinceBoot {
        TimeSinceBoot::from_nanos(self.last_sample)
    }
}

impl UpdateEnd for inflight_value {
    fn update_end(&self, curr: TimeSinceBoot) -> TimeSinceBoot {
        curr
    }
}

impl IncrementStart for UpdatedKey {
    fn increment_start(&self) -> TimeSinceBoot {
        self.start
    }
}

impl From<(&to_update_key, &to_update_value)> for granularity {
    fn from((key, _value): (&to_update_key, &to_update_value)) -> Self {
        let mut gran: granularity = unsafe { MaybeUninit::zeroed().assume_init() };
        gran.tgid = key.granularity.tgid;
        gran.pid = key.granularity.pid;
        gran.bri.fs_magic = key.granularity.bri.fs_magic;
        gran.bri.i_rdev = key.granularity.bri.i_rdev;
        gran.bri.i_ino = key.granularity.bri.i_ino;
        gran.op = key.granularity.op;
        gran
    }
}

impl From<(&inflight_key, &inflight_value)> for granularity {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        let mut gran: granularity = unsafe { MaybeUninit::zeroed().assume_init() };
        gran.tgid = (key.tgid_pid >> 32) as u32;
        gran.pid = key.tgid_pid as u32;
        gran.bri.fs_magic = value.bri.fs_magic;
        gran.bri.i_rdev = value.bri.i_rdev;
        gran.bri.i_ino = value.bri.i_ino;
        gran.op = value.op;
        gran
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Bri {
    fs_magic: u32,
    i_ino: u64,
    i_rdev: u32,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct UpdatedKey {
    bri: Bri,
    start: TimeSinceBoot,
    tgid_pid: u64,
    op: u8,
}

impl BPFKeyDefault for granularity {}

impl Hash for granularity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key_hash(state)
    }
}

impl PartialEq for granularity {
    fn eq(&self, other: &Self) -> bool {
        self.key_eq(other)
    }
}

impl Eq for granularity {}

impl From<(&to_update_key, &to_update_value)> for UpdatedKey {
    fn from((key, _): (&to_update_key, &to_update_value)) -> Self {
        Self {
            bri: Bri {
                fs_magic: key.granularity.bri.fs_magic,
                i_ino: key.granularity.bri.i_ino,
                i_rdev: key.granularity.bri.i_rdev,
            },
            start: TimeSinceBoot::from_nanos(key.ts),
            tgid_pid: (key.granularity.tgid as u64) << 32 | key.granularity.pid as u64,
            op: key.granularity.op,
        }
    }
}

impl From<(&inflight_key, &inflight_value)> for UpdatedKey {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        Self {
            bri: Bri {
                fs_magic: value.bri.fs_magic,
                i_ino: value.bri.i_ino,
                i_rdev: value.bri.i_rdev,
            },
            start: TimeSinceBoot::from_nanos(value.ts),
            tgid_pid: key.tgid_pid,
            op: value.op,
        }
    }
}

pub struct Vfs<'obj> {
    pub skel: VfsSkel<'obj>,
    sink_tx: Sender<Event>,
    updated: HashMap<UpdatedKey, TimeSinceBoot>,
    machine_id: u32,
}

impl<'obj> Vfs<'obj> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        sink_tx: Sender<Event>,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
        machine_id: u32,
    ) -> Self {
        let skel_builder = VfsSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .expect("Vfs skel open failed");
        open_skel
            .maps
            .pids
            .reuse_fd(pid_map)
            .expect("Vfs pid_map reuse failed");
        open_skel
            .maps
            .pid_rb
            .reuse_fd(pid_rb)
            .expect("Vfs pid_rb reuse failed");

        let mut skel = open_skel.load().expect("Failed to load Vfs programs");
        samples_init::<granularity, stats>(&skel.maps.samples)
            .expect("Vfs samples map initialisation failed");

        if let Err(e) = skel.attach() {
            warn!("Failed to attach Vfs programs:\n{e:?}");
        } else {
            info!("Successfully registered Vfs");
        }

        Self {
            skel,
            sink_tx,
            machine_id,
            updated: HashMap::new(),
        }
    }

    pub fn sample(&mut self) -> Result<(), SendError<Event>> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts as *mut timespec) };

        let events: Vec<(granularity, stats)> = super::process_samples::<
            granularity,
            stats,
            inflight_key,
            inflight_value,
            to_update_key,
            to_update_value,
            UpdatedKey,
        >(
            &ts,
            &self.skel.maps.samples,
            &self.skel.maps.pending,
            &self.skel.maps.to_update,
            &mut self.updated,
        );

        for (gr, st) in events {
            self.sink_tx.send(Event::Vfs(VfsEvent {
                machine_id: self.machine_id,
                ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(st.ts_s * 1_000_000_000)),
                pid: gr.tgid,
                tid: gr.pid,
                fs_magic: gr.bri.fs_magic,
                device_id: gr.bri.i_rdev,
                inode_id: gr.bri.i_ino,
                op: gr.op,
                total_time: st.total_time,
                total_requests: st.total_requests,
                hist0: st.hist[0],
                hist1: st.hist[1],
                hist2: st.hist[2],
                hist3: st.hist[3],
                hist4: st.hist[4],
                hist5: st.hist[5],
                hist6: st.hist[6],
                hist7: st.hist[7],
            }))?;
        }

        Ok(())
    }
}
