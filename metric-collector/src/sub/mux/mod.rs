use super::UpdateEnd;
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME};
use log::warn;
use std::{
    cmp::{Eq, PartialEq},
    collections::HashMap,
    ffi::c_void,
    fmt::Debug,
    hash::Hash,
    mem::MaybeUninit,
    os::fd::BorrowedFd,
    ptr,
    sync::mpsc::{SendError, Sender},
    time::Duration,
};

use crate::{
    event::{Event, MuxioFileEvent, MuxioWaitEvent},
    sub::{
        AggregateSum, BPFKeyDefault, BootSampleSecond, IncrementStart, LastSample, TimeSinceBoot,
    },
};

mod mux_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/mux/bpf/mux.skel.rs"
    ));
}
use mux_skel::types::{
    file_granularity, file_stats, granularity, inflight_key, inflight_value, stats, to_update_key,
    to_update_value,
};
use mux_skel::*;

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

impl<'a> From<(&'a inflight_key, &'a inflight_value)> for granularity {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        let mut gran: granularity = unsafe { MaybeUninit::zeroed().assume_init() };
        gran.tgid = (key.tgid_pid >> 32) as u32;
        gran.pid = key.tgid_pid as u32;
        gran.ep = value.ep;
        gran
    }
}

impl<'a> From<(&'a to_update_key, &'a to_update_value)> for granularity {
    fn from((key, _value): (&to_update_key, &to_update_value)) -> Self {
        let mut gran: granularity = unsafe { MaybeUninit::zeroed().assume_init() };
        gran.tgid = key.granularity.tgid;
        gran.pid = key.granularity.pid;
        gran.ep = key.granularity.ep;
        gran
    }
}

impl AggregateSum for stats {
    fn aggregate_sum(&mut self, other: &Self) {
        self.total_time += other.total_time;
    }
}

impl BootSampleSecond for stats {
    fn boot_sample_second(&self) -> TimeSinceBoot {
        TimeSinceBoot::from_secs(self.ts_s)
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

impl IncrementStart for UpdatedKey {
    fn increment_start(&self) -> TimeSinceBoot {
        self.start
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Bri {
    is_epoll: bool,
    poll_id: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct UpdatedKey {
    bri: Bri,
    start: TimeSinceBoot,
    tgid_pid: u64,
}

impl From<UpdatedKey> for to_update_key {
    fn from(value: UpdatedKey) -> Self {
        let mut key: to_update_key = unsafe { MaybeUninit::zeroed().assume_init() };
        key.ts = value.start.as_nanos();
        key.granularity.pid = value.tgid_pid as u32;
        key.granularity.tgid = (value.tgid_pid >> 32) as u32;
        key.granularity.ep = if value.bri.is_epoll {
            value.bri.poll_id as *mut c_void
        } else {
            ptr::null::<c_void>() as *mut c_void
        };
        key
    }
}

impl From<(&inflight_key, &inflight_value)> for UpdatedKey {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        Self {
            start: TimeSinceBoot::from_nanos(value.ts),
            tgid_pid: key.tgid_pid,
            bri: Bri {
                is_epoll: if value.ep.is_null() { false } else { true },
                poll_id: if value.ep.is_null() {
                    key.tgid_pid
                } else {
                    value.ep as u64
                },
            },
        }
    }
}

impl From<(&to_update_key, &to_update_value)> for UpdatedKey {
    fn from((key, _value): (&to_update_key, &to_update_value)) -> Self {
        Self {
            start: TimeSinceBoot::from_nanos(key.ts),
            tgid_pid: ((key.granularity.tgid as u64) << 32) | (key.granularity.pid as u64),
            bri: Bri {
                is_epoll: if key.granularity.ep.is_null() {
                    false
                } else {
                    true
                },
                poll_id: if key.granularity.ep.is_null() {
                    ((key.granularity.tgid as u64) << 32) | (key.granularity.pid as u64)
                } else {
                    key.granularity.ep as u64
                },
            },
        }
    }
}

impl UpdateEnd for inflight_value {
    fn update_end(&self, curr: TimeSinceBoot) -> TimeSinceBoot {
        curr
    }
}

impl LastSample for to_update_value {
    fn last_sample(&self) -> TimeSinceBoot {
        TimeSinceBoot::from_nanos(self.last_sample)
    }
}

pub struct Muxio<'obj> {
    skel: MuxSkel<'obj>,
    sink_tx: Sender<Event>,
    updated: HashMap<UpdatedKey, TimeSinceBoot>,
    machine_id: u32,
}

impl<'obj> Muxio<'obj> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
        sink_tx: Sender<Event>,
        machine_id: u32,
    ) -> Result<Self> {
        let skel_builder = MuxSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .expect("Muxio skel open failed");
        open_skel
            .maps
            .pids
            .reuse_fd(pid_map)
            .expect("Muxio pid_map reuse failed");
        open_skel
            .maps
            .pid_rb
            .reuse_fd(pid_rb)
            .expect("Muxio pid_rb reuse failed");

        let mut skel = open_skel.load().expect("Muxio skel load failed");
        super::samples_init::<granularity, stats>(&skel.maps.samples)
            .expect("Muxio samples map initialisation failed");
        super::samples_init::<file_granularity, file_stats>(&skel.maps.file_samples)
            .expect("Muxio file_samples map initialisation failed");
        if let Err(e) = skel.attach() {
            warn!("Failed to attach Muxio programs:\n{e}");
            return Err(e.into());
        }

        Ok(Self {
            skel,
            sink_tx,
            machine_id,
            updated: HashMap::new(),
        })
    }

    fn store_file_samples<
        'a,
        I: ExactSizeIterator<Item = (&'a file_granularity, &'a file_stats)>,
    >(
        &mut self,
        records: I,
    ) -> Result<(), SendError<Event>> {
        for (gr, st) in records {
            self.sink_tx.send(Event::MuxioFile(MuxioFileEvent {
                machine_id: self.machine_id,
                ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(st.ts_s * 1_000_000_000)),
                poll_id: gr.id,
                fs_magic: gr.bri.fs_magic,
                device_id: gr.bri.i_rdev,
                inode_id: gr.bri.i_ino,
                mode: gr.mode,
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
            self.sink_tx.send(Event::MuxioWait(MuxioWaitEvent {
                machine_id: self.machine_id,
                ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(st.ts_s * 1_000_000_000)),
                pid: gr.tgid,
                tid: gr.pid,
                is_epoll: !gr.ep.is_null(),
                poll_id: if gr.ep.is_null() {
                    (gr.tgid as u64) << 32 | (gr.pid as u64)
                } else {
                    gr.ep as u64
                },
                total_time: st.total_time,
                total_requests: st.total_requests,
            }))?;
        }

        // thread mux samples
        let (keys, values) = super::replace_samples(&self.skel.maps.file_samples, &ts);
        self.store_file_samples(keys.iter().zip(values.iter()))?;

        Ok(())
    }
}
