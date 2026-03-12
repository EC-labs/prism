use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME, FUTEX_WAIT, FUTEX_WAKE};
use log::{error, warn};
use std::{
    cmp::{Eq, PartialEq},
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    mem::MaybeUninit,
    os::fd::BorrowedFd,
    sync::mpsc::{SendError, Sender},
    time::Duration,
};
use types::{granularity, inflight_key, inflight_value, stats, to_update_key, to_update_value};

use crate::sub::{
    samples_init, AggregateSum, BPFKeyDefault, IncrementStart, LastSample, TimeSinceBoot, UpdateEnd,
};
use crate::{
    event::{Event, FutexWaitEvent, FutexWakeEvent},
    sub::BootSampleSecond,
};

mod futex_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/futex/bpf/futex.skel.rs"
    ));
}

use futex_skel::*;

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

impl UpdateEnd for inflight_value {
    fn update_end(&self, curr: TimeSinceBoot) -> TimeSinceBoot {
        curr
    }
}

impl AggregateSum for stats {
    fn aggregate_sum(&mut self, other: &Self) {
        // Aggregation will only happen on wait futexes since these are the only
        // ones that go into the pending / to_update map
        unsafe { self.wait.total_time += other.wait.total_time };
    }
}

impl BootSampleSecond for stats {
    fn boot_sample_second(&self) -> TimeSinceBoot {
        TimeSinceBoot::from_secs(unsafe { self.both.ts_s })
    }
}

impl From<(TimeSinceBoot, Duration)> for stats {
    fn from((boot_sample, increment): (TimeSinceBoot, Duration)) -> Self {
        let mut st: Self = unsafe { MaybeUninit::zeroed().assume_init() };
        st.wait.ts_s = boot_sample.as_secs();
        st.wait.total_time = increment.as_nanos() as u64;
        st
    }
}

impl IncrementStart for UpdatedKey {
    fn increment_start(&self) -> TimeSinceBoot {
        self.start
    }
}

impl LastSample for to_update_value {
    fn last_sample(&self) -> TimeSinceBoot {
        TimeSinceBoot::from_nanos(self.last_sample)
    }
}

impl<'a> From<(&'a inflight_key, &'a inflight_value)> for granularity {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        let mut gran: granularity = unsafe { MaybeUninit::zeroed().assume_init() };
        gran.tgid = (key.tgid_pid >> 32) as u32;
        gran.pid = key.tgid_pid as u32;
        gran.fkey.both.ptr = unsafe { value.fkey.both.ptr };
        gran.fkey.both.word = unsafe { value.fkey.both.word };
        gran.fkey.both.offset = unsafe { value.fkey.both.offset };
        gran.op = value.op;
        gran
    }
}

impl<'a> From<(&'a to_update_key, &'a to_update_value)> for granularity {
    fn from((key, _value): (&to_update_key, &to_update_value)) -> Self {
        let mut gran: granularity = unsafe { MaybeUninit::zeroed().assume_init() };
        gran.tgid = key.granularity.tgid;
        gran.pid = key.granularity.pid;
        gran.fkey.both.ptr = unsafe { key.granularity.fkey.both.ptr };
        gran.fkey.both.word = unsafe { key.granularity.fkey.both.word };
        gran.fkey.both.offset = unsafe { key.granularity.fkey.both.offset };
        gran.op = key.granularity.op;
        gran
    }
}

impl From<UpdatedKey> for to_update_key {
    fn from(value: UpdatedKey) -> Self {
        let mut key: to_update_key = unsafe { MaybeUninit::zeroed().assume_init() };
        key.ts = value.start.as_nanos();
        key.granularity.pid = value.tgid_pid as u32;
        key.granularity.tgid = (value.tgid_pid >> 32) as u32;
        key.granularity.fkey.both.ptr = value.futex_key.ptr;
        key.granularity.fkey.both.word = value.futex_key.word;
        key.granularity.fkey.both.offset = value.futex_key.offset;
        key
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct FutexKey {
    ptr: u64,
    word: u64,
    offset: u32,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct UpdatedKey {
    futex_key: FutexKey,
    start: TimeSinceBoot,
    tgid_pid: u64,
}

impl From<(&inflight_key, &inflight_value)> for UpdatedKey {
    fn from((map_key, map_value): (&inflight_key, &inflight_value)) -> Self {
        let fkey = unsafe { map_value.fkey.both };
        UpdatedKey {
            futex_key: FutexKey {
                ptr: fkey.ptr,
                word: fkey.word,
                offset: fkey.offset,
            },
            start: TimeSinceBoot::from_nanos(map_value.ts),
            tgid_pid: map_key.tgid_pid,
        }
    }
}

impl From<(&to_update_key, &to_update_value)> for UpdatedKey {
    fn from((map_key, _): (&to_update_key, &to_update_value)) -> Self {
        let fkey = unsafe { map_key.granularity.fkey.both };
        UpdatedKey {
            futex_key: FutexKey {
                ptr: fkey.ptr,
                word: fkey.word,
                offset: fkey.offset,
            },
            start: TimeSinceBoot::from_nanos(map_key.ts),
            tgid_pid: (map_key.granularity.tgid as u64) << 32 | map_key.granularity.pid as u64,
        }
    }
}

pub struct Futex<'obj> {
    skel: FutexSkel<'obj>,
    updated: HashMap<UpdatedKey, TimeSinceBoot>,
    sink_tx: Sender<Event>,
    machine_id: u32,
}

impl<'obj> Futex<'obj> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
        sink_tx: Sender<Event>,
        machine_id: u32,
    ) -> Result<Self> {
        let skel_builder = FutexSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .expect("Futex skel open failed");
        open_skel
            .maps
            .pids
            .reuse_fd(pid_map)
            .expect("Futex pid_map reuse failed");
        open_skel
            .maps
            .pid_rb
            .reuse_fd(pid_rb)
            .expect("Futex pid_rb reuse failed");

        let mut skel = open_skel.load().expect("Futex skel load failed");
        samples_init::<granularity, stats>(&skel.maps.samples)
            .expect("Futex samples map initialisation failed");

        if let Err(e) = skel.attach() {
            warn!("Failed to attach Futex programs:\n{e}");
            return Err(e.into());
        }

        Ok(Self {
            skel,
            updated: HashMap::new(),
            sink_tx,
            machine_id,
        })
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
            match gr.op as i32 {
                FUTEX_WAIT => unsafe {
                    self.sink_tx.send(Event::FutexWait(FutexWaitEvent {
                        machine_id: self.machine_id,
                        ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(
                            st.both.ts_s * 1_000_000_000,
                        )),
                        pid: gr.tgid,
                        tid: gr.pid,
                        futex_key_addr: gr.fkey.both.ptr,
                        futex_key_word: gr.fkey.both.word,
                        futex_key_offset: gr.fkey.both.offset,
                        total_requests: st.wait.total_requests,
                        total_time: st.wait.total_time,
                        hist0: st.wait.hist[0],
                        hist1: st.wait.hist[1],
                        hist2: st.wait.hist[2],
                        hist3: st.wait.hist[3],
                        hist4: st.wait.hist[4],
                        hist5: st.wait.hist[5],
                        hist6: st.wait.hist[6],
                        hist7: st.wait.hist[7],
                    }))?;
                },
                FUTEX_WAKE => unsafe {
                    self.sink_tx.send(Event::FutexWake(FutexWakeEvent {
                        machine_id: self.machine_id,
                        ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(
                            st.both.ts_s * 1_000_000_000,
                        )),
                        pid: gr.tgid,
                        tid: gr.pid,
                        futex_key_addr: gr.fkey.both.ptr,
                        futex_key_word: gr.fkey.both.word,
                        futex_key_offset: gr.fkey.both.offset,
                        total_requests: st.both.total_requests,
                        successful_count: st.both.total_requests,
                    }))?;
                },
                futex_type => {
                    error!("Unexpected futex type `{futex_type}`");
                    panic!();
                }
            }
        }

        Ok(())
    }
}
