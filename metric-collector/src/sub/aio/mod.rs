use super::UpdateEnd;
use crate::{
    event::{AioFileEvent, AioGeteventsEvent, AioSubmitEvent, Event},
    sub::{
        AggregateSum, BPFKeyDefault, BootSampleSecond, IncrementStart, LastSample, TimeSinceBoot,
    },
};
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME};
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

mod aio_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/aio/bpf/aio.skel.rs"
    ));
}

use aio_skel::types::{
    file_granularity, file_stats, granularity, inflight_key, inflight_value, stats, to_update_key,
    to_update_value,
};
use aio_skel::*;

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
        gran.aioctx = value.aioctx;
        gran.op = value.op;
        gran
    }
}

impl<'a> From<(&'a to_update_key, &'a to_update_value)> for granularity {
    fn from((key, _value): (&to_update_key, &to_update_value)) -> Self {
        let mut gran: granularity = unsafe { MaybeUninit::zeroed().assume_init() };
        gran.tgid = key.granularity.tgid;
        gran.pid = key.granularity.pid;
        gran.aioctx = key.granularity.aioctx;
        gran.op = key.granularity.op;
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
    aioctx: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct UpdatedKey {
    bri: Bri,
    start: TimeSinceBoot,
    tgid_pid: u64,
}

impl From<(&inflight_key, &inflight_value)> for UpdatedKey {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        Self {
            start: TimeSinceBoot::from_nanos(value.ts),
            tgid_pid: key.tgid_pid,
            bri: Bri {
                aioctx: value.aioctx as u64,
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
                aioctx: key.granularity.aioctx as u64,
            },
        }
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

pub struct Aio<'obj> {
    skel: AioSkel<'obj>,
    machine_id: u32,
    sink_tx: Sender<Event>,
    updated: HashMap<UpdatedKey, TimeSinceBoot>,
}

impl<'obj> Aio<'obj> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        sink_tx: Sender<Event>,
        machine_id: u32,
    ) -> Result<Self> {
        let skel_builder = AioSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .expect("Aio skel open failed");
        open_skel
            .maps
            .pids
            .reuse_fd(pid_map)
            .expect("Aio pid_map reuse failed");

        let mut skel = open_skel.load().expect("Aio skel load failed");
        super::samples_init::<granularity, stats>(&skel.maps.samples)
            .expect("Aio samples map initialisation failed");
        super::samples_init::<file_granularity, file_stats>(&skel.maps.file_samples)
            .expect("Aio file_samples map initialisation failed");
        if let Err(e) = skel.attach() {
            warn!("Failed to attach Aio programs:\n{e}");
            return Err(e.into());
        }

        Ok(Aio {
            machine_id,
            skel,
            sink_tx,
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
            match gr.isreg as u32 {
                0 => unsafe {
                    self.sink_tx.send(Event::AioFile(AioFileEvent {
                        machine_id: self.machine_id,
                        ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(
                            st.ts_s * 1_000_000_000,
                        )),
                        aioctx: gr.aioctx,
                        isreg: gr.isreg,
                        fs_magic: Some(gr.bri.vfs.fs_magic),
                        device_id: Some(gr.bri.vfs.i_rdev),
                        inode_id: Some(gr.bri.vfs.i_ino),
                        part0: None::<u64>,
                        bdev: None::<u64>,
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
                },
                1 => unsafe {
                    self.sink_tx.send(Event::AioFile(AioFileEvent {
                        machine_id: self.machine_id,
                        ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(
                            st.ts_s * 1_000_000_000,
                        )),
                        aioctx: gr.aioctx,
                        isreg: gr.isreg,
                        fs_magic: None::<u32>,
                        device_id: None::<u32>,
                        inode_id: None::<u64>,
                        part0: Some(gr.bri.bdev.part0),
                        bdev: Some(gr.bri.bdev.dev),
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
                },
                op => {
                    error!("unknown aio_file op code: `{}`", op);
                    panic!();
                }
            }
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
            match gr.op as u32 {
                super::consts::AIO_GETEVENTS => {
                    self.sink_tx.send(Event::AioGetevents(AioGeteventsEvent {
                        machine_id: self.machine_id,
                        ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(
                            st.ts_s * 1_000_000_000,
                        )),
                        pid: gr.tgid,
                        tid: gr.pid,
                        aioctx: gr.aioctx as u64,
                        total_time: st.total_time,
                        total_requests: st.total_requests,
                    }))?;
                }
                super::consts::AIO_SUBMIT => {
                    self.sink_tx.send(Event::AioSubmit(AioSubmitEvent {
                        machine_id: self.machine_id,
                        ts_s: Duration::from_nanos(crate::extract::boot_to_epoch(
                            st.ts_s * 1_000_000_000,
                        )),
                        pid: gr.tgid,
                        tid: gr.pid,
                        aioctx: gr.aioctx as u64,
                        total_requests: st.total_requests,
                    }))?;
                }
                aio_type => {
                    error!("Unexpected aio_type `{aio_type}`");
                    panic!();
                }
            }
        }

        let (keys, values) = super::replace_samples(&self.skel.maps.file_samples, &ts);
        self.store_file_samples(keys.iter().zip(values.iter()))?;

        Ok(())
    }
}
