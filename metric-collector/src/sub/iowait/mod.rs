use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use log::{debug, warn};
use std::{
    mem::MaybeUninit,
    sync::mpsc::{SendError, Sender},
    time::Duration,
};

mod iowait_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/iowait/bpf/iowait.skel.rs"
    ));
}

use iowait_skel::types::{granularity, stats};
use iowait_skel::*;
use libc::clock_gettime;
use libc::timespec;
use libc::CLOCK_BOOTTIME;

use crate::event::{Event, IoWaitEvent};

pub struct IOWait<'obj> {
    skel: IowaitSkel<'obj>,
    machine_id: u32,
    sink_tx: Sender<Event>,
}

impl<'obj> IOWait<'obj> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        sink_tx: Sender<Event>,
        machine_id: u32,
    ) -> Result<Self> {
        let skel_builder = IowaitSkelBuilder::default();
        let open_skel = skel_builder
            .open(open_object)
            .expect("Iowait skel open failed");

        let mut skel = open_skel.load().expect("Iowait skel load failed");
        super::samples_init::<granularity, stats>(&skel.maps.samples)
            .expect("Iowait samples map initialisation failed");

        if let Err(e) = skel.attach() {
            warn!("Failed to attach Iowait programs:\n{e}");
            return Err(e.into());
        };

        Ok(Self {
            skel,
            machine_id,
            sink_tx,
        })
    }

    fn store<'a, I: ExactSizeIterator<Item = (&'a granularity, &'a stats)>>(
        &mut self,
        records: I,
    ) -> Result<(), SendError<Event>> {
        let nrecords = records.len();
        if nrecords == 0 {
            return Ok(());
        }

        debug!("Store {} records", records.len());
        for (granularity, stats) in records {
            let ts_s = crate::extract::boot_to_epoch(stats.ts_s * 1_000_000_000);
            self.sink_tx.send(Event::IoWait(IoWaitEvent {
                machine_id: self.machine_id,
                ts_s: Duration::from_nanos(ts_s),
                pid: granularity.tgid,
                tid: granularity.pid,
                part0: granularity.part0,
                bdev: granularity.bdev,
                total_time: stats.total_time,
                sector_cnt: stats.sector_cnt,
                total_requests: stats.total_requests,
                hist0: stats.hist[0],
                hist1: stats.hist[1],
                hist2: stats.hist[2],
                hist3: stats.hist[3],
                hist4: stats.hist[4],
                hist5: stats.hist[5],
                hist6: stats.hist[6],
                hist7: stats.hist[7],
            }))?;
        }

        Ok(())
    }

    pub fn sample(&mut self) -> Result<(), SendError<Event>> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts as *mut timespec) };
        let (keys, values) = super::replace_samples(&self.skel.maps.samples, &ts);
        self.store(keys.iter().zip(values.iter()))?;
        Ok(())
    }
}
