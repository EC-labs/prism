// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::{bail, Result};
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    libbpf_sys::{self, __u32, bpf_map_create},
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use log::debug;
use std::{
    ffi::c_void,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};

mod iowait {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/iowait/bpf/iowait.skel.rs"
    ));
}

use iowait::types::{granularity, stats};
use iowait::*;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libc::clock_gettime;
use libc::timespec;
use libc::CLOCK_MONOTONIC;

use crate::sub::{replace_samples, BATCH_SIZE, MAX_ENTRIES, SAMPLES};

pub struct IOWait<'obj, 'conn> {
    skel: IowaitSkel<'obj>,
    appender: Appender<'conn>,
}

impl<'obj, 'conn> IOWait<'obj, 'conn> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        conn: &'conn Connection,
    ) -> Result<Self> {
        Self::init_store(conn)?;

        let skel_builder = IowaitSkelBuilder::default();
        let open_skel = skel_builder.open(open_object)?;

        let mut skel = open_skel.load()?;
        for i in 0..SAMPLES {
            let mapfd = unsafe {
                bpf_map_create(
                    libbpf_sys::BPF_MAP_TYPE_HASH,
                    std::ptr::null(),
                    size_of::<granularity>() as u32,
                    size_of::<stats>() as u32,
                    MAX_ENTRIES as u32,
                    std::ptr::null(),
                )
            };
            if mapfd < 0 {
                bail!("Failed to create map for {i}: {mapfd}")
            }

            skel.maps.samples.update(
                &(i as u64).to_ne_bytes(),
                &mapfd.to_ne_bytes(),
                MapFlags::ANY,
            )?;
            unsafe { libc::close(mapfd) };
        }

        skel.attach()?;
        Ok(Self {
            skel,
            appender: conn.appender("iowait")?,
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE iowait (
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    part0 UBIGINT,
                    bdev UBIGINT,
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
            ",
        )?;
        Ok(())
    }

    fn store<'a, I: ExactSizeIterator<Item = (&'a granularity, &'a stats)>>(
        &mut self,
        records: I,
    ) -> Result<()> {
        let nrecords = records.len();
        if nrecords == 0 {
            return Ok(());
        }

        debug!("Store {} records", records.len());
        for (granularity, stats) in records {
            let ts_s = crate::extract::boot_to_epoch(stats.ts_s * 1_000_000_000);
            self.appender.append_row([
                &Duration::from_nanos(ts_s) as &dyn ToSql,
                &granularity.tgid,
                &granularity.pid,
                &granularity.part0,
                &granularity.bdev,
                &stats.total_time,
                &stats.sector_cnt,
                &stats.total_requests,
                &stats.hist[0],
                &stats.hist[1],
                &stats.hist[2],
                &stats.hist[3],
                &stats.hist[4],
                &stats.hist[5],
                &stats.hist[6],
                &stats.hist[7],
            ])?;
        }

        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
        let (keys, values) = replace_samples(&self.skel.maps.samples, &ts);
        self.store(keys.iter().zip(values.iter()))?;
        Ok(())
    }
}
