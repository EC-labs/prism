use anyhow::Result;
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use log::{debug, warn};
use std::{mem::MaybeUninit, time::Duration};

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

pub struct IOWait<'obj, 'conn> {
    skel: IowaitSkel<'obj>,
    appender: Appender<'conn>,
    machine_id: u32,
}

impl<'obj, 'conn> IOWait<'obj, 'conn> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        conn: &'conn Connection,
        machine_id: u32,
    ) -> Result<Self> {
        Self::init_store(conn);

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
            appender: conn
                .appender("iowait")
                .expect("Table iowait does not exist"),
        })
    }

    fn init_store(conn: &Connection) {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE iowait (
                    machine_id UINTEGER,
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
        )
        .expect("Iowait store initialisation failed");
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
                &self.machine_id as &dyn ToSql,
                &Duration::from_nanos(ts_s),
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
        unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts as *mut timespec) };
        let (keys, values) = super::replace_samples(&self.skel.maps.samples, &ts);
        self.store(keys.iter().zip(values.iter()))?;
        Ok(())
    }
}
