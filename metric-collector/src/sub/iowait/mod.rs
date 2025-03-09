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

        bump_memlock_rlimit()?;
        let open_skel = skel_builder.open(open_object)?;

        let mut skel = open_skel.load()?;
        for i in 0..SAMPLES {
            let mapfd = unsafe {
                bpf_map_create(
                    libbpf_sys::BPF_MAP_TYPE_HASH,
                    std::ptr::null(),
                    size_of::<granularity>() as u32,
                    size_of::<stats>() as u32,
                    8192,
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
        let records = records.map(|(granularity, stats)| {
            let ts_s = crate::extract::boot_to_epoch(stats.ts_s * 1_000_000_000);
            [
                Box::new(Duration::from_nanos(ts_s)) as Box<dyn ToSql>,
                Box::new(granularity.tgid),
                Box::new(granularity.pid),
                Box::new(granularity.part0),
                Box::new(granularity.bdev),
                Box::new(stats.total_time),
                Box::new(stats.sector_cnt),
                Box::new(stats.total_requests),
                Box::new(stats.hist[0]),
                Box::new(stats.hist[1]),
                Box::new(stats.hist[2]),
                Box::new(stats.hist[3]),
                Box::new(stats.hist[4]),
                Box::new(stats.hist[5]),
                Box::new(stats.hist[6]),
                Box::new(stats.hist[7]),
            ]
        });
        self.appender.append_rows(records)?;

        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
        let curr = ts.tv_sec as u64;
        let mut keys: Vec<granularity> = Vec::new();
        let mut values: Vec<stats> = Vec::new();
        for ts in (curr - (SAMPLES - 1))..curr {
            let outer = ts % SAMPLES;

            let inner_id = self
                .skel
                .maps
                .samples
                .lookup(&(outer as u64).to_ne_bytes(), MapFlags::ANY);

            let inner_id = match inner_id {
                Ok(Some(inner_vec)) => {
                    let mut inner: [u8; 4] = [0; 4];
                    inner.copy_from_slice(&inner_vec);
                    u32::from_ne_bytes(inner)
                }
                _ => {
                    continue;
                }
            };
            let mh = MapHandle::from_map_id(inner_id).unwrap();
            let mut in_batch: u64 = unsafe { MaybeUninit::zeroed().assume_init() };
            let mut out_batch: u64 = unsafe { MaybeUninit::zeroed().assume_init() };
            let mut count: __u32;
            let mut delete = false;

            loop {
                count = BATCH_SIZE as u32;
                assert!(keys.len() == values.len());
                let batch_start = keys.len();
                if keys.capacity() - keys.len() < BATCH_SIZE {
                    keys.reserve(BATCH_SIZE - (keys.capacity() - keys.len()));
                }

                if values.capacity() - values.len() < BATCH_SIZE {
                    values.reserve(BATCH_SIZE - (values.capacity() - values.len()));
                }
                unsafe {
                    libbpf_sys::bpf_map_lookup_batch(
                        mh.as_fd().as_raw_fd(),
                        std::mem::transmute::<&mut u64, *mut c_void>(&mut in_batch),
                        std::mem::transmute::<&mut u64, *mut c_void>(&mut out_batch),
                        std::mem::transmute::<_, *mut c_void>(keys[batch_start..].as_mut_ptr()),
                        std::mem::transmute::<_, *mut c_void>(values[batch_start..].as_mut_ptr()),
                        &mut count as *mut __u32,
                        std::ptr::null(),
                    );
                    keys.set_len(batch_start + count as usize);
                    values.set_len(batch_start + count as usize);
                }
                std::mem::swap(&mut in_batch, &mut out_batch);

                if count == 0 {
                    break;
                }
                delete = true;
            }

            if !delete {
                continue;
            }

            let mapfd = unsafe {
                bpf_map_create(
                    libbpf_sys::BPF_MAP_TYPE_HASH,
                    std::ptr::null(),
                    size_of::<granularity>() as u32,
                    size_of::<stats>() as u32,
                    8192,
                    std::ptr::null(),
                )
            };
            if mapfd < 0 {
                println!("Failed to create map for {outer}: {mapfd}");
                continue;
            }

            let res = self.skel.maps.samples.update(
                &(outer as u64).to_ne_bytes(),
                &mapfd.to_ne_bytes(),
                MapFlags::ANY,
            );
            match res {
                Ok(()) => {}
                Err(e) => {
                    println!("Failed to update map {}: {e}", outer);
                }
            }
            unsafe { libc::close(mapfd) };
        }
        self.store(keys.iter().zip(values.iter()))?;
        Ok(())
    }
}
