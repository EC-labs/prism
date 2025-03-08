// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::{bail, Result};
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    libbpf_sys::{self, __u32, bpf_map_create},
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, MapFlags, MapHandle, OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC};
use log::debug;
use std::{
    collections::HashMap,
    ffi::{c_void, CStr},
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, RawFd},
};
use types::{inflight_key, inflight_value, to_update_key};

mod vfs {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/vfs/bpf/vfs.skel.rs"
    ));
}

use vfs::types::{granularity, stats};
use vfs::*;
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

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Bri {
    fs_id: [u8; 32],
    i_ino: u64,
    i_rdev: u32,
}

#[derive(PartialEq, Eq, Hash)]
struct UpdatedKey {
    bri: Bri,
    start: u64,
    tgid_pid: u64,
    is_write: u8,
}

#[derive(Debug)]
struct PendingRecord {
    ts_s: u64,
    pid: u32,
    tid: u32,
    bri: Bri,
    additional_time: u64,
    is_write: u8,
}

impl From<(&to_update_key, &u8)> for UpdatedKey {
    fn from((key, _): (&to_update_key, &u8)) -> Self {
        Self {
            bri: Bri {
                fs_id: key.granularity.bri.s_id,
                i_ino: key.granularity.bri.i_ino,
                i_rdev: key.granularity.bri.i_rdev,
            },
            start: key.ts,
            tgid_pid: (key.granularity.tgid as u64) << 32 | key.granularity.pid as u64,
            is_write: key.granularity.dir,
        }
    }
}

impl From<(&inflight_key, &inflight_value)> for UpdatedKey {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        Self {
            bri: Bri {
                fs_id: value.bri.s_id,
                i_ino: value.bri.i_ino,
                i_rdev: value.bri.i_rdev,
            },
            start: value.ts,
            tgid_pid: key.tgid_pid,
            is_write: value.is_write,
        }
    }
}

pub struct Vfs<'obj, 'conn> {
    skel: VfsSkel<'obj>,
    appender: Appender<'conn>,
    staging_appender: Appender<'conn>,
    conn: &'conn Connection,
    updated: HashMap<UpdatedKey, u64>,
}

impl<'obj, 'conn> Vfs<'obj, 'conn> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        conn: &'conn Connection,
        pid_map: MapHandle,
    ) -> Result<Self> {
        let skel_builder = VfsSkelBuilder::default();

        bump_memlock_rlimit()?;
        let mut open_skel = skel_builder.open(open_object)?;
        open_skel.maps.pids.reuse_fd(pid_map.as_fd())?;

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

        Self::init_store(conn)?;
        Ok(Self {
            skel,
            appender: conn.appender("vfs")?,
            staging_appender: conn.appender("vfs_staging")?,
            conn: conn,
            updated: HashMap::new(),
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE vfs (
                    ts_s UBIGINT,
                    pid UINTEGER,
                    tid UINTEGER,
                    fs_id VARCHAR,
                    device_id UINTEGER,
                    inode_id UBIGINT,
                    is_write UTINYINT,
                    total_time UBIGINT,
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

                CREATE OR REPLACE TEMP TABLE vfs_staging (
                    ts_s UBIGINT,
                    pid UINTEGER,
                    tid UINTEGER,
                    fs_id VARCHAR,
                    device_id UINTEGER,
                    inode_id UBIGINT,
                    is_write UTINYINT,
                    additional_time UBIGINT,
                )
            ",
        )?;
        Ok(())
    }

    fn store_samples<'a, I: ExactSizeIterator<Item = (&'a granularity, &'a stats)>>(
        &mut self,
        records: I,
    ) -> Result<()> {
        let nrecords = records.len();
        if nrecords == 0 {
            return Ok(());
        }

        debug!("Store {} records", records.len());
        let records = records.map(|(granularity, stats)| {
            let fs_id = unsafe { CStr::from_ptr(granularity.bri.s_id.as_ptr() as *const i8) };
            let fs_id = fs_id.to_str().unwrap();
            [
                Box::new(&stats.ts_s) as Box<dyn ToSql>,
                Box::new(&granularity.tgid),
                Box::new(&granularity.pid),
                Box::new(fs_id),
                Box::new(&granularity.bri.i_rdev),
                Box::new(&granularity.bri.i_ino),
                Box::new(&granularity.dir),
                Box::new(&stats.total_time),
                Box::new(&stats.total_requests),
                Box::new(&stats.hist[0]),
                Box::new(&stats.hist[1]),
                Box::new(&stats.hist[2]),
                Box::new(&stats.hist[3]),
                Box::new(&stats.hist[4]),
                Box::new(&stats.hist[5]),
                Box::new(&stats.hist[6]),
                Box::new(&stats.hist[7]),
            ]
        });
        self.appender.append_rows(records)?;

        Ok(())
    }

    fn read_samples(&mut self, ts: &timespec) -> (Vec<granularity>, Vec<stats>) {
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
            let count = Self::read_batch(mh.as_fd().as_raw_fd(), &mut keys, &mut values);

            if count == 0 {
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
        (keys, values)
    }

    fn read_batch<'a, K, V>(map_fd: RawFd, keys: &mut Vec<K>, values: &mut Vec<V>) -> usize {
        let mut total = 0;
        let mut in_batch: u64 = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut out_batch: u64 = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut count: __u32;

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
                    map_fd,
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

            total += count;
            if count == 0 {
                break;
            }
        }
        total as usize
    }

    fn create_pending_records<'a, K, V, I>(
        &mut self,
        pending: I,
        now: &timespec,
        records: &mut Vec<PendingRecord>,
    ) where
        I: Iterator<Item = (K, V)>,
        UpdatedKey: From<(K, V)>,
    {
        let curr_sample = (now.tv_sec as u64) * 1_000_000_000;
        for (key, value) in pending {
            let updated_key = UpdatedKey::from((key, value));
            let last_sample = *self.updated.get(&updated_key).unwrap_or(&updated_key.start);
            let start = (last_sample / 1_000_000_000 * 1_000_000_000) + 1_000_000_000;
            if curr_sample < start {
                continue;
            }

            for sample in (start..=curr_sample).step_by(1_000_000_000) {
                let additional_time = u64::min(1_000_000_000, sample - last_sample);
                records.push(PendingRecord {
                    ts_s: sample / 1_000_000_000,
                    pid: (updated_key.tgid_pid & ((1 << 32) - 1)) as u32,
                    tid: (updated_key.tgid_pid >> 32) as u32,
                    bri: updated_key.bri.clone(),
                    additional_time,
                    is_write: updated_key.is_write,
                });
            }

            assert!(curr_sample > last_sample);
            self.updated
                .insert(updated_key, last_sample + (curr_sample - last_sample));
        }
    }

    fn store_pending<'a, I: ExactSizeIterator<Item = &'a PendingRecord>>(
        &mut self,
        records: I,
    ) -> Result<()> {
        let nrecords = records.len();
        if nrecords == 0 {
            return Ok(());
        }

        debug!("Stage {} records", records.len());
        let records = records.map(|record| {
            let fs_id = unsafe { CStr::from_ptr(record.bri.fs_id.as_ptr() as *const i8) };
            let fs_id = fs_id.to_str().unwrap();
            [
                Box::new(&record.ts_s) as Box<dyn ToSql>,
                Box::new(&record.pid),
                Box::new(&record.tid),
                Box::new(fs_id),
                Box::new(&record.bri.i_rdev),
                Box::new(&record.bri.i_ino),
                Box::new(&record.is_write),
                Box::new(&record.additional_time),
            ]
        });
        self.staging_appender.append_rows(records)?;

        Ok(())
    }

    fn upsert_pending(&mut self) -> Result<()> {
        self.conn.execute_batch(
            r"
            UPDATE 
                vfs as v
            SET 
                total_time = total_time + additional_time
            FROM 
                vfs_staging as vs
            WHERE
                v.ts_s = vs.ts_s
                AND v.pid = vs.pid
                AND v.tid = vs.tid
                AND v.fs_id = vs.fs_id
                AND v.device_id = vs.device_id
                AND v.inode_id = vs.inode_id
                AND v.is_write = vs.is_write;

            INSERT INTO vfs (ts_s, pid, tid, fs_id, device_id, inode_id, is_write, total_time)
                SELECT 
                    vs.*
                FROM vfs_staging as vs
                LEFT JOIN vfs as v
                    USING (ts_s, pid, tid, fs_id, device_id, inode_id, is_write)
                WHERE 
                    v.ts_s IS NULL;

            DELETE FROM vfs_staging
            WHERE true;
            ",
        )?;
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
        let (keys, values) = self.read_samples(&ts);
        self.store_samples(keys.iter().zip(values.iter()))?;
        self.appender.flush();

        let mut pending_records = Vec::new();
        let (mut pending_keys, mut pending_values) = (Vec::new(), Vec::new());
        Self::read_batch::<inflight_key, inflight_value>(
            self.skel.maps.pending.as_fd().as_raw_fd(),
            &mut pending_keys,
            &mut pending_values,
        );
        self.create_pending_records(
            pending_keys.iter().zip(pending_values.iter()),
            &ts,
            &mut pending_records,
        );
        debug!("after pending: {}", pending_records.len());

        let (mut to_update_keys, mut to_update_values) = (Vec::new(), Vec::new());
        Self::read_batch::<to_update_key, u8>(
            self.skel.maps.to_update.as_fd().as_raw_fd(),
            &mut to_update_keys,
            &mut to_update_values,
        );
        self.create_pending_records(
            to_update_keys.iter().zip(to_update_values.iter()),
            &ts,
            &mut pending_records,
        );
        debug!("after to_update: {}", pending_records.len());
        self.store_pending(pending_records.iter())?;
        for record in pending_records {
            println!("{:?}", record);
        }
        self.staging_appender.flush();

        self.upsert_pending()?;
        // self.remove_updated_entries();

        Ok(())
    }
}
