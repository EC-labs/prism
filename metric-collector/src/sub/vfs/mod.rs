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
    ffi::c_void,
    fmt::Debug,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    time::Duration,
};
use types::{inflight_key, inflight_value, to_update_key};

use crate::sub::{read_batch, replace_samples, samples_init, BATCH_SIZE, MAX_ENTRIES, SAMPLES};

mod vfs {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/vfs/bpf/vfs.skel.rs"
    ));
}

use vfs::types::{granularity, stats};
use vfs::*;

trait UpdateEnd<T> {
    fn update_end(curr: u64, pending: T) -> u64;
}

impl UpdateEnd<&u64> for &u64 {
    fn update_end(_curr: u64, pending: &u64) -> u64 {
        *pending / 1_000_000_000 * 1_000_000_000
    }
}

impl UpdateEnd<&inflight_value> for &inflight_value {
    fn update_end(curr: u64, _pending: &inflight_value) -> u64 {
        curr
    }
}

impl From<UpdatedKey> for to_update_key {
    fn from(value: UpdatedKey) -> Self {
        let mut key: to_update_key = unsafe { MaybeUninit::zeroed().assume_init() };
        key.ts = value.start;
        key.granularity.bri.fs_magic = value.bri.fs_magic;
        key.granularity.bri.i_ino = value.bri.i_ino;
        key.granularity.bri.i_rdev = value.bri.i_rdev;
        key.granularity.pid = value.tgid_pid as u32;
        key.granularity.tgid = (value.tgid_pid >> 32) as u32;
        key.granularity.op = value.op;
        key
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
    start: u64,
    tgid_pid: u64,
    op: u8,
}

#[derive(Debug)]
struct PendingRecord {
    ts_s: u64,
    pid: u32,
    tid: u32,
    bri: Bri,
    additional_time: u64,
    op: u8,
}

impl From<(&to_update_key, &u64)> for UpdatedKey {
    fn from((key, _): (&to_update_key, &u64)) -> Self {
        Self {
            bri: Bri {
                fs_magic: key.granularity.bri.fs_magic,
                i_ino: key.granularity.bri.i_ino,
                i_rdev: key.granularity.bri.i_rdev,
            },
            start: key.ts,
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
            start: value.ts,
            tgid_pid: key.tgid_pid,
            op: value.op,
        }
    }
}

pub struct Vfs<'obj, 'conn> {
    pub skel: VfsSkel<'obj>,
    appender: Appender<'conn>,
    staging_appender: Appender<'conn>,
    conn: &'conn Connection,
    updated: HashMap<UpdatedKey, u64>,
}

impl<'obj, 'conn> Vfs<'obj, 'conn> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        conn: &'conn Connection,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
    ) -> Result<Self> {
        let skel_builder = VfsSkelBuilder::default();

        let mut open_skel = skel_builder.open(open_object)?;
        open_skel.maps.pids.reuse_fd(pid_map)?;
        open_skel.maps.pid_rb.reuse_fd(pid_rb)?;

        let mut skel = open_skel.load()?;
        samples_init::<granularity, stats>(&skel.maps.samples);

        skel.attach()?;

        Self::init_store(conn)?;
        Ok(Self {
            skel,
            appender: conn.appender("vfs")?,
            staging_appender: conn.appender("vfs_staging")?,
            conn,
            updated: HashMap::new(),
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE vfs (
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    fs_magic UINTEGER,
                    device_id UINTEGER,
                    inode_id UBIGINT,
                    op UTINYINT,
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
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    fs_magic UINTEGER,
                    device_id UINTEGER,
                    inode_id UBIGINT,
                    op UTINYINT,
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
        for (granularity, stats) in records {
            let ts_s = crate::extract::boot_to_epoch(stats.ts_s * 1_000_000_000);
            self.appender.append_row([
                &Duration::from_nanos(ts_s) as &dyn ToSql,
                &granularity.tgid,
                &granularity.pid,
                &granularity.bri.fs_magic,
                &granularity.bri.i_rdev,
                &granularity.bri.i_ino,
                &granularity.op,
                &stats.total_time,
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

    fn store_pending<'a, I: ExactSizeIterator<Item = &'a PendingRecord>>(
        &mut self,
        records: I,
    ) -> Result<()> {
        let nrecords = records.len();
        if nrecords == 0 {
            return Ok(());
        }

        debug!("Stage {} records", records.len());
        for record in records {
            let ts_s = crate::extract::boot_to_epoch(record.ts_s * 1_000_000_000);
            self.staging_appender.append_row([
                &Duration::from_nanos(ts_s) as &dyn ToSql,
                &record.pid,
                &record.tid,
                &record.bri.fs_magic,
                &record.bri.i_rdev,
                &record.bri.i_ino,
                &record.op,
                &record.additional_time,
            ])?;
        }

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
                AND v.fs_magic = vs.fs_magic
                AND v.device_id = vs.device_id
                AND v.inode_id = vs.inode_id
                AND v.op = vs.op;

            INSERT INTO vfs (ts_s, pid, tid, fs_magic, device_id, inode_id, op, total_time)
                SELECT 
                    vs.*
                FROM vfs_staging as vs
                LEFT JOIN vfs as v
                    USING (ts_s, pid, tid, fs_magic, device_id, inode_id, op)
                WHERE 
                    v.ts_s IS NULL;

            DELETE FROM vfs_staging;
            ",
        )?;
        Ok(())
    }

    fn create_pending_records<'a, K, V, I>(
        &mut self,
        pending: I,
        now: &timespec,
        records: &mut Vec<PendingRecord>,
    ) where
        I: Iterator<Item = (K, V)>,
        UpdatedKey: From<(K, V)>,
        V: UpdateEnd<V>,
        K: Copy,
        V: Copy + Debug,
    {
        let curr_sample = (now.tv_sec as u64) * 1_000_000_000;
        for (key, value) in pending {
            let updated_key = UpdatedKey::from((key, value));
            let last_sample = *self.updated.get(&updated_key).unwrap_or(&updated_key.start);
            let start = (last_sample / 1_000_000_000 * 1_000_000_000) + 1_000_000_000;
            let end = V::update_end(curr_sample, value);
            if end < start {
                continue;
            }

            for sample in (start..=end).step_by(1_000_000_000) {
                let additional_time = u64::min(1_000_000_000, sample - last_sample);
                records.push(PendingRecord {
                    ts_s: (sample - 1) / 1_000_000_000,
                    pid: (updated_key.tgid_pid >> 32) as u32,
                    tid: (updated_key.tgid_pid & ((1 << 32) - 1)) as u32,
                    bri: updated_key.bri.clone(),
                    additional_time,
                    op: updated_key.op,
                });
            }

            assert!(end > last_sample);
            self.updated.insert(updated_key, end);
        }
    }

    fn remove_updated_entries<'a, I: Iterator<Item = (&'a to_update_key, &'a u64)>>(
        &mut self,
        entries: I,
    ) -> Result<()> {
        for (key, value) in entries {
            let update_key = UpdatedKey::from((key, value));
            let Some(last_sample) = self.updated.get(&update_key) else {
                continue;
            };

            assert!(last_sample <= value);
            if last_sample < value {
                continue;
            }

            self.updated.remove(&update_key);
            let key = to_update_key::from(update_key);
            let key = unsafe { std::mem::transmute::<_, [u8; size_of::<to_update_key>()]>(key) };
            self.skel.maps.to_update.delete(&key)?
        }
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
        let (keys, values) = replace_samples(&self.skel.maps.samples, &ts);
        self.store_samples(keys.iter().zip(values.iter()))?;
        self.appender.flush();

        let mut pending_records = Vec::new();
        let (mut pending_keys, mut pending_values) = (Vec::new(), Vec::new());
        read_batch::<inflight_key, inflight_value>(
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
        read_batch::<to_update_key, u64>(
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
        self.staging_appender.flush();

        self.upsert_pending()?;
        self.remove_updated_entries(to_update_keys.iter().zip(to_update_values.iter()))?;

        Ok(())
    }
}
