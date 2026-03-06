use super::UpdateEnd;
use anyhow::Result;
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME};
use log::{debug, warn};
use std::{
    collections::HashMap,
    ffi::c_void,
    fmt::Debug,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    ptr,
    time::Duration,
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

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Bri {
    is_epoll: bool,
    poll_id: u64,
}

#[derive(Debug)]
struct PendingRecord {
    ts_s: u64,
    pid: u32,
    tid: u32,
    bri: Bri,
    additional_time: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct UpdatedKey {
    bri: Bri,
    start: u64,
    tgid_pid: u64,
}

impl From<UpdatedKey> for to_update_key {
    fn from(value: UpdatedKey) -> Self {
        let mut key: to_update_key = unsafe { MaybeUninit::zeroed().assume_init() };
        key.ts = value.start;
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
            start: value.ts,
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
            start: key.ts,
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

impl UpdateEnd<&inflight_value> for &inflight_value {
    fn update_end(curr: u64, _pending: &inflight_value) -> u64 {
        curr
    }
}

impl UpdateEnd<&to_update_value> for &to_update_value {
    fn update_end(_curr: u64, pending: &to_update_value) -> u64 {
        pending.additional_time
    }
}

pub struct Muxio<'obj, 'conn> {
    skel: MuxSkel<'obj>,
    conn: &'conn Connection,
    muxio_appender: Appender<'conn>,
    muxio_staging_appender: Appender<'conn>,
    muxio_file_appender: Appender<'conn>,
    updated: HashMap<UpdatedKey, u64>,
    machine_id: u32,
}

impl<'obj, 'conn> Muxio<'obj, 'conn> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
        conn: &'conn Connection,
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

        Self::init_store(conn);
        let muxio_appender = conn
            .appender("muxio_wait")
            .expect("Table muxio_wait does not exist");
        let muxio_staging_appender = conn
            .appender("muxio_staging")
            .expect("Table muxio_staging does not exist");
        let muxio_file_appender = conn
            .appender("muxio_file")
            .expect("Table muxio_file does not exist");
        Ok(Self {
            skel,
            conn,
            muxio_appender,
            muxio_staging_appender,
            muxio_file_appender,
            machine_id,
            updated: HashMap::new(),
        })
    }

    fn init_store(conn: &Connection) {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE muxio_wait (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    is_epoll BOOLEAN,
                    poll_id UBIGINT,
                    total_time UBIGINT,
                    total_requests UBIGINT,
                );

                CREATE OR REPLACE TEMP TABLE muxio_staging (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    is_epoll BOOLEAN,
                    poll_id UBIGINT,
                    additional_time UBIGINT,
                );

                CREATE OR REPLACE TABLE muxio_file (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    poll_id UBIGINT,
                    fs_magic UINTEGER,
                    device_id UINTEGER,
                    inode_id UBIGINT,
                    mode UTINYINT,
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
        .expect("Muxio store initialisation failed");
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
            self.muxio_appender.append_row([
                &self.machine_id as &dyn ToSql,
                &Duration::from_nanos(ts_s),
                &granularity.tgid,
                &granularity.pid,
                &(if granularity.ep.is_null() {
                    false
                } else {
                    true
                }),
                &(if granularity.ep.is_null() {
                    (granularity.tgid as u64) << 32 | (granularity.pid as u64)
                } else {
                    granularity.ep as u64
                }),
                &stats.total_time,
                &stats.total_requests,
            ])?;
        }

        Ok(())
    }

    fn create_pending_records<K, V, I>(
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
                });
            }

            assert!(end > last_sample);
            self.updated.insert(updated_key, end);
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
        for record in records {
            let ts_s = crate::extract::boot_to_epoch(record.ts_s * 1_000_000_000);
            self.muxio_staging_appender.append_row([
                &self.machine_id as &dyn ToSql,
                &Duration::from_nanos(ts_s),
                &record.pid,
                &record.tid,
                &record.bri.is_epoll,
                &record.bri.poll_id,
                &record.additional_time,
            ])?;
        }

        Ok(())
    }

    fn remove_updated_entries<'a, I: Iterator<Item = (&'a to_update_key, &'a to_update_value)>>(
        &mut self,
        entries: I,
    ) -> Result<()> {
        for (key, value) in entries {
            let update_key = UpdatedKey::from((key, value));
            let value = value.additional_time;
            let Some(last_sample) = self.updated.remove(&update_key) else {
                continue;
            };

            assert!(last_sample <= value);
            if last_sample < value {
                continue;
            }

            let key = to_update_key::from(update_key);
            let key = unsafe {
                std::mem::transmute::<to_update_key, [u8; size_of::<to_update_key>()]>(key)
            };
            self.skel.maps.to_update.delete(&key)?
        }
        Ok(())
    }

    fn upsert_pending(&mut self) -> Result<()> {
        self.conn.execute_batch(
            r"
            UPDATE 
                muxio_wait as mw
            SET 
                total_time = total_time + additional_time
            FROM 
                muxio_staging as ms
            WHERE
                mw.ts_s = ms.ts_s
                AND mw.pid = ms.pid
                AND mw.tid = ms.tid
                AND mw.is_epoll = ms.is_epoll
                AND mw.poll_id = ms.poll_id;

            INSERT INTO muxio_wait (machine_id, ts_s, pid, tid, is_epoll, poll_id, total_time)
                SELECT 
                    ms.*
                FROM muxio_staging as ms
                LEFT JOIN muxio_wait as mw
                    USING (ts_s, pid, tid, is_epoll, poll_id)
                WHERE 
                    mw.ts_s IS NULL;

            DELETE FROM muxio_staging;
            ",
        )?;
        Ok(())
    }

    fn store_file_samples<
        'a,
        I: ExactSizeIterator<Item = (&'a file_granularity, &'a file_stats)>,
    >(
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
            self.muxio_file_appender.append_row([
                &self.machine_id as &dyn ToSql,
                &Duration::from_nanos(ts_s),
                &granularity.id,
                &granularity.bri.fs_magic,
                &granularity.bri.i_rdev,
                &granularity.bri.i_ino,
                &granularity.mode,
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

        // thread mux samples
        let (keys, values) = super::replace_samples(&self.skel.maps.samples, &ts);
        self.store_samples(keys.iter().zip(values.iter()))?;
        self.muxio_appender.flush();

        let mut pending_records = Vec::new();
        let (mut pending_keys, mut pending_values) = (Vec::new(), Vec::new());
        super::read_batch::<inflight_key, inflight_value>(
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
        super::read_batch::<to_update_key, to_update_value>(
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
        self.muxio_staging_appender.flush();

        self.upsert_pending()?;
        self.remove_updated_entries(to_update_keys.iter().zip(to_update_values.iter()))?;

        // thread mux samples
        let (keys, values) = super::replace_samples(&self.skel.maps.file_samples, &ts);
        self.store_file_samples(keys.iter().zip(values.iter()))?;
        self.muxio_file_appender.flush();

        Ok(())
    }
}
