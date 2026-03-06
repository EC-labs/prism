use anyhow::{bail, Result};
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME};
use log::{debug, error, warn};
use std::{
    collections::HashMap,
    ffi::c_void,
    fmt::Debug,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    time::Duration,
};

use super::UpdateEnd;

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

#[derive(Debug)]
struct PendingRecord {
    ts_s: u64,
    pid: u32,
    tid: u32,
    bri: Bri,
    additional_time: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Bri {
    aioctx: u64,
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
        key.granularity.aioctx = value.bri.aioctx as *mut c_void;
        key
    }
}

impl From<(&inflight_key, &inflight_value)> for UpdatedKey {
    fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
        Self {
            start: value.ts,
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
            start: key.ts,
            tgid_pid: ((key.granularity.tgid as u64) << 32) | (key.granularity.pid as u64),
            bri: Bri {
                aioctx: key.granularity.aioctx as u64,
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

pub struct Aio<'conn, 'obj> {
    skel: AioSkel<'obj>,
    machine_id: u32,
    aio_getevents_appender: Appender<'conn>,
    aio_staging_appender: Appender<'conn>,
    aio_submit_appender: Appender<'conn>,
    aio_file_appender: Appender<'conn>,
    conn: &'conn Connection,
    updated: HashMap<UpdatedKey, u64>,
}

impl<'conn, 'obj> Aio<'conn, 'obj> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        conn: &'conn Connection,
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

        Self::init_store(conn);
        let aio_getevents_appender = conn
            .appender("aio_getevents")
            .expect("Table aio_getevents does not exist");
        let aio_staging_appender = conn
            .appender("aio_staging")
            .expect("Table aio_staging does not exist");
        let aio_submit_appender = conn
            .appender("aio_submit")
            .expect("Table aio_submit does not exist");
        let aio_file_appender = conn
            .appender("aio_file")
            .expect("Table aio_file does not exist");
        Ok(Aio {
            machine_id,
            skel,
            aio_getevents_appender,
            aio_staging_appender,
            aio_submit_appender,
            aio_file_appender,
            conn,
            updated: HashMap::new(),
        })
    }

    fn init_store(conn: &Connection) {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE aio_getevents (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    aioctx UBIGINT,
                    total_time UBIGINT,
                    total_requests UBIGINT,
                );

                CREATE OR REPLACE TEMP TABLE aio_staging (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    aioctx UBIGINT,
                    additional_time UBIGINT,
                );

                CREATE OR REPLACE TABLE aio_submit (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    aioctx UBIGINT,
                    total_requests UBIGINT,
                );

                CREATE OR REPLACE TABLE aio_file (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    aioctx UBIGINT,
                    isreg UTINYINT,
                    fs_magic UINTEGER,
                    device_id UINTEGER,
                    inode_id UBIGINT,
                    part0 UBIGINT,
                    bdev UBIGINT,
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
        .expect("Aio store initialisation failed");
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
            match granularity.op as u32 {
                super::consts::AIO_GETEVENTS => self.aio_getevents_appender.append_row([
                    &self.machine_id as &dyn ToSql,
                    &Duration::from_nanos(ts_s),
                    &granularity.tgid,
                    &granularity.pid,
                    &(granularity.aioctx as u64),
                    &stats.total_time,
                    &stats.total_requests,
                ])?,
                super::consts::AIO_SUBMIT => self.aio_submit_appender.append_row([
                    &self.machine_id as &dyn ToSql,
                    &Duration::from_nanos(ts_s),
                    &granularity.tgid,
                    &granularity.pid,
                    &(granularity.aioctx as u64),
                    &stats.total_requests,
                ])?,
                op => {
                    error!("unknown aio op code: `{}`", op);
                    bail!("unknown aio op code `{}`", op);
                }
            }
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
            self.aio_staging_appender.append_row([
                &self.machine_id as &dyn ToSql,
                &Duration::from_nanos(ts_s),
                &record.pid,
                &record.tid,
                &record.bri.aioctx,
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
                aio_getevents as t
            SET 
                total_time = total_time + additional_time
            FROM 
                aio_staging as s
            WHERE
                t.machine_id = s.machine_id
                AND t.ts_s = s.ts_s
                AND t.pid = s.pid
                AND t.tid = s.tid
                AND t.aioctx = s.aioctx;

            INSERT INTO aio_getevents (machine_id, ts_s, pid, tid, aioctx, total_time)
                SELECT 
                    s.*
                FROM aio_staging as s
                LEFT JOIN aio_getevents as t
                    USING (machine_id, ts_s, pid, tid, aioctx)
                WHERE 
                    t.ts_s IS NULL;

            DELETE FROM aio_staging;
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

        debug!("Store {} file samples", records.len());
        for (granularity, stats) in records {
            let ts_s = crate::extract::boot_to_epoch(stats.ts_s * 1_000_000_000);
            match granularity.isreg as u32 {
                0 => unsafe {
                    self.aio_file_appender.append_row([
                        &self.machine_id as &dyn ToSql,
                        &Duration::from_nanos(ts_s),
                        &granularity.aioctx,
                        &(0 as u8),
                        &granularity.__anon_34.bri.fs_magic,
                        &granularity.__anon_34.bri.i_rdev,
                        &granularity.__anon_34.bri.i_ino,
                        &None::<u64>,
                        &None::<u64>,
                        &granularity.mode,
                        &stats.hist[0],
                        &stats.hist[1],
                        &stats.hist[2],
                        &stats.hist[3],
                        &stats.hist[4],
                        &stats.hist[5],
                        &stats.hist[6],
                        &stats.hist[7],
                    ])?
                },
                1 => unsafe {
                    self.aio_file_appender.append_row([
                        &self.machine_id as &dyn ToSql,
                        &Duration::from_nanos(ts_s),
                        &granularity.aioctx,
                        &(1 as u8),
                        &None::<u32>,
                        &None::<u32>,
                        &None::<u64>,
                        &granularity.__anon_34.bdev.part0,
                        &granularity.__anon_34.bdev.dev,
                        &granularity.mode,
                        &stats.hist[0],
                        &stats.hist[1],
                        &stats.hist[2],
                        &stats.hist[3],
                        &stats.hist[4],
                        &stats.hist[5],
                        &stats.hist[6],
                        &stats.hist[7],
                    ])?
                },
                op => {
                    error!("unknown aio_file op code: `{}`", op);
                    bail!("unknown aio_file op code `{}`", op);
                }
            }
        }

        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts as *mut timespec) };
        let (keys, values) = super::replace_samples(&self.skel.maps.samples, &ts);
        self.store_samples(keys.iter().zip(values.iter()))?;
        self.aio_getevents_appender.flush();

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
        self.aio_staging_appender.flush();

        self.upsert_pending()?;
        self.remove_updated_entries(to_update_keys.iter().zip(to_update_values.iter()))?;

        let (keys, values) = super::replace_samples(&self.skel.maps.file_samples, &ts);
        self.store_file_samples(keys.iter().zip(values.iter()))?;
        self.aio_file_appender.flush();

        Ok(())
    }
}
