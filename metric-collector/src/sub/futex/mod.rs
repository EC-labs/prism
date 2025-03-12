// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::{bail, Result};
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    libbpf_sys::{self, __u32, bpf_map_create},
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, MapFlags, MapHandle, OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC, FUTEX_WAIT, FUTEX_WAKE};
use log::debug;
use std::{
    collections::HashMap,
    ffi::c_void,
    fmt::Debug,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    time::Duration,
};
use types::{granularity, inflight_key, inflight_value, stats, to_update_key};

mod futex {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/futex/bpf/futex.skel.rs"
    ));
}

use futex::*;
const BATCH_SIZE: usize = 8192;
const SAMPLES: u64 = 10;

trait UpdateEnd<T> {
    fn update_end(curr: u64, pending: T) -> u64;
}

impl UpdateEnd<&u64> for &u64 {
    fn update_end(_: u64, pending: &u64) -> u64 {
        *pending / 1_000_000_000 * 1_000_000_000
    }
}

impl UpdateEnd<&inflight_value> for &inflight_value {
    fn update_end(curr: u64, _: &inflight_value) -> u64 {
        curr
    }
}

impl From<UpdatedKey> for to_update_key {
    fn from(value: UpdatedKey) -> Self {
        let mut key: to_update_key = unsafe { MaybeUninit::zeroed().assume_init() };
        key.ts = value.start;
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
    start: u64,
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
            start: map_value.ts,
            tgid_pid: map_key.tgid_pid,
        }
    }
}

impl From<(&to_update_key, &u64)> for UpdatedKey {
    fn from((map_key, _): (&to_update_key, &u64)) -> Self {
        let fkey = unsafe { map_key.granularity.fkey.both };
        UpdatedKey {
            futex_key: FutexKey {
                ptr: fkey.ptr,
                word: fkey.word,
                offset: fkey.offset,
            },
            start: map_key.ts,
            tgid_pid: (map_key.granularity.tgid as u64) << 32 | map_key.granularity.pid as u64,
        }
    }
}

#[derive(Debug)]
struct PendingRecord {
    ts_s: u64,
    pid: u32,
    tid: u32,
    futex_key: FutexKey,
    additional_time: u64,
}

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

pub struct Futex<'obj, 'conn> {
    skel: FutexSkel<'obj>,
    futex_wait_appender: Appender<'conn>,
    futex_wake_appender: Appender<'conn>,
    updated: HashMap<UpdatedKey, u64>,
    staging_appender: Appender<'conn>,
    conn: &'conn Connection,
}

impl<'obj, 'conn> Futex<'obj, 'conn> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        conn: &'conn Connection,
    ) -> Result<Self> {
        let skel_builder = FutexSkelBuilder::default();

        bump_memlock_rlimit()?;
        let mut open_skel = skel_builder.open(open_object)?;
        open_skel.maps.pids.reuse_fd(pid_map)?;

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
            futex_wait_appender: conn.appender("futex_wait")?,
            futex_wake_appender: conn.appender("futex_wake")?,
            staging_appender: conn.appender("futex_wait_staging")?,
            updated: HashMap::new(),
            conn,
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE futex_wait (
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    futex_key_addr UBIGINT,
                    futex_key_word UBIGINT,
                    futex_key_offset UINTEGER,
                    total_requests UBIGINT,
                    total_time UBIGINT,
                    hist0 UINTEGER,
                    hist1 UINTEGER,
                    hist2 UINTEGER,
                    hist3 UINTEGER,
                    hist4 UINTEGER,
                    hist5 UINTEGER,
                    hist6 UINTEGER,
                    hist7 UINTEGER,
                );

                CREATE OR REPLACE TEMP TABLE futex_wait_staging (
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    futex_key_addr UBIGINT,
                    futex_key_word UBIGINT,
                    futex_key_offset UINTEGER,
                    additional_time UBIGINT,
                );

                CREATE OR REPLACE TABLE futex_wake (
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    futex_key_addr UBIGINT,
                    futex_key_word UBIGINT,
                    futex_key_offset UINTEGER,
                    total_requests UBIGINT,
                    successful_count UBIGINT,
                );
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
        for (granularity, stat) in records {
            match granularity.op as i32 {
                FUTEX_WAIT => {
                    let stat = unsafe { stat.wait };
                    let fkey = unsafe { granularity.fkey.both };
                    let ts_s = crate::extract::boot_to_epoch(stat.ts_s * 1_000_000_000);
                    self.futex_wait_appender.append_row([
                        Box::new(Duration::from_nanos(ts_s)) as Box<dyn ToSql>,
                        Box::new(&granularity.tgid),
                        Box::new(&granularity.pid),
                        Box::new(&fkey.ptr),
                        Box::new(&fkey.word),
                        Box::new(&fkey.offset),
                        Box::new(&stat.total_requests),
                        Box::new(&stat.total_time),
                        Box::new(&stat.hist[0]),
                        Box::new(&stat.hist[1]),
                        Box::new(&stat.hist[2]),
                        Box::new(&stat.hist[3]),
                        Box::new(&stat.hist[4]),
                        Box::new(&stat.hist[5]),
                        Box::new(&stat.hist[6]),
                        Box::new(&stat.hist[7]),
                    ])?;
                }
                FUTEX_WAKE => {
                    let stat = unsafe { stat.wake };
                    let fkey = unsafe { granularity.fkey.both };
                    let ts_s = crate::extract::boot_to_epoch(stat.ts_s * 1_000_000_000);
                    self.futex_wake_appender.append_row([
                        Box::new(Duration::from_nanos(ts_s)) as Box<dyn ToSql>,
                        Box::new(&granularity.tgid),
                        Box::new(&granularity.pid),
                        Box::new(&fkey.ptr),
                        Box::new(&fkey.word),
                        Box::new(&fkey.offset),
                        Box::new(&stat.total_requests),
                        Box::new(&stat.successful_count),
                    ])?;
                }
                op => bail!("unexpected op {}", op),
            }
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
        let records = records.map(|record| {
            let ts_s = crate::extract::boot_to_epoch(record.ts_s * 1_000_000_000);
            [
                Box::new(Duration::from_nanos(ts_s)) as Box<dyn ToSql>,
                Box::new(&record.pid),
                Box::new(&record.tid),
                Box::new(&record.futex_key.ptr),
                Box::new(&record.futex_key.word),
                Box::new(&record.futex_key.offset),
                Box::new(&record.additional_time),
            ]
        });
        self.staging_appender.append_rows(records)?;

        Ok(())
    }

    fn upsert_pending(&mut self) -> Result<()> {
        self.conn.execute_batch(
            r"
            UPDATE futex_wait as f
            SET
                total_time = total_time + additional_time
            FROM
                futex_wait_staging as fs
            WHERE
                f.ts_s = fs.ts_s
                AND f.pid = fs.pid
                AND f.tid = fs.tid
                AND f.futex_key_addr = fs.futex_key_addr
                AND f.futex_key_word = fs.futex_key_word
                AND f.futex_key_offset = fs.futex_key_offset;

            INSERT INTO futex_wait (ts_s, pid, tid, futex_key_addr, futex_key_word, futex_key_offset, total_time)
                SELECT
                    fs.*
                FROM futex_wait_staging as fs
                LEFT JOIN futex_wait as f
                    USING (ts_s, pid, tid, futex_key_addr, futex_key_word, futex_key_offset)
                WHERE
                    f.ts_s IS NULL;

            DELETE FROM futex_wait_staging;
            ",
        )?;
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
                    futex_key: updated_key.futex_key.clone(),
                    additional_time,
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
        let (keys, values) = self.read_samples(&ts);
        self.store_samples(keys.iter().zip(values.iter()))?;
        self.futex_wake_appender.flush();
        self.futex_wait_appender.flush();

        let mut pending_records = Vec::new();
        let (mut pending_keys, mut pending_values) = (Vec::new(), Vec::new());
        Self::read_batch::<inflight_key, inflight_value>(
            self.skel.maps.pending.as_fd().as_raw_fd(),
            &mut pending_keys,
            &mut pending_values,
        );
        self.create_pending_records(
            pending_keys
                .iter()
                .zip(pending_values.iter())
                .filter(|(_, value)| value.op as i32 == FUTEX_WAIT),
            &ts,
            &mut pending_records,
        );
        debug!("after pending: {}", pending_records.len());

        let (mut to_update_keys, mut to_update_values) = (Vec::new(), Vec::new());
        Self::read_batch::<to_update_key, u64>(
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
