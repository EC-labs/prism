// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::{bail, Result};
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    libbpf_sys::{self, __u32, bpf_map_create},
    skel::{OpenSkel, Skel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, OpenObject, RingBuffer, RingBufferBuilder,
};
use libc::{
    clock_gettime, timespec, AF_INET, AF_INET6, AF_UNIX, CLOCK_MONOTONIC, SOCK_DGRAM,
    SOCK_SEQPACKET, SOCK_STREAM,
};
use log::debug;
use std::{
    collections::HashMap,
    ffi::{c_void, CStr},
    fmt::Debug,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    time::{Duration, SystemTime},
};
use types::{inflight_key, inflight_value, socket_context_value, to_update_key};

mod net {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/net/bpf/net.skel.rs"
    ));
}

use net::types::{granularity, stats};
use net::*;
const BATCH_SIZE: usize = 8192;
const SAMPLES: u64 = 10;

#[derive(Debug, Default)]
struct SocketContext {
    netns_cookie: u64,
    inode_id: u64,
    sk_family: u16,
    sk_type: u16,
    sk_protocol: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    dst_addr: Option<IpAddr>,
    dst_port: Option<u16>,
}

impl TryFrom<&socket_context_value> for SocketContext {
    type Error = ();
    fn try_from(value: &socket_context_value) -> Result<Self, Self::Error> {
        // let mut res = SocketContext::default();
        let mut res = Self {
            netns_cookie: value.netns_cookie,
            inode_id: value.inode_id,
            sk_family: value.family,
            sk_type: value.sk_type,
            sk_protocol: value.sk_protocol,
            ..Default::default()
        };
        match value.family as i32 {
            AF_INET => {
                let src_addr = unsafe { u32::from_be(value.__anon_5.ipv4.src_addr) };
                res.src_addr = Some(IpAddr::V4(Ipv4Addr::from(src_addr)));

                let dst_addr = unsafe { u32::from_be(value.__anon_5.ipv4.dst_addr) };
                res.dst_addr = Some(IpAddr::V4(Ipv4Addr::from(dst_addr)));

                match value.sk_type as i32 {
                    SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => {
                        res.src_port = Some(value.src_port);
                        res.dst_port = Some(u16::from_be(value.dst_port));
                    }
                    _ => {}
                }
            }
            AF_INET6 => {
                let src_addr = unsafe { value.__anon_5.ipv6.src_addr };
                let src_addr: u128 = unsafe { std::mem::transmute(src_addr) };
                let src_addr = u128::from_be(src_addr);
                res.src_addr = Some(IpAddr::V6(Ipv6Addr::from(src_addr)));

                let dst_addr = unsafe { value.__anon_5.ipv6.dst_addr };
                let dst_addr: u128 = unsafe { std::mem::transmute(dst_addr) };
                let dst_addr = u128::from_be(dst_addr);
                res.dst_addr = Some(IpAddr::V6(Ipv6Addr::from(dst_addr)));

                match value.sk_type as i32 {
                    SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => {
                        res.src_port = Some(value.src_port);
                        res.dst_port = Some(u16::from_be(value.dst_port));
                    }
                    _ => {}
                }
            }
            AF_UNIX => {}
            _ => return Err(()),
        }

        Ok(res)
    }
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

// trait UpdateEnd<T> {
//     fn update_end(curr: u64, pending: T) -> u64;
// }

// impl UpdateEnd<&u64> for &u64 {
//     fn update_end(curr: u64, pending: &u64) -> u64 {
//         *pending / 1_000_000_000 * 1_000_000_000
//     }
// }

// impl UpdateEnd<&inflight_value> for &inflight_value {
//     fn update_end(curr: u64, pending: &inflight_value) -> u64 {
//         curr
//     }
// }

// impl From<UpdatedKey> for to_update_key {
//     fn from(value: UpdatedKey) -> Self {
//         let mut key: to_update_key = unsafe { MaybeUninit::zeroed().assume_init() };
//         key.ts = value.start;
//         key.granularity.bri.s_id.copy_from_slice(&value.bri.fs_id);
//         key.granularity.bri.i_ino = value.bri.i_ino;
//         key.granularity.bri.i_rdev = value.bri.i_rdev;
//         key.granularity.pid = value.tgid_pid as u32;
//         key.granularity.tgid = (value.tgid_pid >> 32) as u32;
//         key.granularity.dir = value.is_write;
//         key
//     }
// }

// #[derive(Debug, PartialEq, Eq, Hash, Clone)]
// struct Bri {
//     fs_id: [u8; 32],
//     i_ino: u64,
//     i_rdev: u32,
// }

// #[derive(Debug, PartialEq, Eq, Hash)]
// struct UpdatedKey {
//     bri: Bri,
//     start: u64,
//     tgid_pid: u64,
//     is_write: u8,
// }

// #[derive(Debug)]
// struct PendingRecord {
//     ts_s: u64,
//     pid: u32,
//     tid: u32,
//     bri: Bri,
//     additional_time: u64,
//     is_write: u8,
// }

// impl From<(&to_update_key, &u64)> for UpdatedKey {
//     fn from((key, _): (&to_update_key, &u64)) -> Self {
//         Self {
//             bri: Bri {
//                 fs_id: key.granularity.bri.s_id,
//                 i_ino: key.granularity.bri.i_ino,
//                 i_rdev: key.granularity.bri.i_rdev,
//             },
//             start: key.ts,
//             tgid_pid: (key.granularity.tgid as u64) << 32 | key.granularity.pid as u64,
//             is_write: key.granularity.dir,
//         }
//     }
// }

// impl From<(&inflight_key, &inflight_value)> for UpdatedKey {
//     fn from((key, value): (&inflight_key, &inflight_value)) -> Self {
//         Self {
//             bri: Bri {
//                 fs_id: value.bri.s_id,
//                 i_ino: value.bri.i_ino,
//                 i_rdev: value.bri.i_rdev,
//             },
//             start: value.ts,
//             tgid_pid: key.tgid_pid,
//             is_write: value.is_write,
//         }
//     }
// }

pub struct Net<'obj> {
    skel: NetSkel<'obj>,
    rb: RingBuffer<'obj>,
    // appender: Appender<'conn>,
    // staging_appender: Appender<'conn>,
    // conn: &'conn Connection,
    // updated: HashMap<UpdatedKey, u64>,
}

impl<'obj> Net<'obj> {
    pub fn new<'conn>(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        conn: &'conn Connection,
        pid_map: BorrowedFd,
        samples_map: BorrowedFd,
        pending_map: BorrowedFd,
        to_update_map: BorrowedFd,
    ) -> Result<Self>
    where
        'conn: 'obj,
    {
        Self::init_store(conn)?;
        let skel_builder = NetSkelBuilder::default();

        bump_memlock_rlimit()?;
        let mut open_skel = skel_builder.open(open_object)?;
        open_skel.maps.pids.reuse_fd(pid_map)?;
        open_skel.maps.samples.reuse_fd(samples_map)?;
        open_skel.maps.pending.reuse_fd(pending_map)?;
        open_skel.maps.to_update.reuse_fd(to_update_map)?;

        let mut skel = open_skel.load()?;
        // for i in 0..SAMPLES {
        //     let mapfd = unsafe {
        //         bpf_map_create(
        //             libbpf_sys::BPF_MAP_TYPE_HASH,
        //             std::ptr::null(),
        //             size_of::<granularity>() as u32,
        //             size_of::<stats>() as u32,
        //             8192,
        //             std::ptr::null(),
        //         )
        //     };
        //     if mapfd < 0 {
        //         bail!("Failed to create map for {i}: {mapfd}")
        //     }

        //     skel.maps.samples.update(
        //         &(i as u64).to_ne_bytes(),
        //         &mapfd.to_ne_bytes(),
        //         MapFlags::ANY,
        //     )?;
        //     unsafe { libc::close(mapfd) };
        // }
        let mut builder = RingBufferBuilder::new();
        builder.add(
            &skel.maps.rb,
            wrapped_callback(
                conn.appender("socket_context").unwrap(),
                conn.appender("socket_inet").unwrap(),
            ),
        )?;
        let rb = builder.build()?;

        skel.attach()?;

        Ok(Self {
            skel,
            rb,
            // appender: conn.appender("vfs")?,
            // staging_appender: conn.appender("vfs_staging")?,
            // conn,
            // updated: HashMap::new(),
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE socket_context (
                    socket_inode_id UBIGINT,
                    family          USMALLINT, 
                    type            USMALLINT, 
                    protocol        USMALLINT, 
                );

                CREATE OR REPLACE TABLE socket_inet (
                    inode_id        UBIGINT,
                    netns_cookie    UBIGINT,
                    src_address     VARCHAR,
                    src_port        USMALLINT, 
                    dst_address     VARCHAR,
                    dst_port        USMALLINT, 
                );
            ",
        )?;
        Ok(())
    }

    // fn store_samples<'a, I: ExactSizeIterator<Item = (&'a granularity, &'a stats)>>(
    //     &mut self,
    //     records: I,
    // ) -> Result<()> {
    //     let nrecords = records.len();
    //     if nrecords == 0 {
    //         return Ok(());
    //     }

    //     debug!("Store {} records", records.len());
    //     let records = records.map(|(granularity, stats)| {
    //         let ts_s = crate::extract::boot_to_epoch(stats.ts_s * 1_000_000_000);
    //         let fs_id = unsafe { CStr::from_ptr(granularity.bri.s_id.as_ptr() as *const i8) };
    //         let fs_id = fs_id.to_str().unwrap();
    //         [
    //             Box::new(Duration::from_nanos(ts_s)) as Box<dyn ToSql>,
    //             Box::new(&granularity.tgid),
    //             Box::new(&granularity.pid),
    //             Box::new(fs_id),
    //             Box::new(&granularity.bri.i_rdev),
    //             Box::new(&granularity.bri.i_ino),
    //             Box::new(&granularity.dir),
    //             Box::new(&stats.total_time),
    //             Box::new(&stats.total_requests),
    //             Box::new(&stats.hist[0]),
    //             Box::new(&stats.hist[1]),
    //             Box::new(&stats.hist[2]),
    //             Box::new(&stats.hist[3]),
    //             Box::new(&stats.hist[4]),
    //             Box::new(&stats.hist[5]),
    //             Box::new(&stats.hist[6]),
    //             Box::new(&stats.hist[7]),
    //         ]
    //     });
    //     self.appender.append_rows(records)?;

    //     Ok(())
    // }

    // fn store_pending<'a, I: ExactSizeIterator<Item = &'a PendingRecord>>(
    //     &mut self,
    //     records: I,
    // ) -> Result<()> {
    //     let nrecords = records.len();
    //     if nrecords == 0 {
    //         return Ok(());
    //     }

    //     debug!("Stage {} records", records.len());
    //     let records = records.map(|record| {
    //         let ts_s = crate::extract::boot_to_epoch(record.ts_s * 1_000_000_000);
    //         let fs_id = unsafe { CStr::from_ptr(record.bri.fs_id.as_ptr() as *const i8) };
    //         let fs_id = fs_id.to_str().unwrap();
    //         [
    //             Box::new(Duration::from_nanos(ts_s)) as Box<dyn ToSql>,
    //             Box::new(&record.pid),
    //             Box::new(&record.tid),
    //             Box::new(fs_id),
    //             Box::new(&record.bri.i_rdev),
    //             Box::new(&record.bri.i_ino),
    //             Box::new(&record.is_write),
    //             Box::new(&record.additional_time),
    //         ]
    //     });
    //     self.staging_appender.append_rows(records)?;

    //     Ok(())
    // }

    // fn upsert_pending(&mut self) -> Result<()> {
    //     self.conn.execute_batch(
    //         r"
    //         UPDATE
    //             vfs as v
    //         SET
    //             total_time = total_time + additional_time
    //         FROM
    //             vfs_staging as vs
    //         WHERE
    //             v.ts_s = vs.ts_s
    //             AND v.pid = vs.pid
    //             AND v.tid = vs.tid
    //             AND v.fs_id = vs.fs_id
    //             AND v.device_id = vs.device_id
    //             AND v.inode_id = vs.inode_id
    //             AND v.is_write = vs.is_write;

    //         INSERT INTO vfs (ts_s, pid, tid, fs_id, device_id, inode_id, is_write, total_time)
    //             SELECT
    //                 vs.*
    //             FROM vfs_staging as vs
    //             LEFT JOIN vfs as v
    //                 USING (ts_s, pid, tid, fs_id, device_id, inode_id, is_write)
    //             WHERE
    //                 v.ts_s IS NULL;

    //         DELETE FROM vfs_staging;
    //         ",
    //     )?;
    //     Ok(())
    // }

    // fn read_samples(&mut self, ts: &timespec) -> (Vec<granularity>, Vec<stats>) {
    //     let curr = ts.tv_sec as u64;
    //     let mut keys: Vec<granularity> = Vec::new();
    //     let mut values: Vec<stats> = Vec::new();
    //     for ts in (curr - (SAMPLES - 1))..curr {
    //         let outer = ts % SAMPLES;

    //         let inner_id = self
    //             .skel
    //             .maps
    //             .samples
    //             .lookup(&(outer as u64).to_ne_bytes(), MapFlags::ANY);

    //         let inner_id = match inner_id {
    //             Ok(Some(inner_vec)) => {
    //                 let mut inner: [u8; 4] = [0; 4];
    //                 inner.copy_from_slice(&inner_vec);
    //                 u32::from_ne_bytes(inner)
    //             }
    //             _ => {
    //                 continue;
    //             }
    //         };
    //         let mh = MapHandle::from_map_id(inner_id).unwrap();
    //         let count = Self::read_batch(mh.as_fd().as_raw_fd(), &mut keys, &mut values);

    //         if count == 0 {
    //             continue;
    //         }

    //         let mapfd = unsafe {
    //             bpf_map_create(
    //                 libbpf_sys::BPF_MAP_TYPE_HASH,
    //                 std::ptr::null(),
    //                 size_of::<granularity>() as u32,
    //                 size_of::<stats>() as u32,
    //                 8192,
    //                 std::ptr::null(),
    //             )
    //         };
    //         if mapfd < 0 {
    //             println!("Failed to create map for {outer}: {mapfd}");
    //             continue;
    //         }

    //         let res = self.skel.maps.samples.update(
    //             &(outer as u64).to_ne_bytes(),
    //             &mapfd.to_ne_bytes(),
    //             MapFlags::ANY,
    //         );
    //         match res {
    //             Ok(()) => {}
    //             Err(e) => {
    //                 println!("Failed to update map {}: {e}", outer);
    //             }
    //         }
    //         unsafe { libc::close(mapfd) };
    //     }
    //     (keys, values)
    // }

    // fn read_batch<'a, K, V>(map_fd: RawFd, keys: &mut Vec<K>, values: &mut Vec<V>) -> usize {
    //     let mut total = 0;
    //     let mut in_batch: u64 = unsafe { MaybeUninit::zeroed().assume_init() };
    //     let mut out_batch: u64 = unsafe { MaybeUninit::zeroed().assume_init() };
    //     let mut count: __u32;

    //     loop {
    //         count = BATCH_SIZE as u32;
    //         assert!(keys.len() == values.len());
    //         let batch_start = keys.len();
    //         if keys.capacity() - keys.len() < BATCH_SIZE {
    //             keys.reserve(BATCH_SIZE - (keys.capacity() - keys.len()));
    //         }

    //         if values.capacity() - values.len() < BATCH_SIZE {
    //             values.reserve(BATCH_SIZE - (values.capacity() - values.len()));
    //         }
    //         unsafe {
    //             libbpf_sys::bpf_map_lookup_batch(
    //                 map_fd,
    //                 std::mem::transmute::<&mut u64, *mut c_void>(&mut in_batch),
    //                 std::mem::transmute::<&mut u64, *mut c_void>(&mut out_batch),
    //                 std::mem::transmute::<_, *mut c_void>(keys[batch_start..].as_mut_ptr()),
    //                 std::mem::transmute::<_, *mut c_void>(values[batch_start..].as_mut_ptr()),
    //                 &mut count as *mut __u32,
    //                 std::ptr::null(),
    //             );
    //             keys.set_len(batch_start + count as usize);
    //             values.set_len(batch_start + count as usize);
    //         }
    //         std::mem::swap(&mut in_batch, &mut out_batch);

    //         total += count;
    //         if count == 0 {
    //             break;
    //         }
    //     }
    //     total as usize
    // }

    // fn create_pending_records<'a, K, V, I>(
    //     &mut self,
    //     pending: I,
    //     now: &timespec,
    //     records: &mut Vec<PendingRecord>,
    // ) where
    //     I: Iterator<Item = (K, V)>,
    //     UpdatedKey: From<(K, V)>,
    //     V: UpdateEnd<V>,
    //     K: Copy,
    //     V: Copy + Debug,
    // {
    //     let curr_sample = (now.tv_sec as u64) * 1_000_000_000;
    //     for (key, value) in pending {
    //         let updated_key = UpdatedKey::from((key, value));
    //         let last_sample = *self.updated.get(&updated_key).unwrap_or(&updated_key.start);
    //         let start = (last_sample / 1_000_000_000 * 1_000_000_000) + 1_000_000_000;
    //         let end = V::update_end(curr_sample, value);
    //         if end < start {
    //             continue;
    //         }

    //         for sample in (start..=end).step_by(1_000_000_000) {
    //             let additional_time = u64::min(1_000_000_000, sample - last_sample);
    //             records.push(PendingRecord {
    //                 ts_s: (sample - 1) / 1_000_000_000,
    //                 pid: (updated_key.tgid_pid >> 32) as u32,
    //                 tid: (updated_key.tgid_pid & ((1 << 32) - 1)) as u32,
    //                 bri: updated_key.bri.clone(),
    //                 additional_time,
    //                 is_write: updated_key.is_write,
    //             });
    //         }

    //         assert!(end > last_sample);
    //         self.updated.insert(updated_key, end);
    //     }
    // }

    // fn remove_updated_entries<'a, I: Iterator<Item = (&'a to_update_key, &'a u64)>>(
    //     &mut self,
    //     entries: I,
    // ) -> Result<()> {
    //     for (key, value) in entries {
    //         let update_key = UpdatedKey::from((key, value));
    //         let Some(last_sample) = self.updated.get(&update_key) else {
    //             continue;
    //         };

    //         assert!(last_sample <= value);
    //         if last_sample < value {
    //             continue;
    //         }

    //         self.updated.remove(&update_key);
    //         let key = to_update_key::from(update_key);
    //         let key = unsafe { std::mem::transmute::<_, [u8; size_of::<to_update_key>()]>(key) };
    //         self.skel.maps.to_update.delete(&key)?
    //     }
    //     Ok(())
    // }

    pub fn sample(&mut self) -> Result<()> {
        self.rb.consume()?;
        // let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        // unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
        // let (keys, values) = self.read_samples(&ts);
        // self.store_samples(keys.iter().zip(values.iter()))?;
        // self.appender.flush();

        // let mut pending_records = Vec::new();
        // let (mut pending_keys, mut pending_values) = (Vec::new(), Vec::new());
        // Self::read_batch::<inflight_key, inflight_value>(
        //     self.skel.maps.pending.as_fd().as_raw_fd(),
        //     &mut pending_keys,
        //     &mut pending_values,
        // );
        // self.create_pending_records(
        //     pending_keys.iter().zip(pending_values.iter()),
        //     &ts,
        //     &mut pending_records,
        // );
        // debug!("after pending: {}", pending_records.len());

        // let (mut to_update_keys, mut to_update_values) = (Vec::new(), Vec::new());
        // Self::read_batch::<to_update_key, u64>(
        //     self.skel.maps.to_update.as_fd().as_raw_fd(),
        //     &mut to_update_keys,
        //     &mut to_update_values,
        // );
        // self.create_pending_records(
        //     to_update_keys.iter().zip(to_update_values.iter()),
        //     &ts,
        //     &mut pending_records,
        // );
        // debug!("after to_update: {}", pending_records.len());
        // self.store_pending(pending_records.iter())?;
        // self.staging_appender.flush();

        // self.upsert_pending()?;
        // self.remove_updated_entries(to_update_keys.iter().zip(to_update_values.iter()))?;

        Ok(())
    }
}

fn wrapped_callback<'conn>(
    mut socket_context_appender: Appender<'conn>,
    mut socket_inet_appender: Appender<'conn>,
) -> impl FnMut(&[u8]) -> i32 + use<'conn> {
    let cb = move |data: &[u8]| {
        let data: &[u8; size_of::<socket_context_value>()] = &data
            [..size_of::<socket_context_value>()]
            .try_into()
            .unwrap();
        let socket_context: &socket_context_value = unsafe { std::mem::transmute(data) };
        let Ok(context) = SocketContext::try_from(socket_context) else {
            return 0;
        };

        println!("{:?}", context);
        socket_context_appender
            .append_row([
                &context.inode_id as &dyn ToSql,
                &context.sk_family,
                &context.sk_type,
                &context.sk_protocol,
            ])
            .unwrap();
        match (context.src_addr, context.dst_addr) {
            (Some(IpAddr::V4(src_addr)), Some(IpAddr::V4(dst_addr))) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &dst_addr.to_string(),
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            (Some(IpAddr::V4(src_addr)), None) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &Ipv4Addr::from(0).to_string() as &dyn ToSql,
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            (Some(IpAddr::V6(src_addr)), Some(IpAddr::V6(dst_addr))) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &dst_addr.to_string(),
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            (Some(IpAddr::V6(src_addr)), None) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &Ipv4Addr::from(0).to_string() as &dyn ToSql,
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            _ => {}
        }
        0
    };
    cb
}
