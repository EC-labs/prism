// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::{bail, Result};
use duckdb::{Appender, Connection};
use libbpf_rs::{
    libbpf_sys::{self, __u32, bpf_map_create, BPF_ANY},
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, MapFlags, MapHandle, MapImpl, MapType, OpenObject,
};
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC};
use std::{
    ffi::c_void,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, RawFd},
    time::Duration,
};
use types::to_update_key;

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

pub struct Vfs<'obj, 'conn> {
    skel: VfsSkel<'obj>,
    appender: Appender<'conn>,
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
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE vfs (
                    ts_s UBIGINT,
                    pid UINTEGER,
                    tid UINTEGER,
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

    pub fn sample(&mut self) -> Result<()> {
        let mut ts: timespec = unsafe { MaybeUninit::<timespec>::zeroed().assume_init() };
        unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
        let (keys, values) = self.read_samples(&ts);
        for (gran, stat) in keys.into_iter().zip(values.into_iter()) {
            println!(
                "{} {} {} {} {} {} {} {} {} {:?}",
                stat.ts_s,
                gran.tgid_pid >> 32,
                gran.tgid_pid & ((1u64 << 32) - 1),
                String::from_utf8(gran.bri.s_id.into())?,
                gran.bri.i_rdev,
                gran.bri.i_ino,
                if gran.dir == 0 { 'R' } else { 'W' },
                stat.total_time,
                stat.total_requests,
                stat.hist,
            );
        }

        let mut to_update = Vec::new();
        Self::read_batch::<to_update_key, u8>(
            self.skel.maps.to_update.as_fd().as_raw_fd(),
            &mut to_update,
            &mut Vec::new(),
        );
        for key in to_update {
            println!("{} {}", key.granularity.tgid_pid >> 32, key.ts);
        }
        Ok(())
    }
}
