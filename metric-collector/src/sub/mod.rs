use anyhow::{bail, Result};
use libbpf_rs::{
    libbpf_sys::{self, __u32},
    MapCore, MapFlags, MapHandle, MapMut,
};
use libc::timespec;
use std::{
    ffi::c_void,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, RawFd},
};

pub mod futex;
pub mod iowait;
pub mod muxio;
pub mod net;
pub mod taskstats;
pub mod vfs;

mod consts {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(clippy::const_static_lifetime)]
    #![allow(clippy::unreadable_literal)]
    #![allow(clippy::cyclomatic_complexity)]
    #![allow(clippy::useless_transmute)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/include/consts.bindings.rs"
    ));
}

pub const SAMPLES: u64 = consts::SAMPLES as u64;
pub const MAX_ENTRIES: u64 = consts::MAX_ENTRIES as u64;
pub const BATCH_SIZE: usize = 8192;

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn samples_init<K, V>(samples: &MapMut) -> Result<()> {
    for i in 0..SAMPLES {
        let mapfd = unsafe {
            libbpf_sys::bpf_map_create(
                libbpf_sys::BPF_MAP_TYPE_HASH,
                std::ptr::null(),
                size_of::<K>() as u32,
                size_of::<V>() as u32,
                MAX_ENTRIES as u32,
                std::ptr::null(),
            )
        };
        if mapfd < 0 {
            bail!("Failed to create map for {i}: {mapfd}")
        }

        samples.update(
            &(i as u64).to_ne_bytes(),
            &mapfd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        unsafe { libc::close(mapfd) };
    }
    Ok(())
}

pub fn replace_samples<K, V>(samples: &MapMut, ts: &timespec) -> (Vec<K>, Vec<V>) {
    let curr = ts.tv_sec as u64;
    let mut keys: Vec<K> = Vec::new();
    let mut values: Vec<V> = Vec::new();
    for ts in (curr - (SAMPLES - 1))..curr {
        let outer = ts % SAMPLES;

        let inner_id = samples.lookup(&(outer as u64).to_ne_bytes(), MapFlags::ANY);

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
        let count = read_batch(mh.as_fd().as_raw_fd(), &mut keys, &mut values);

        if count == 0 {
            continue;
        }

        let mapfd = unsafe {
            libbpf_sys::bpf_map_create(
                libbpf_sys::BPF_MAP_TYPE_HASH,
                std::ptr::null(),
                size_of::<K>() as u32,
                size_of::<V>() as u32,
                MAX_ENTRIES as u32,
                std::ptr::null(),
            )
        };
        if mapfd < 0 {
            println!("Failed to create map for {outer}: {mapfd}");
            continue;
        }

        let res = samples.update(
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
