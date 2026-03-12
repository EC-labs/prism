use anyhow::{bail, Result};
use libbpf_rs::{
    libbpf_sys::{self, __u32},
    MapCore, MapFlags, MapHandle, MapMut,
};
use libc::timespec;
use log::error;
use std::{
    cmp::{Eq, Ord, Ordering, PartialOrd},
    collections::HashMap,
    ffi::c_void,
    fmt::Debug,
    hash::Hash,
    mem::MaybeUninit,
    ops::{Add, Sub},
    os::fd::{AsFd, AsRawFd, RawFd},
    time::Duration,
};

pub mod aio;
pub mod discovery;
pub mod futex;
pub mod iowait;
pub mod mux;
// pub mod muxio;
pub mod net;
pub mod process_context;
pub mod taskstats;
pub mod vfs;

mod consts {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(clippy::redundant_static_lifetimes)]
    #![allow(clippy::unreadable_literal)]
    #![allow(clippy::cognitive_complexity)]
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

trait BPFKeyDefault {
    fn key_hash<H: std::hash::Hasher>(&self, state: &mut H)
    where
        Self: Sized,
    {
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        };
        bytes.hash(state);
    }

    fn key_eq(&self, other: &Self) -> bool
    where
        Self: Sized,
    {
        let self_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        };
        let other_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                other as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        };

        self_bytes == other_bytes
    }
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

        samples.update(&i.to_ne_bytes(), &mapfd.to_ne_bytes(), MapFlags::ANY)?;
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

        let inner_id = samples.lookup(&outer.to_ne_bytes(), MapFlags::ANY);

        let inner_id = match inner_id {
            Ok(Some(inner_vec)) => {
                let mut inner: [u8; 4] = [0; 4];
                inner.copy_from_slice(&inner_vec);
                u32::from_ne_bytes(inner)
            }
            e => {
                error!("Failed to get map inner_id for ts `{ts}`: {e:?}");
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
            error!("Failed to create map for {outer}: {mapfd}");
            panic!();
        }

        let res = samples.update(&outer.to_ne_bytes(), &mapfd.to_ne_bytes(), MapFlags::ANY);
        match res {
            Ok(()) => {}
            Err(e) => {
                error!("Failed to update map {}: {e}", outer);
                panic!();
            }
        }
        unsafe { libc::close(mapfd) };
    }
    (keys, values)
}

fn read_batch<K, V>(map_fd: RawFd, keys: &mut Vec<K>, values: &mut Vec<V>) -> usize {
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
                &mut in_batch as *mut u64 as *mut libc::c_void,
                &mut out_batch as *mut u64 as *mut libc::c_void,
                std::mem::transmute::<*mut K, *mut c_void>(keys[batch_start..].as_mut_ptr()),
                std::mem::transmute::<*mut V, *mut c_void>(values[batch_start..].as_mut_ptr()),
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

trait UpdateEnd {
    fn update_end(&self, curr: TimeSinceBoot) -> TimeSinceBoot;
}

trait AggregateSum {
    fn aggregate_sum(&mut self, other: &Self);
}

trait BootSampleSecond {
    fn boot_sample_second(&self) -> TimeSinceBoot;
}

trait IncrementStart {
    fn increment_start(&self) -> TimeSinceBoot;
}

trait LastSample {
    fn last_sample(&self) -> TimeSinceBoot;
}

impl<ToUpdateValue: LastSample> UpdateEnd for ToUpdateValue {
    fn update_end(&self, curr: TimeSinceBoot) -> TimeSinceBoot {
        self.last_sample().min(curr)
    }
}

/// This function pushes additional records into `keys` and `values` based on the
/// `entries`. `entries` is expected to be populated with `Inflight` records or
/// `ToUpdate` records.
fn create_increment_records<'a, IncrementKey, IncrementValue, I, Granularity, Stats, UpdatedKey>(
    entries: I,
    now: &timespec,
    keys: &mut Vec<Granularity>,
    values: &mut Vec<Stats>,
    updated: &mut HashMap<UpdatedKey, TimeSinceBoot>,
) where
    I: Iterator<Item = (&'a IncrementKey, &'a IncrementValue)>,
    UpdatedKey: Hash + Eq,
    UpdatedKey: From<(&'a IncrementKey, &'a IncrementValue)>,
    UpdatedKey: IncrementStart,
    Granularity: From<(&'a IncrementKey, &'a IncrementValue)>,
    Stats: From<(TimeSinceBoot, Duration)>,
    IncrementValue: 'a + UpdateEnd,
    IncrementKey: 'a,
{
    let upper_sample = TimeSinceBoot::from_secs(now.tv_sec as u64);
    for (key, value) in entries {
        let updated_key = UpdatedKey::from((key, value));
        // This can either be the start time of the Inflight/ToUpdate record or the last registered
        // sample. The latter is rounded to the second, whereas the former might not be.
        let last_registered_sample = *updated
            .get(&updated_key)
            .unwrap_or(&updated_key.increment_start());
        let start = TimeSinceBoot::from_secs(last_registered_sample.as_secs() + 1);

        // If `entries` refers to Inflight records, the upper limit should be the current sampling
        // period passed as an argument. If the values in entries refer to ToUpdate entries,
        // then the upper limit should be the smallest value between the current sample and the
        // record's `last_sample`. `last_sample` is guaranteed to be at a second boundary relative
        // to the time since boot.
        //
        // The reason why the minimum between upper_sample and last_sample is selected is because
        // we want to make sure that we are not processing events ahead of the current sample
        // window. I.e. we want to make sure that the events we are processing are between the last
        // time the subsystem's `sample` method is called, and the current execution of the same
        // subsystem's `sample method`. This is important to ensure that the records can be
        // merged between the values in the `samples_map` and the records extracted from the
        // `to_update_map` / `pending_map` maps.
        //
        // Conversely, if update_end returned a value greater than upper_sample, then we would be
        // processing requests relative to time samples ahead of upper_sample. Instead, we only
        // want to process the records that are missing from before `upper_sample`.
        let end = value.update_end(upper_sample);

        if end < start {
            continue;
        }

        assert!(end > last_registered_sample);

        for since_boot in (start.as_secs()..=end.as_secs()).map(|s| TimeSinceBoot::from_secs(s)) {
            // sample is used to calculate how much time should be accounted for sample - 1. This
            // is our convention considering we account the total time waiting between
            // [sample-1; sample] to `sample - 1`
            let increment = Duration::from_secs(1).min(since_boot - last_registered_sample);
            let boot_sample = since_boot - Duration::from_secs(1);
            keys.push(Granularity::from((key, value)));
            values.push(Stats::from((boot_sample, increment)));
        }

        updated.insert(updated_key, end);
    }
}

fn aggregate_records<I, Granularity, Stats>(entries: I) -> Vec<(Granularity, Stats)>
where
    I: Iterator<Item = (Granularity, Stats)>,
    Granularity: Hash + Eq,
    Stats: AggregateSum,
    Stats: BootSampleSecond,
{
    let mut res = HashMap::new();
    for (gran, st) in entries {
        res.entry((st.boot_sample_second(), gran))
            .and_modify(|v: &mut Stats| {
                v.aggregate_sum(&st);
            })
            .or_insert(st);
    }

    let mut res = res
        .into_iter()
        .map(|((_, gr), st)| (gr, st))
        .collect::<Vec<(Granularity, Stats)>>();
    res.sort_by(|a, b| a.1.boot_sample_second().cmp(&b.1.boot_sample_second()));
    res
}

fn remove_updated_entries<I, UpdatedKey, ToUpdateKey, ToUpdateValue>(
    entries: I,
    updated: &mut HashMap<UpdatedKey, TimeSinceBoot>,
    to_update_map: &MapMut,
) where
    I: Iterator<Item = (ToUpdateKey, ToUpdateValue)>,
    UpdatedKey: for<'a> From<(&'a ToUpdateKey, &'a ToUpdateValue)> + Hash + Eq,
    ToUpdateKey: Debug + Sized,
    ToUpdateValue: LastSample,
{
    for (key, value) in entries {
        let update_key = UpdatedKey::from((&key, &value));
        let Some(last_registered_sample) = updated.get(&update_key) else {
            continue;
        };

        assert!(*last_registered_sample <= value.last_sample());
        if *last_registered_sample < value.last_sample() {
            continue;
        }

        // The previous assertion and if statement have ensured that the current ToUpdate record
        // can be removed because it is equal to the value that is in the updated map.
        updated.remove(&update_key);
        let key_ptr = &key as *const ToUpdateKey as *const u8;
        let key_len = std::mem::size_of::<ToUpdateKey>();
        let key_slice = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
        if let Err(e) = to_update_map.delete(&key_slice) {
            error!("Could not remove key `{key:?}: {e}`");
            panic!();
        }
    }
}

/// Stores the elapsed nanoseconds since Boot
#[derive(Hash, PartialEq, Eq, Debug, Copy, Clone)]
struct TimeSinceBoot(u64);
impl TimeSinceBoot {
    fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    fn from_secs(secs: u64) -> Self {
        Self(secs * 1_000_000_000)
    }

    fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    fn as_nanos(&self) -> u64 {
        self.0
    }
}

impl Sub<Duration> for TimeSinceBoot {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs.as_nanos() as u64)
    }
}

impl Sub<TimeSinceBoot> for TimeSinceBoot {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        Duration::from_nanos(self.as_nanos() - rhs.as_nanos())
    }
}

impl Add<Duration> for TimeSinceBoot {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.as_nanos() as u64)
    }
}

impl Ord for TimeSinceBoot {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for TimeSinceBoot {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn process_samples<
    Granularity,
    Stats,
    InflightKey,
    InflightValue,
    ToUpdateKey,
    ToUpdateValue,
    UpdatedKey,
>(
    ts: &timespec,
    samples_map: &MapMut,
    inflight_map: &MapMut,
    to_update_map: &MapMut,
    updated: &mut HashMap<UpdatedKey, TimeSinceBoot>,
) -> Vec<(Granularity, Stats)>
where
    Granularity: Hash + Eq,
    Granularity: for<'a> From<(&'a InflightKey, &'a InflightValue)>,
    Granularity: for<'a> From<(&'a ToUpdateKey, &'a ToUpdateValue)>,
    Stats: AggregateSum,
    Stats: BootSampleSecond,
    Stats: From<(TimeSinceBoot, Duration)>,
    UpdatedKey: Hash + Eq,
    UpdatedKey: for<'a> From<(&'a InflightKey, &'a InflightValue)>,
    UpdatedKey: for<'a> From<(&'a ToUpdateKey, &'a ToUpdateValue)>,
    UpdatedKey: IncrementStart,
    ToUpdateValue: LastSample,
    ToUpdateKey: Debug,
    ToUpdateValue: UpdateEnd,
    InflightValue: UpdateEnd,
{
    let (mut keys, mut values) = replace_samples::<Granularity, Stats>(samples_map, &ts);

    let (mut pending_keys, mut pending_values) = (Vec::new(), Vec::new());
    read_batch::<InflightKey, InflightValue>(
        inflight_map.as_fd().as_raw_fd(),
        &mut pending_keys,
        &mut pending_values,
    );
    create_increment_records(
        pending_keys.iter().zip(pending_values.iter()),
        ts,
        &mut keys,
        &mut values,
        updated,
    );

    let (mut to_update_keys, mut to_update_values) = (Vec::new(), Vec::new());
    read_batch::<ToUpdateKey, ToUpdateValue>(
        to_update_map.as_fd().as_raw_fd(),
        &mut to_update_keys,
        &mut to_update_values,
    );
    create_increment_records(
        to_update_keys.iter().zip(to_update_values.iter()),
        ts,
        &mut keys,
        &mut values,
        updated,
    );

    remove_updated_entries(
        to_update_keys.into_iter().zip(to_update_values.into_iter()),
        updated,
        to_update_map,
    );

    return aggregate_records(keys.into_iter().zip(values.into_iter()));
}
