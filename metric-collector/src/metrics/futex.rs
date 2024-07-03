use eyre::Result;
use lru::LruCache;
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    fs::{self, File},
    io::prelude::*,
    num::NonZeroUsize,
    path::Path,
    rc::Rc,
};

use super::{Collect, ToCsv};
use crate::execute::{
    boot_to_epoch,
    programs::futex::{FutexEvent, FutexProgram},
};

#[derive(Debug)]
struct UnwritableEvent;

impl fmt::Display for UnwritableEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", "Event is not writable")
    }
}

impl Error for UnwritableEvent {}

#[derive(PartialEq, Eq, Hash, Clone)]
struct FutexKey {
    root_pid: usize,
    uaddr: Rc<str>,
}

#[derive(Clone)]
struct WaitStat {
    accumulated_wait: u64,
    count: usize,
}

enum SnapshotStat {
    Wait(WaitStat),
    Wake { count: usize },
}

pub struct Futex {
    tid: usize,
    futex_program: Rc<RefCell<FutexProgram>>,
    futex_stats_map: HashMap<FutexKey, WaitStat>,
    snapshots: HashMap<FutexKey, VecDeque<(u64, SnapshotStat)>>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
}

impl Futex {
    pub fn new(
        futex_program: Rc<RefCell<FutexProgram>>,
        tid: usize,
        root_directory: Rc<str>,
        target_subdirectory: &str,
    ) -> Self {
        Self {
            tid,
            futex_program,
            futex_stats_map: HashMap::new(),
            snapshots: HashMap::new(),
            data_files: LruCache::new(NonZeroUsize::new(4).unwrap()),
            target_subdirectory: format!("{}/{}/futex", root_directory, target_subdirectory),
        }
    }

    fn get_or_create_file<'a>(
        data_files: &'a mut LruCache<String, File>,
        filepath: &Path,
        headers: &str,
    ) -> Result<&'a File> {
        let file = data_files.get(filepath.to_str().unwrap());
        if let None = file {
            let file = File::options().append(true).open(filepath);
            let file = match file {
                Err(_) => {
                    fs::create_dir_all(filepath.parent().unwrap())?;
                    let mut file = File::options().append(true).create(true).open(filepath)?;
                    file.write_all(headers.as_bytes())?;
                    file
                }
                Ok(file) => file,
            };
            data_files.put(filepath.to_str().unwrap().into(), file);
        }

        let file = data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }
}

impl Collect for Futex {
    fn sample(&mut self) -> Result<()> {
        let events = self
            .futex_program
            .borrow_mut()
            .take_futex_events(self.tid)?;

        for event in events {
            match event {
                FutexEvent::Wait {
                    root_pid,
                    uaddr,
                    sample_instant_ns,
                    total_interval_wait_ns,
                    count,
                    ..
                } => {
                    let futex = FutexKey { root_pid, uaddr };
                    let stat = self
                        .futex_stats_map
                        .entry(futex.clone())
                        .or_insert(WaitStat {
                            accumulated_wait: 0,
                            count: 0,
                        });
                    *stat = WaitStat {
                        accumulated_wait: stat.accumulated_wait + total_interval_wait_ns,
                        count,
                    };
                    let snapshot = self
                        .snapshots
                        .entry(futex)
                        .or_insert_with(|| VecDeque::new());
                    snapshot.push_back((sample_instant_ns, SnapshotStat::Wait(stat.clone())));
                }
                FutexEvent::Wake {
                    root_pid,
                    uaddr,
                    sample_instant_ns,
                    count,
                    ..
                } => {
                    let futex = FutexKey { root_pid, uaddr };
                    let snapshot = self
                        .snapshots
                        .entry(futex)
                        .or_insert_with(|| VecDeque::new());
                    snapshot.push_back((sample_instant_ns, SnapshotStat::Wake { count }))
                }
            }
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        if self.snapshots.len() == 0 {
            return Ok(());
        }

        for (futex, snapshots) in self.snapshots.iter_mut() {
            while let Some((sample_instant_ns, snapshot)) = snapshots.pop_front() {
                let sample_epoch_ms = boot_to_epoch(sample_instant_ns as u128) / 1_000_000;
                let (sample, filename): (Box<dyn ToCsv>, String) = match snapshot {
                    SnapshotStat::Wait(wait) => {
                        let sample = Box::new(FutexWaitSample {
                            epoch_ms: sample_epoch_ms,
                            cumulative_futex_wait: wait.accumulated_wait,
                            count: wait.count,
                        });
                        let filename = format!(
                            "{}/wait/{}/{}-{}",
                            self.target_subdirectory,
                            (sample_epoch_ms / (1000 * 60)) * 60,
                            futex.root_pid,
                            futex.uaddr,
                        );
                        (sample, filename)
                    }
                    SnapshotStat::Wake { count } => {
                        let sample = Box::new(FutexWakeSample {
                            epoch_ms: boot_to_epoch(sample_instant_ns as u128),
                            count,
                        });
                        let filename = format!(
                            "{}/wake/{}/{}-{}",
                            self.target_subdirectory,
                            (sample_epoch_ms / (1000 * 60)) * 60,
                            futex.root_pid,
                            futex.uaddr,
                        );
                        (sample, filename)
                    }
                };
                let mut file = Self::get_or_create_file(
                    &mut self.data_files,
                    Path::new(&filename),
                    sample.csv_headers(),
                )?;
                file.write_all(sample.to_csv_row().as_bytes())?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct FutexWaitSample {
    epoch_ms: u128,
    cumulative_futex_wait: u64,
    count: usize,
}

impl ToCsv for FutexWaitSample {
    fn csv_headers(&self) -> &'static str {
        "epoch_ms,futex_wait_ns,futex_count\n"
    }

    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{}\n",
            self.epoch_ms, self.cumulative_futex_wait, self.count
        )
    }
}

#[derive(Debug)]
struct FutexWakeSample {
    epoch_ms: u128,
    count: usize,
}

impl ToCsv for FutexWakeSample {
    fn csv_headers(&self) -> &'static str {
        "epoch_ms,futex_count\n"
    }

    fn to_csv_row(&self) -> String {
        format!("{},{}\n", self.epoch_ms, self.count)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn tmp() {}
}
