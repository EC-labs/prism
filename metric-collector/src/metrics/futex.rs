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

#[derive(Clone, Debug, PartialEq, Eq)]
struct WaitStat {
    accumulated_wait: u64,
    count: usize,
}

#[derive(Debug, PartialEq, Eq)]
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
                            "{}/wait/{}/{}-{}.csv",
                            self.target_subdirectory,
                            (sample_epoch_ms / (1000 * 60)) * 60,
                            futex.root_pid,
                            futex.uaddr,
                        );
                        (sample, filename)
                    }
                    SnapshotStat::Wake { count } => {
                        let sample = Box::new(FutexWakeSample {
                            epoch_ms: sample_epoch_ms,
                            count,
                        });
                        let filename = format!(
                            "{}/wake/{}/{}-{}.csv",
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

    use eyre::Result;
    use indoc::indoc;
    use std::{
        cell::RefCell,
        fs,
        fs::File,
        io::prelude::*,
        rc::Rc,
        sync::{Arc, Mutex},
    };
    use tempdir::TempDir;

    use super::Futex;
    use crate::metrics::{
        futex::{SnapshotStat, WaitStat},
        Collect,
    };
    use crate::{
        execute::programs::{self, futex::FutexProgram},
        metrics::futex::FutexKey,
    };

    fn new_custom_futex() -> (FutexProgram, File) {
        let (rx, tx) = programs::pipe();
        let program = FutexProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap();
        (program, tx)
    }

    fn write_and_poll(program: &mut FutexProgram, tx: &mut File, data: &[u8]) -> Result<()> {
        tx.write(data)?;
        while let Ok(0) = program.poll_events() {}
        Ok(())
    }

    #[test]
    fn single_snapshot_wait() -> Result<()> {
        let bpf_content = indoc! {"
            HEADER 

            => start map statistics
            @wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (847638877, 4)
            SampleInstant  	65384570945103
            => end map statistics
        "};
        let (mut program, mut tx) = new_custom_futex();
        write_and_poll(&mut program, &mut tx, bpf_content.as_bytes())?;

        let root_directory = TempDir::new("")?;
        let mut futex = Futex::new(
            Rc::new(RefCell::new(program)),
            8955,
            Rc::from(root_directory.path().to_str().unwrap()),
            &format!("thread/{}/{}", 8877, 8955),
        );

        futex.sample()?;
        let snapshots = futex
            .snapshots
            .get(&FutexKey {
                root_pid: 8877,
                uaddr: Rc::from("0x7c3dd4f85fb0"),
            })
            .unwrap();
        assert_eq!(
            snapshots[0],
            (
                65384570945103,
                SnapshotStat::Wait(WaitStat {
                    accumulated_wait: 847638877,
                    count: 4
                })
            )
        );

        futex.store()?;
        let content = fs::read_to_string(format!(
            "{}/thread/8877/8955/futex/wait/65340/8877-0x7c3dd4f85fb0.csv",
            root_directory.path().to_str().unwrap()
        ))?;
        assert_eq!(
            content,
            indoc! {"
                epoch_ms,futex_wait_ns,futex_count
                65384570,847638877,4
            "}
        );

        Ok(())
    }

    #[test]
    fn single_snapshot_wake() -> Result<()> {
        let bpf_content = indoc! {"
            HEADER 

            => start map statistics
            @wake[8986, 8877, 0x7c3cfc00560c]: 1
            SampleInstant  	65384570945103
            => end map statistics
        "};
        let (pid, tid, address): (usize, usize, Rc<str>) = (8877, 8986, Rc::from("0x7c3cfc00560c"));
        let (mut program, mut tx) = new_custom_futex();
        write_and_poll(&mut program, &mut tx, bpf_content.as_bytes())?;

        let root_directory = TempDir::new("")?;
        let mut futex = Futex::new(
            Rc::new(RefCell::new(program)),
            tid,
            Rc::from(root_directory.path().to_str().unwrap()),
            &format!("thread/{}/{}", pid, tid),
        );

        futex.sample()?;
        let snapshots = futex
            .snapshots
            .get(&FutexKey {
                root_pid: pid,
                uaddr: address.clone(),
            })
            .unwrap();
        assert_eq!(
            snapshots[0],
            (65384570945103, SnapshotStat::Wake { count: 1 })
        );

        futex.store()?;
        let content = fs::read_to_string(format!(
            "{}/thread/{}/{}/futex/wake/65340/{}-{}.csv",
            root_directory.path().to_str().unwrap(),
            pid,
            tid,
            pid,
            address.clone(),
        ))?;
        assert_eq!(
            content,
            indoc! {"
                epoch_ms,futex_count
                65384570,1
            "}
        );

        Ok(())
    }

    #[test]
    fn double_snapshot_wait() -> Result<()> {
        let bpf_content = indoc! {"
            HEADER 

            => start map statistics
            @wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (847638877, 4)
            SampleInstant  	65384570945103
            => end map statistics

            => start map statistics
            @wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (847638877, 4)
            SampleInstant  	65385570945103
            => end map statistics
        "};
        let (pid, tid, address): (usize, usize, Rc<str>) = (8877, 8955, Rc::from("0x7c3dd4f85fb0"));
        let (mut program, mut tx) = new_custom_futex();
        write_and_poll(&mut program, &mut tx, bpf_content.as_bytes())?;

        let root_directory = TempDir::new("")?;
        let mut futex = Futex::new(
            Rc::new(RefCell::new(program)),
            tid,
            Rc::from(root_directory.path().to_str().unwrap()),
            &format!("thread/{}/{}", pid, tid),
        );

        futex.sample()?;
        let snapshots = futex
            .snapshots
            .get(&FutexKey {
                root_pid: pid,
                uaddr: address.clone(),
            })
            .unwrap();
        assert_eq!(
            snapshots[0],
            (
                65384570945103,
                SnapshotStat::Wait(WaitStat {
                    accumulated_wait: 847638877,
                    count: 4
                })
            )
        );
        assert_eq!(
            snapshots[1],
            (
                65385570945103,
                SnapshotStat::Wait(WaitStat {
                    accumulated_wait: 847638877 * 2,
                    count: 4
                })
            )
        );

        futex.store()?;
        let content = fs::read_to_string(format!(
            "{}/thread/{}/{}/futex/wait/65340/{}-{}.csv",
            root_directory.path().to_str().unwrap(),
            pid,
            tid,
            pid,
            address.clone(),
        ))?;
        assert_eq!(
            content,
            indoc! {"
                epoch_ms,futex_wait_ns,futex_count
                65384570,847638877,4
                65385570,1695277754,4
            "}
        );

        Ok(())
    }

    #[test]
    fn double_snapshot_wake() -> Result<()> {
        let bpf_content = indoc! {"
            HEADER 

            => start map statistics
            @wake[8986, 8877, 0x7c3cfc00560c]: 1
            SampleInstant  	65384570945103
            => end map statistics

            => start map statistics
            @wake[8986, 8877, 0x7c3cfc00560c]: 1
            SampleInstant  	65385570945103
            => end map statistics
        "};
        let (pid, tid, address): (usize, usize, Rc<str>) = (8877, 8986, Rc::from("0x7c3cfc00560c"));
        let (mut program, mut tx) = new_custom_futex();
        write_and_poll(&mut program, &mut tx, bpf_content.as_bytes())?;

        let root_directory = TempDir::new("")?;
        let mut futex = Futex::new(
            Rc::new(RefCell::new(program)),
            tid,
            Rc::from(root_directory.path().to_str().unwrap()),
            &format!("thread/{}/{}", pid, tid),
        );

        futex.sample()?;
        let snapshots = futex
            .snapshots
            .get(&FutexKey {
                root_pid: pid,
                uaddr: address.clone(),
            })
            .unwrap();
        assert_eq!(
            snapshots[0],
            (65384570945103, SnapshotStat::Wake { count: 1 })
        );
        assert_eq!(
            snapshots[1],
            (65385570945103, SnapshotStat::Wake { count: 1 })
        );

        futex.store()?;
        let content = fs::read_to_string(format!(
            "{}/thread/{}/{}/futex/wake/65340/{}-{}.csv",
            root_directory.path().to_str().unwrap(),
            pid,
            tid,
            pid,
            address.clone(),
        ))?;
        assert_eq!(
            content,
            indoc! {"
                epoch_ms,futex_count
                65384570,1
                65385570,1
            "}
        );

        Ok(())
    }

    #[test]
    fn single_wait_and_wake() -> Result<()> {
        let bpf_content = indoc! {"
            HEADER 

            => start map statistics
            @wake[8955, 8877, 0x7c3cfc00560c]: 1
            @wait_elapsed[8955, 8877, 0x7c3cfc00560c]: (847638877, 4)
            SampleInstant  	65384570945103
            => end map statistics
        "};
        let (pid, tid, address): (usize, usize, Rc<str>) = (8877, 8955, Rc::from("0x7c3cfc00560c"));
        let (mut program, mut tx) = new_custom_futex();
        write_and_poll(&mut program, &mut tx, bpf_content.as_bytes())?;

        let root_directory = TempDir::new("")?;
        let mut futex = Futex::new(
            Rc::new(RefCell::new(program)),
            tid,
            Rc::from(root_directory.path().to_str().unwrap()),
            &format!("thread/{}/{}", pid, tid),
        );

        futex.sample()?;
        let snapshots = futex
            .snapshots
            .get(&FutexKey {
                root_pid: pid,
                uaddr: address.clone(),
            })
            .unwrap();
        println!("{:?}", snapshots);
        assert!(snapshots.contains(&(65384570945103, SnapshotStat::Wake { count: 1 })));
        assert!(snapshots.contains(&(
            65384570945103,
            SnapshotStat::Wait(WaitStat {
                accumulated_wait: 847638877,
                count: 4
            })
        )));

        futex.store()?;
        let content = fs::read_to_string(format!(
            "{}/thread/{}/{}/futex/wake/65340/{}-{}.csv",
            root_directory.path().to_str().unwrap(),
            pid,
            tid,
            pid,
            address.clone(),
        ))?;
        assert_eq!(
            content,
            indoc! {"
                epoch_ms,futex_count
                65384570,1
            "}
        );

        let content = fs::read_to_string(format!(
            "{}/thread/{}/{}/futex/wait/65340/{}-{}.csv",
            root_directory.path().to_str().unwrap(),
            pid,
            tid,
            pid,
            address.clone(),
        ))?;
        assert_eq!(
            content,
            indoc! {"
                epoch_ms,futex_wait_ns,futex_count
                65384570,847638877,4
            "}
        );

        Ok(())
    }
}
