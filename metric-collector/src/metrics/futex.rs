use eyre::Result;
use lru::LruCache;
use nix::time::{self, ClockId};
use std::{
    cell::RefCell,
    error::Error,
    fmt,
    fs::{self, File},
    io::prelude::*,
    num::NonZeroUsize,
    path::Path,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{Collect, MissingSample, ToCsv};
use crate::execute::programs::futex::{FutexEvent, FutexProgram, BOOT_EPOCH_NS};

#[derive(Debug)]
struct UnwritableEvent;

impl fmt::Display for UnwritableEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", "Event is not writable")
    }
}

impl Error for UnwritableEvent {}

pub struct Futex {
    futex_program: Rc<RefCell<FutexProgram>>,
    tid: usize,
    sum_futex_wait_time: u128,
    futex_wait_start: Option<u128>,
    futex_sample: Option<FutexSample>,
    events: Option<Vec<FutexEvent>>,
    current_start: Option<FutexEvent>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
    root_directory: Rc<str>,
}

impl Futex {
    pub fn new(
        futex_program: Rc<RefCell<FutexProgram>>,
        tid: usize,
        root_directory: Rc<str>,
        target_subdirectory: &str,
    ) -> Self {
        Self {
            futex_program,
            tid,
            sum_futex_wait_time: 0,
            futex_wait_start: None,
            futex_sample: None,
            events: None,
            current_start: None,
            data_files: LruCache::new(NonZeroUsize::new(4).unwrap()),
            target_subdirectory: format!("{}/{}/futex", root_directory, target_subdirectory),
            root_directory: root_directory.clone(),
        }
    }

    fn get_or_create_file(&mut self, filepath: &Path, headers: &str) -> Result<&File> {
        let file = self.data_files.get(filepath.to_str().unwrap());
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
            self.data_files.put(filepath.to_str().unwrap().into(), file);
        }

        let file = self.data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }

    fn store_sample(&mut self, sample: FutexSample) -> Result<()> {
        let epoch_ms = sample.epoch_ms;
        let row = sample.to_csv_row();
        let day_epoch = (epoch_ms / (1000 * 60 * 60 * 24)) * (1000 * 60 * 60 * 24);
        let filepath = format!("{}/{}.csv", self.target_subdirectory, day_epoch);
        let filepath = Path::new(&filepath);
        let mut file = self.get_or_create_file(filepath, &sample.csv_headers())?;
        file.write_all(row.as_bytes())?;

        Ok(())
    }

    fn write_event(&mut self, event: &FutexEvent) -> Result<()> {
        let filename = match event {
            FutexEvent::Elapsed { ns_since_boot, .. } => {
                let epoch_ns = *BOOT_EPOCH_NS.read().unwrap() + ns_since_boot;
                let epoch_minute_s = (epoch_ns / (1_000_000_000 * 60)) * 60;
                format!(
                    "{}/futex/wait/{}/{}.csv",
                    self.root_directory, self.tid, epoch_minute_s,
                )
            }
            FutexEvent::Wake {
                root_pid,
                uaddr,
                ns_since_boot,
                ..
            } => {
                let epoch_ns = *BOOT_EPOCH_NS.read().unwrap() + ns_since_boot;
                let epoch_minute_s = (epoch_ns / (1_000_000_000 * 60)) * 60;
                format!(
                    "{}/futex/wake/{}/{}/{}.csv",
                    self.root_directory, root_pid, uaddr, epoch_minute_s,
                )
            }
            _ => return Err(UnwritableEvent.into()),
        };

        let mut file = self.get_or_create_file(&Path::new(&filename), event.csv_headers())?;
        file.write_all(event.to_csv_row().as_bytes())?;
        Ok(())
    }

    fn store_events(&mut self) -> Result<()> {
        for event in self.events.take().unwrap() {
            match event {
                FutexEvent::Start { .. } => {
                    self.current_start = Some(event);
                }
                FutexEvent::Elapsed { ret, .. } => {
                    self.current_start.take().unwrap();
                    if ret == 0 {
                        self.write_event(&event)?;
                    }
                }
                FutexEvent::Wake { ret, .. } => {
                    if ret > 0 {
                        self.write_event(&event)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Collect for Futex {
    fn sample(&mut self) -> Result<()> {
        let time_since_boot =
            Duration::from(time::clock_gettime(ClockId::CLOCK_BOOTTIME)?).as_nanos();
        self.events = Some(self.futex_program.borrow_mut().get_events(self.tid)?);
        for event in self.events.as_ref().unwrap() {
            match event {
                FutexEvent::Start { ns_since_boot, .. } => {
                    self.futex_wait_start = Some(*ns_since_boot);
                }
                FutexEvent::Elapsed { ns_elapsed, .. } => {
                    self.futex_wait_start = None;
                    self.sum_futex_wait_time += ns_elapsed;
                }
                _ => {}
            }
        }

        let time_since_wait_start = if let Some(wait_start) = self.futex_wait_start {
            time_since_boot - wait_start
        } else {
            0
        };

        let start = SystemTime::now();
        let ms_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        self.futex_sample = Some(FutexSample {
            epoch_ms: ms_epoch,
            cumulative_futex_wait: self.sum_futex_wait_time + time_since_wait_start,
        });

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        if let None = self.futex_sample {
            return Err(MissingSample.into());
        }
        let sample = self.futex_sample.take().unwrap();

        self.store_sample(sample)?;
        self.store_events()
    }
}

#[derive(Debug)]
struct FutexSample {
    epoch_ms: u128,
    cumulative_futex_wait: u128,
}

impl ToCsv for FutexSample {
    fn csv_headers(&self) -> &'static str {
        "epoch_ms,futex_wait\n"
    }

    fn to_csv_row(&self) -> String {
        format!("{},{}\n", self.epoch_ms, self.cumulative_futex_wait)
    }
}
