use eyre::Result;
use nix::time::{self, ClockId};
use std::{
    cell::RefCell,
    fs::{self, File},
    io::prelude::*,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{Collect, ToCsv};
use crate::execute::programs::futex::{FutexEvent, FutexProgram};

pub struct Futex {
    futex_program: Rc<RefCell<FutexProgram>>,
    tid: usize,
    sum_futex_wait_time: u128,
    futex_wait_start: Option<u128>,
    boot_epoch_ns: u128,
    events: Option<Vec<FutexEvent>>,
    day_epoch: Option<u128>,
    data_file: Option<File>,
    data_directory: String,
}

impl Futex {
    pub fn new(futex_program: Rc<RefCell<FutexProgram>>, tid: usize, data_directory: &str) -> Self {
        let ns_since_boot =
            Duration::from(time::clock_gettime(ClockId::CLOCK_BOOTTIME).unwrap()).as_nanos();
        let start = SystemTime::now();
        let ns_since_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();
        Self {
            futex_program,
            tid,
            sum_futex_wait_time: 0,
            futex_wait_start: None,
            boot_epoch_ns: ns_since_epoch - ns_since_boot,
            events: None,
            day_epoch: None,
            data_file: None,
            data_directory: format!("{}/futex", data_directory),
        }
    }
}

impl Collect for Futex {
    fn sample(&mut self) -> Result<Box<dyn super::ToCsv>> {
        let time_since_boot =
            Duration::from(time::clock_gettime(ClockId::CLOCK_BOOTTIME)?).as_nanos();
        self.events = Some(self.futex_program.borrow_mut().poll_events(self.tid)?);
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

        let sample = FutexSample {
            epoch_ms: ms_epoch,
            cumulative_futex_wait: self.sum_futex_wait_time + time_since_wait_start,
        };
        Ok(Box::new(sample))
    }

    fn store(&mut self, sample: Box<dyn ToCsv>) -> Result<()> {
        let (epoch, row) = sample.to_csv_row();
        let day_epoch = (epoch / (1000 * 60 * 60 * 24)) * (1000 * 60 * 60 * 24);

        if Some(day_epoch) != self.day_epoch {
            let filepath = format!("{}/{}.csv", self.data_directory, day_epoch);
            fs::create_dir_all(&self.data_directory)?;
            self.day_epoch = Some(day_epoch);
            let file = File::options().append(true).open(&filepath);
            let file = match file {
                Err(_) => {
                    let mut file = File::options().append(true).create(true).open(&filepath)?;
                    file.write_all(sample.csv_headers().as_bytes())?;
                    file
                }
                Ok(file) => file,
            };
            self.data_file = Some(file);
        }
        self.data_file.as_ref().unwrap().write_all(row.as_bytes())?;

        Ok(())
    }
}

#[derive(Debug)]
struct FutexSample {
    epoch_ms: u128,
    cumulative_futex_wait: u128,
}

impl ToCsv for FutexSample {
    fn csv_headers(&self) -> String {
        String::from("epoch_ms,futex_wait\n")
    }

    fn to_csv_row(&self) -> (u128, String) {
        (
            self.epoch_ms,
            format!("{},{}\n", self.epoch_ms, self.cumulative_futex_wait),
        )
    }
}
