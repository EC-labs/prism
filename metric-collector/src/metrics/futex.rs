use eyre::Result;
use nix::time::{self, ClockId};
use std::{cell::RefCell, rc::Rc, time::Duration};

use super::{Collect, ToCsv};
use crate::execute::programs::futex::{FutexProgram, WaitEvent};

pub struct Futex {
    futex_program: Rc<RefCell<FutexProgram>>,
    tid: usize,
    sum_futex_wait_time: u128,
    futex_wait_start: Option<u128>,
}

impl Futex {
    pub fn new(futex_program: Rc<RefCell<FutexProgram>>, tid: usize, data_directory: &str) -> Self {
        Self {
            futex_program,
            tid,
            sum_futex_wait_time: 0,
            futex_wait_start: None,
        }
    }
}

impl Collect for Futex {
    fn sample(&mut self) -> Result<Box<dyn super::ToCsv>> {
        let time_since_boot =
            Duration::from(time::clock_gettime(ClockId::CLOCK_BOOTTIME)?).as_nanos();
        let events = self.futex_program.borrow_mut().poll_events(self.tid)?;
        for event in events {
            match event {
                WaitEvent::Start { epoch, .. } => {
                    self.futex_wait_start = Some(epoch);
                }
                WaitEvent::Elapsed { elapsed, .. } => {
                    self.futex_wait_start = None;
                    self.sum_futex_wait_time += elapsed;
                }
            }
        }

        let time_since_wait_start = if let Some(wait_start) = self.futex_wait_start {
            time_since_boot - wait_start
        } else {
            0
        };

        let sample = FutexSample {
            cumulative_futex_wait: self.sum_futex_wait_time + time_since_wait_start,
        };
        println!("{:?}", sample);
        Ok(Box::new(sample))
    }

    fn store(&mut self, sample: Box<dyn ToCsv>) -> eyre::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct FutexSample {
    cumulative_futex_wait: u128,
}

impl ToCsv for FutexSample {
    fn csv_headers(&self) -> String {
        String::from("header1,header2\n")
    }

    fn to_csv_row(&self) -> (u128, String) {
        (0, format!("{}", self.cumulative_futex_wait))
    }
}
