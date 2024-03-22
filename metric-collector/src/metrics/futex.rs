use std::{cell::RefCell, rc::Rc};

use super::{Collect, ToCsv};
use crate::execute::programs::futex::FutexProgram;

pub struct Futex {
    futex_program: Rc<RefCell<FutexProgram>>,
    tid: usize,
}

impl Futex {
    pub fn new(futex_program: Rc<RefCell<FutexProgram>>, tid: usize, data_directory: &str) -> Self {
        Self { futex_program, tid }
    }
}

impl Collect for Futex {
    fn sample(&self) -> eyre::Result<Box<dyn super::ToCsv>> {
        let events = self.futex_program.borrow_mut().poll_events(self.tid);
        println!("{:?}", events);
        Ok(Box::new(FutexSample::from(String::from(""))))
    }

    fn store(&mut self, sample: Box<dyn ToCsv>) -> eyre::Result<()> {
        Ok(())
    }
}

struct FutexSample {
    futex_wait: String,
}

impl From<String> for FutexSample {
    fn from(value: String) -> Self {
        Self { futex_wait: value }
    }
}

impl ToCsv for FutexSample {
    fn csv_headers(&self) -> String {
        String::from("header1,header2\n")
    }

    fn to_csv_row(&self) -> (u128, String) {
        (0, self.futex_wait.clone())
    }
}
