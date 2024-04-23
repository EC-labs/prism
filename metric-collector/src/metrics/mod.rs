use eyre::Result;
use std::{
    error::Error,
    fmt::{self, Display},
};

pub mod futex;
pub mod iowait;
pub mod ipc;
pub mod scheduler;

pub trait Collect {
    fn sample(&mut self) -> Result<()>;

    fn store(&mut self) -> Result<()>;
}

pub trait ToCsv {
    fn to_csv_row(&self) -> String;

    fn csv_headers(&self) -> &'static str;
}

#[derive(Debug)]
struct MissingSample;

impl Display for MissingSample {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Missing sample")
    }
}

impl Error for MissingSample {}
