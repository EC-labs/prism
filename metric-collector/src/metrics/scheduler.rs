use eyre::Result;
use lazy_static::lazy_static;
use nix::time::{self, ClockId};
use regex::Regex;
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::prelude::*;
use std::time::UNIX_EPOCH;
use std::{
    concat,
    time::{Duration, SystemTime},
};

use super::{Collect, MissingSample, ToCsv};

lazy_static! {
    static ref REGEX_PATTERN: Regex = Regex::new(concat!(
        r"se.sum_exec_runtime\s*:\s*(\d+\.\d+)\n(.*\n)*",
        r"sum_sleep_runtime\s*:\s*(\d+\.\d+)\n(.*\n)*",
        r"sum_block_runtime\s*:\s*(\d+\.\d+)\n(.*\n)*",
        r"wait_start\s*:\s*(\d+\.\d+)\n(.*\n)*",
        r"sleep_start\s*:\s*(\d+\.\d+)\n(.*\n)*",
        r"block_start\s*:\s*(\d+\.\d+)\n(.*\n)*",
        r"wait_sum\s*:\s*(\d+\.\d+)\n(.*\n)*",
        r"iowait_sum\s*:\s*(\d+\.\d+)\n(.*\n)*",
    ))
    .unwrap();
}

pub struct SchedStat {
    proc_file: String,
    data_directory: String,
    day_epoch: Option<u128>,
    data_file: Option<File>,
    sample: Option<SchedStatSample>,
}

#[derive(Debug)]
pub struct SchedStatSample {
    epoch: u128,
    runtime: u64,
    rq_time: u64,
    run_periods: u64,
}

impl From<Vec<&str>> for SchedStatSample {
    fn from(v: Vec<&str>) -> Self {
        let start = SystemTime::now();
        let epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        Self {
            epoch,
            runtime: v[0].parse().unwrap(),
            rq_time: v[1].parse().unwrap(),
            run_periods: v[2].parse().unwrap(),
        }
    }
}

impl ToCsv for SchedStatSample {
    fn csv_headers(&self) -> &'static str {
        "epoch_ms,runtime,rq_time,run_periods\n"
    }

    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{}\n",
            self.epoch, self.runtime, self.rq_time, self.run_periods
        )
    }
}

impl SchedStat {
    pub fn new(tid: usize, data_directory: &str) -> Self {
        Self {
            proc_file: format!("/proc/{}/schedstat", tid),
            data_directory: format!("{}/schedstat", data_directory),
            day_epoch: None,
            data_file: None,
            sample: None,
        }
    }
}

impl Collect for SchedStat {
    fn sample(&mut self) -> Result<()> {
        let contents = fs::read_to_string(&self.proc_file)?.replace("\n", "");
        let sample = SchedStatSample::from(contents.split(" ").collect::<Vec<&str>>());
        self.sample = Some(sample);
        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        if let None = self.sample {
            return Err(MissingSample.into());
        }

        let sample = self.sample.take().unwrap();
        let epoch_ms = sample.epoch;
        let row = sample.to_csv_row();
        let day_epoch = (epoch_ms / (1000 * 60 * 60 * 24)) * (1000 * 60 * 60 * 24);

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

pub struct Sched {
    proc_file: String,
    data_directory: String,
    data_file: Option<File>,
    day_epoch: Option<u128>,
    sample: Option<SchedSample>,
}

impl Sched {
    pub fn new(tid: usize, data_directory: &str) -> Self {
        Self {
            proc_file: format!("/proc/{tid}/sched"),
            data_directory: format!("{}/sched", data_directory),
            data_file: None,
            day_epoch: None,
            sample: None,
        }
    }
}

impl Collect for Sched {
    fn sample(&mut self) -> Result<()> {
        let contents = fs::read_to_string(&self.proc_file)?;
        let sample = SchedSample::from(contents.as_str());
        self.sample = Some(sample);
        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        if let None = self.sample {
            return Err(MissingSample.into());
        }

        let sample = self.sample.take().unwrap();
        let epoch_ms = sample.epoch;
        let row = sample.to_csv_row();
        let day_epoch = (epoch_ms / (1000 * 60 * 60 * 24)) * (1000 * 60 * 60 * 24);

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
pub struct SchedSample {
    epoch: u128,
    runtime: f64,
    rq_time: f64,
    sleep_time: f64,
    block_time: f64,
    iowait_time: f64,
}

impl From<&str> for SchedSample {
    fn from(content: &str) -> Self {
        let start = SystemTime::now();
        let epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        let captures = REGEX_PATTERN.captures(&content).unwrap();
        let time_since_boot = Duration::from(time::clock_gettime(ClockId::CLOCK_BOOTTIME).unwrap())
            .as_millis() as f64;

        let wait_start = &captures[7];
        let sleep_start = &captures[9];
        let block_start = &captures[11];

        let wait_since_start = if wait_start != "0.000000" {
            let wait_start: f64 = wait_start.parse().unwrap();
            f64::max(time_since_boot - wait_start, 0.0)
        } else {
            0.0
        };

        let sleep_since_start = if sleep_start != "0.000000" {
            let sleep_start: f64 = sleep_start.parse().unwrap();
            f64::max(time_since_boot - sleep_start, 0.0)
        } else {
            0.0
        };

        let block_since_start = if block_start != "0.000000" {
            let block_start: f64 = block_start.parse().unwrap();
            f64::max(time_since_boot - block_start, 0.0)
        } else {
            0.0
        };

        let sum_runtime: f64 = captures[1].parse().unwrap();
        let sum_sleep: f64 = captures[3].parse().unwrap();
        let sum_block: f64 = captures[5].parse().unwrap();
        let sum_wait: f64 = captures[13].parse().unwrap();
        let sum_iowait: f64 = captures[15].parse().unwrap();

        Self {
            epoch,
            runtime: sum_runtime,
            sleep_time: sum_sleep + sleep_since_start,
            block_time: sum_block + block_since_start,
            rq_time: sum_wait + wait_since_start,
            iowait_time: sum_iowait,
        }
    }
}

impl ToCsv for SchedSample {
    fn csv_headers(&self) -> &'static str {
        "epoch_ms,runtime,rq_time,sleep_time,block_time,iowait_time\n"
    }

    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{}\n",
            self.epoch,
            self.runtime,
            self.rq_time,
            self.sleep_time,
            self.block_time,
            self.iowait_time
        )
    }
}
