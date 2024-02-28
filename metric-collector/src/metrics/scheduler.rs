use eyre::Result;
use regex::Regex;
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::prelude::*;
use std::time::UNIX_EPOCH;
use std::{concat, time::SystemTime};

use super::{Collect, ToCsv};

pub struct SchedStat {
    proc_file: String,
    data_directory: String,
    day_epoch: Option<u128>,
    data_file: Option<File>,
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
    fn csv_headers(&self) -> String {
        String::from("epoch_ms,runtime,rq_time,run_periods\n")
    }

    fn to_csv_row(&self) -> (u128, String) {
        (
            self.epoch,
            format!(
                "{},{},{},{}\n",
                self.epoch, self.runtime, self.rq_time, self.run_periods
            ),
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
        }
    }
}

impl Collect for SchedStat {
    fn sample(&self) -> Result<Box<dyn ToCsv>> {
        let contents = fs::read_to_string(&self.proc_file)?.replace("\n", "");
        let sample = SchedStatSample::from(contents.split(" ").collect::<Vec<&str>>());
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

pub struct Sched {
    proc_file: String,
    data_directory: String,
    data_file: Option<File>,
    day_epoch: Option<u128>,
}

impl Sched {
    pub fn new(tid: usize, data_directory: &str) -> Self {
        Self {
            proc_file: format!("/proc/{tid}/sched"),
            data_directory: format!("{}/sched", data_directory),
            data_file: None,
            day_epoch: None,
        }
    }
}

impl Collect for Sched {
    fn sample(&self) -> Result<Box<dyn ToCsv>> {
        let contents = fs::read_to_string(&self.proc_file)?;
        let sample = SchedSample::from(contents);
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
pub struct SchedSample {
    epoch: u128,
    runtime: f64,
    rq_time: f64,
    sleep_time: f64,
    block_time: f64,
    iowait_time: f64,
}

impl From<String> for SchedSample {
    fn from(content: String) -> Self {
        let start = SystemTime::now();
        let epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        let re = Regex::new(concat!(
            r"sum_exec_runtime\s*:\s*(\d+\.\d+)\n(.*\n)*",
            r"sum_sleep_runtime\s*:\s*(\d+\.\d+)\n(.*\n)*",
            r"sum_block_runtime\s*:\s*(\d+\.\d+)\n(.*\n)*",
            r"wait_sum\s*:\s*(\d+\.\d+)\n(.*\n)*",
            r"iowait_sum\s*:\s*(\d+\.\d+)\n(.*\n)*",
        ))
        .unwrap();
        let captures = re.captures(&content).unwrap();

        Self {
            epoch,
            runtime: captures[1].parse().unwrap(),
            sleep_time: captures[3].parse().unwrap(),
            block_time: captures[5].parse().unwrap(),
            rq_time: captures[7].parse().unwrap(),
            iowait_time: captures[9].parse().unwrap(),
        }
    }
}

impl ToCsv for SchedSample {
    fn csv_headers(&self) -> String {
        String::from("epoch_ms,runtime,rq_time,sleep_time,block_time,iowait_time\n")
    }

    fn to_csv_row(&self) -> (u128, String) {
        (
            self.epoch,
            format!(
                "{},{},{},{},{},{}\n",
                self.epoch,
                self.runtime,
                self.rq_time,
                self.sleep_time,
                self.block_time,
                self.iowait_time
            ),
        )
    }
}
