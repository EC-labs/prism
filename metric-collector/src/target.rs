use crate::metrics::{
    scheduler::{Sched, SchedStat},
    Collect,
};
use eyre::Result;
use regex::Regex;
use std::{
    error::Error,
    fmt::{self, Display},
    fs::{self, File, ReadDir},
    io::BufReader,
    path::PathBuf,
};

#[derive(Debug)]
struct NotFound;

impl Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Error for NotFound {
    fn description(&self) -> &str {
        "target not found"
    }
}

pub struct Target {
    collectors: Vec<Box<dyn Collect>>,
    tid: usize,
    name: String,
}

impl Target {
    pub fn new(tid: usize, data_directory: &str) -> Self {
        Self {
            tid,
            collectors: vec![
                Box::new(SchedStat::new(tid, data_directory)),
                Box::new(Sched::new(tid, data_directory)),
            ],
            name: String::from(""),
        }
    }

    pub fn search_targets_regex(
        name: &str,
        kthread: bool,
        data_directory: &str,
    ) -> Result<Vec<Self>> {
        let mut targets = Vec::new();

        let tasks = fs::read_dir(format!("/proc"))?;
        for task in tasks {
            let file_path = task?.path();
            let stem = file_path.file_stem().unwrap().to_str().unwrap();
            let re = Regex::new(r"\d+").unwrap();
            let captures = re.captures(stem);
            if let None = captures {
                continue;
            }
            let tid: usize = stem.parse()?;

            let proc_stat = fs::read_to_string(format!("{}/stat", file_path.to_str().unwrap()))?;
            let mut proc_stat = proc_stat.split(" ");
            let (comm, flags) = (proc_stat.nth(1).unwrap(), proc_stat.nth(6).unwrap());
            let re = Regex::new(r"[\(\)]")?;
            let comm = re.replace_all(&comm, "");
            let flags = flags.parse::<i64>()?;

            let is_kthread = (flags & 0x00200000) != 0;
            if is_kthread != kthread {
                continue;
            }

            let re = Regex::new(name)?;
            let re_match = re.captures(&comm);
            if let None = re_match {
                continue;
            }

            targets.extend(
                Self::get_threads(file_path)?
                    .into_iter()
                    .map(|tid| {
                        Ok(Target::new(
                            tid,
                            &format!("{}/{}/{}", data_directory, comm, tid),
                        ))
                    })
                    .collect::<Result<Vec<Target>>>()?,
            );
        }

        return Ok(targets);
    }

    fn get_threads(proc_pid_path: PathBuf) -> Result<Vec<usize>> {
        let tasks = fs::read_dir(format!("{}/task", proc_pid_path.to_str().unwrap()))?;

        tasks
            .map(|task| {
                let file_path = task?.path();
                let stem = file_path.file_stem().unwrap().to_str().unwrap();
                Ok(stem.parse()?)
            })
            .collect()
    }

    pub fn sample(&mut self) -> Result<()> {
        for collector in self.collectors.iter_mut() {
            let sample = collector.sample()?;
            collector.store(sample)?;
        }
        Ok(())
    }
}
