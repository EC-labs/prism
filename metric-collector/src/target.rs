use crate::{
    execute::{programs::futex::FutexProgram, Executor},
    metrics::{
        futex::Futex,
        scheduler::{Sched, SchedStat},
        Collect,
    },
};
use eyre::Result;
use regex::Regex;
use std::{
    cell::RefCell,
    error::Error,
    fmt::{self, Display},
    fs,
    path::PathBuf,
    rc::Rc,
};

#[derive(Debug)]
struct NotFound;

impl Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Target not found")
    }
}

impl Error for NotFound {}

pub struct Target {
    pub tid: usize,
    collectors: [Box<dyn Collect>; 3],
}

impl Target {
    pub fn new(
        tid: usize,
        futex_program: Rc<RefCell<FutexProgram>>,
        root_directory: Rc<str>,
        target_subdirectory: &str,
    ) -> Self {
        Self {
            tid,
            collectors: [
                Box::new(SchedStat::new(
                    tid,
                    &format!("{}/{}", root_directory, target_subdirectory),
                )),
                Box::new(Sched::new(
                    tid,
                    &format!("{}/{}", root_directory, target_subdirectory),
                )),
                Box::new(Futex::new(
                    futex_program,
                    tid,
                    root_directory,
                    target_subdirectory,
                )),
            ],
        }
    }

    pub fn search_targets_regex(
        name: &str,
        kthread: bool,
        data_directory: Rc<str>,
        executor: &mut Executor,
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

            let proc_stat = fs::read_to_string(format!("{}/stat", file_path.to_str().unwrap()));
            if let Err(_) = proc_stat {
                continue;
            }
            let proc_stat = proc_stat.unwrap();
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
            let pid: usize = stem.parse()?;
            executor.monitor(pid);

            let futex_program = executor.futex.clone();
            targets.extend(
                Self::get_threads(pid)?
                    .into_iter()
                    .map(|tid| {
                        Ok(Target::new(
                            tid,
                            futex_program.clone(),
                            data_directory.clone(),
                            &format!("{}/{}", comm, tid),
                        ))
                    })
                    .collect::<Result<Vec<Target>>>()?,
            );
        }

        return Ok(targets);
    }

    pub fn get_threads(pid: usize) -> Result<Vec<usize>> {
        let tasks = fs::read_dir(format!("/proc/{}/task", pid))?;

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
            collector.sample()?;
            collector.store()?;
        }
        Ok(())
    }
}
