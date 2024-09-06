use crate::{
    execute::{
        programs::{
            futex::FutexProgram,
            ipc::{Connection, IpcProgram},
        },
        Executor,
    },
    metrics::{
        futex::Futex,
        ipc::{Ipc, KFile},
        scheduler::{Sched, SchedStat},
        Collect,
    },
};
use eyre::Result;
use regex::Regex;
use std::{
    cell::RefCell,
    collections::HashMap,
    error::Error,
    fmt::{self, Display},
    fs,
    rc::Rc,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
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
    collectors: [Box<dyn Collect>; 2],
}

impl Target {
    pub fn new(
        tid: usize,
        futex_program: Rc<RefCell<FutexProgram>>,
        ipc_program: Rc<RefCell<IpcProgram>>,
        root_directory: Rc<str>,
        target_subdirectory: &str,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
        time_sensitive_collector_tx: Sender<Box<dyn Collect + Send>>,
    ) -> Self {
        println!("Register new target {}", tid);
        time_sensitive_collector_tx
            .send(Box::new(SchedStat::new(
                tid,
                &format!("{}/{}", root_directory, target_subdirectory),
            )))
            .expect("Failed to send time sensitive collector");
        time_sensitive_collector_tx
            .send(Box::new(Sched::new(
                tid,
                &format!("{}/{}", root_directory, target_subdirectory),
            )))
            .expect("Failed to send time sensitive collector");
        Self {
            tid,
            collectors: [
                Box::new(Futex::new(
                    futex_program,
                    tid,
                    root_directory.clone(),
                    target_subdirectory,
                )),
                Box::new(Ipc::new(
                    ipc_program,
                    tid,
                    root_directory,
                    target_subdirectory,
                    kfile_socket_map,
                )),
            ],
        }
    }

    pub fn search_targets_regex(
        name: &str,
        kthread: bool,
        data_directory: Rc<str>,
        executor: &mut Executor,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
        time_sensitive_collector_tx: Sender<Box<dyn Collect + Send>>,
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
            let ipc_program = executor.ipc.clone();
            targets.extend(
                Self::get_threads(pid)?
                    .into_iter()
                    .map(|tid| {
                        Ok(Target::new(
                            tid,
                            futex_program.clone(),
                            ipc_program.clone(),
                            data_directory.clone(),
                            &format!("thread/{}/{}", pid, tid),
                            kfile_socket_map.clone(),
                            time_sensitive_collector_tx.clone(),
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
        for (_i, collector) in self.collectors.iter_mut().enumerate() {
            collector.sample()?;
            collector.store()?;
        }
        Ok(())
    }
}

pub struct TimeSensitive;

impl TimeSensitive {
    pub fn init_thread(
        terminate_flag: Arc<Mutex<bool>>,
        sample_interval: Duration,
    ) -> Sender<Box<dyn Collect + Send>> {
        let sample_rx = Self::start_timer_thread(terminate_flag.clone(), sample_interval);
        let (collector_tx, collector_rx) = mpsc::channel::<Box<dyn Collect + Send>>();
        thread::Builder::new()
            .name("ts-collect".to_string())
            .spawn(move || {
                let mut collectors: Vec<Box<dyn Collect + Send>> = Vec::new();
                loop {
                    sample_rx.recv()?;
                    if *terminate_flag.lock().unwrap() == true {
                        break;
                    }
                    while let Ok(collector) = collector_rx.try_recv() {
                        collectors.push(collector);
                    }
                    println!(
                        "{:?} - Start time sensitive collect",
                        chrono::offset::Utc::now()
                    );
                    for collector in collectors.iter_mut() {
                        collector.sample();
                        collector.store();
                    }
                    println!(
                        "{:?} - End time sensitive collect",
                        chrono::offset::Utc::now()
                    );
                }
                Ok(()) as Result<()>
            })
            .expect("Failed to create ts-collect thread");
        collector_tx
    }

    fn start_timer_thread(
        terminate_flag: Arc<Mutex<bool>>,
        sample_interval: Duration,
    ) -> Receiver<bool> {
        let (sample_tx, sample_rx) = mpsc::channel();
        thread::Builder::new()
            .name("ts-timer".to_string())
            .spawn(move || loop {
                thread::sleep(sample_interval);
                if *terminate_flag.lock().unwrap() == true {
                    break;
                }
                sample_tx.send(true).expect("Failed to send timer signal");
            })
            .expect("Failed to create ts-timer thread");
        sample_rx
    }
}
