use chrono;
use ctrlc;
use eyre::Result;
use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::{mpsc::Receiver, Arc, Mutex},
    thread,
    time::Duration,
};

use crate::{
    configure::Config,
    metrics::{iowait::IOWait, Collect},
};
use crate::{
    execute::Executor,
    metrics::ipc::{KFile, Socket},
};
use crate::{metrics::ipc::EventPollCollection, target::Target};

pub struct Extractor {
    terminate_flag: Arc<Mutex<bool>>,
    config: Config,
    targets: HashMap<usize, Target>,
    system_metrics: Vec<Box<dyn Collect>>,
    rx_timer: Option<Receiver<bool>>,
    kfile_socket_map: Rc<RefCell<HashMap<KFile, Socket>>>,
}

impl Extractor {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            terminate_flag: Arc::new(Mutex::new(false)),
            targets: HashMap::new(),
            system_metrics: Vec::new(),
            rx_timer: None,
            kfile_socket_map: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    fn register_sighandler(&self) {
        let terminate_flag = self.terminate_flag.clone();
        ctrlc::set_handler(move || {
            let mut terminate_flag = terminate_flag.lock().unwrap();
            *terminate_flag = true;
        })
        .expect("Error setting Ctrl-C handler");
    }

    fn register_new_targets(&mut self, executor: &mut Executor) {
        executor
            .clone
            .poll_events()
            .unwrap()
            .into_iter()
            .for_each(|(comm, tid)| {
                if let Some(_) = self.targets.get(&tid) {
                    return;
                }

                self.targets.insert(
                    tid,
                    Target::new(
                        tid,
                        executor.futex.clone(),
                        executor.ipc.clone(),
                        self.config.data_directory.clone(),
                        &format!("{}/{}", comm, tid),
                        self.kfile_socket_map.clone(),
                    ),
                );
            });

        let new_pids = executor.futex.borrow_mut().take_new_pid_events().unwrap();
        for (comm, pid) in new_pids {
            executor.monitor(pid);
            Target::get_threads(pid)
                .unwrap()
                .into_iter()
                .for_each(|tid| {
                    self.targets.insert(
                        tid,
                        Target::new(
                            tid,
                            executor.futex.clone(),
                            executor.ipc.clone(),
                            self.config.data_directory.clone(),
                            &format!("{}/{}", comm, tid),
                            self.kfile_socket_map.clone(),
                        ),
                    );
                });
        }
    }

    fn sample_targets(&mut self) {
        let mut targets_remove = Vec::new();
        self.targets.iter_mut().for_each(|(tid, target)| {
            if let Err(_e) = target.sample() {
                println!("Remove target {tid}");
                targets_remove.push(*tid)
            }
        });

        for tid in targets_remove {
            self.targets.remove(&tid);
        }
    }

    fn start_timer_thread(&mut self) {
        let (tx_timer, rx_timer) = std::sync::mpsc::channel::<bool>();
        self.rx_timer = Some(rx_timer);

        let period = self.config.period;
        let terminate_flag = self.terminate_flag.clone();

        thread::spawn(move || {
            while *terminate_flag.lock().unwrap() == false {
                thread::sleep(Duration::from_millis(period));
                if let Err(_) = tx_timer.send(true) {
                    break;
                };
            }
        });
    }

    fn sample_system_metrics(&mut self) -> Result<()> {
        for metric in self.system_metrics.iter_mut() {
            metric.sample()?;
            metric.store()?;
        }

        Ok(())
    }

    pub fn run(mut self) -> Result<()> {
        self.register_sighandler();
        let mut executor = Executor::new(self.terminate_flag.clone())?;
        self.start_timer_thread();

        let targets = Target::search_targets_regex(
            "jbd2",
            true,
            self.config.data_directory.clone(),
            &mut executor,
            self.kfile_socket_map.clone(),
        )?;
        targets.into_iter().for_each(|target| {
            self.targets.insert(target.tid, target);
        });

        let targets = Target::search_targets_regex(
            self.config.process_name.as_ref().unwrap(),
            false,
            self.config.data_directory.clone(),
            &mut executor,
            self.kfile_socket_map.clone(),
        )?;
        targets.into_iter().for_each(|target| {
            self.targets.insert(target.tid, target);
        });

        self.system_metrics.push(Box::new(IOWait::new(
            executor.io_wait.clone(),
            Some(self.config.data_directory.clone()),
        )));
        self.system_metrics.push(Box::new(EventPollCollection::new(
            executor.ipc.clone(),
            self.kfile_socket_map.clone(),
            self.config.data_directory.clone(),
        )));

        let rx_timer = self.rx_timer.take().unwrap();
        loop {
            rx_timer.recv().unwrap();
            if *self.terminate_flag.lock().unwrap() == true {
                break;
            }

            println!("{:?} - Start collect", chrono::offset::Utc::now());
            self.sample_targets();
            self.sample_system_metrics()?;
            self.register_new_targets(&mut executor);
            println!("{:?} - End collect", chrono::offset::Utc::now());
        }

        Ok(())
    }
}
