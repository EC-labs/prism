use chrono;
use ctrlc;
use eyre::Result;
use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    rc::Rc,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crate::{
    configure::Config,
    execute::programs::{clone::CloneEvent, ipc::Connection},
    metrics::{iowait::IOWait, Collect},
    target::TimeSensitive,
};
use crate::{execute::Executor, metrics::ipc::KFile};
use crate::{metrics::ipc::EventPollCollection, target::Target};

pub struct Extractor {
    terminate_flag: Arc<Mutex<bool>>,
    config: Config,
    targets: HashMap<usize, Target>,
    system_metrics: Vec<Box<dyn Collect>>,
    rx_timer: Option<Receiver<bool>>,
    kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
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

    fn register_new_targets(
        &mut self,
        executor: &mut Executor,
        time_sensitive_collector_tx: Sender<Box<dyn Collect + Send>>,
    ) -> Result<()> {
        executor
            .clone
            .poll_events()?
            .into_iter()
            .for_each(|clone_event| match clone_event {
                CloneEvent::NewThread { pid, tid, .. } => {
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
                            &format!("thread/{}/{}", pid, tid),
                            self.kfile_socket_map.clone(),
                            time_sensitive_collector_tx.clone(),
                        ),
                    );
                }
                CloneEvent::NewProcess(_, pid) => {
                    executor.monitor(pid);
                    if let Ok(targets) = Target::get_threads(pid) {
                        targets.into_iter().for_each(|tid| {
                            self.targets.insert(
                                tid,
                                Target::new(
                                    tid,
                                    executor.futex.clone(),
                                    executor.ipc.clone(),
                                    self.config.data_directory.clone(),
                                    &format!("thread/{}/{}", pid, tid),
                                    self.kfile_socket_map.clone(),
                                    time_sensitive_collector_tx.clone(),
                                ),
                            );
                        });
                    }
                }
                CloneEvent::RemoveProcess(pid) => {
                    if let Ok(targets) = Target::get_threads(pid) {
                        targets.into_iter().for_each(|tid| {
                            self.targets.remove(&tid);
                        });
                    }
                }
                _ => {}
            });

        let new_pids = executor.futex.borrow_mut().take_new_pid_events()?;
        for (_, pid) in new_pids {
            executor.monitor(pid);
            if let Ok(targets) = Target::get_threads(pid) {
                targets.into_iter().for_each(|tid| {
                    self.targets.insert(
                        tid,
                        Target::new(
                            tid,
                            executor.futex.clone(),
                            executor.ipc.clone(),
                            self.config.data_directory.clone(),
                            &format!("thread/{}/{}", pid, tid),
                            self.kfile_socket_map.clone(),
                            time_sensitive_collector_tx.clone(),
                        ),
                    );
                });
            }
        }

        let events = executor.ipc.borrow_mut().take_process_events()?;
        for event in events {
            if let IpcEvent::NewProcess { pid, .. } = event {
                executor.monitor(pid);
                if let Ok(targets) = Target::get_threads(pid) {
                    targets.into_iter().for_each(|tid| {
                        self.targets.insert(
                            tid,
                            Target::new(
                                tid,
                                executor.futex.clone(),
                                executor.ipc.clone(),
                                self.config.data_directory.clone(),
                                &format!("thread/{}/{}", pid, tid),
                                self.kfile_socket_map.clone(),
                            ),
                        );
                    });
                }
            }
        }

        Ok(())
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

        thread::Builder::new()
            .name("interval-timer".to_string())
            .spawn(move || {
                while *terminate_flag.lock().unwrap() == false {
                    thread::sleep(Duration::from_millis(period));
                    if let Err(_) = tx_timer.send(true) {
                        break;
                    };
                }
            })
            .expect("Failed to create interval-timer thread");
    }

    fn sample_system_metrics(&mut self) -> Result<()> {
        for metric in self.system_metrics.iter_mut() {
            metric.sample()?;
            metric.store()?;
        }

        Ok(())
    }

    fn write_fs_version(&self) -> Result<()> {
        fs::create_dir_all(&*self.config.data_directory)?;
        fs::write(
            format!("{}/version.txt", self.config.data_directory),
            "0.2.0\n",
        )?;
        Ok(())
    }

    pub fn run(mut self) -> Result<()> {
        self.write_fs_version()?;
        self.register_sighandler();
        let mut executor = Executor::new(self.terminate_flag.clone())?;
        self.start_timer_thread();
        let time_sensitive_collector_tx = TimeSensitive::init_thread(
            self.terminate_flag.clone(),
            Duration::from_millis(self.config.period),
        );

        let targets = Target::search_targets_regex(
            "jbd2",
            true,
            self.config.data_directory.clone(),
            &mut executor,
            self.kfile_socket_map.clone(),
            time_sensitive_collector_tx.clone(),
        )?;
        targets.into_iter().for_each(|target| {
            self.targets.insert(target.tid, target);
        });

        if let Some(process_name) = &self.config.process_name {
            let targets = Target::search_targets_regex(
                &process_name,
                false,
                self.config.data_directory.clone(),
                &mut executor,
                self.kfile_socket_map.clone(),
                time_sensitive_collector_tx.clone(),
            )?;
            targets.into_iter().for_each(|target| {
                self.targets.insert(target.tid, target);
            });
        } else if let Some(pids) = &self.config.pids {
            for pid in pids {
                executor.monitor(*pid as usize);
                let tids = Target::get_threads(*pid as usize)?;
                tids.into_iter().for_each(|tid| {
                    self.targets.insert(
                        tid,
                        Target::new(
                            tid,
                            executor.futex.clone(),
                            executor.ipc.clone(),
                            self.config.data_directory.clone(),
                            &format!("thread/{}/{}", pid, tid),
                            self.kfile_socket_map.clone(),
                            time_sensitive_collector_tx.clone(),
                        ),
                    );
                });
            }
        }

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

            self.sample_targets();
            self.sample_system_metrics()?;
            self.register_new_targets(&mut executor, time_sensitive_collector_tx.clone())?;
        }

        Ok(())
    }
}
