use anyhow::Result;
use ctrlc;
use nix::time::{self, ClockId};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    os::fd::AsFd,
    rc::Rc,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex, RwLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use std::{env, mem::MaybeUninit};

use crate::sub;
use crate::sub::futex::Futex;
use crate::sub::vfs::Vfs;
use duckdb::Connection;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use libc::{geteuid, seteuid};

use crate::{
    configure::Config,
    execute::programs::clone::CloneEvent,
    metrics::{iowait::IOWait, Collect},
    target::TimeSensitive,
};
use crate::{execute::Executor, metrics::ipc::KFile};
use crate::{metrics::ipc::EventPollCollection, target::Target};

pub static BOOT_EPOCH_NS: RwLock<u64> = RwLock::new(0);

pub fn boot_to_epoch(boot_ns: u64) -> u64 {
    *BOOT_EPOCH_NS.read().unwrap() + boot_ns
}

fn create_pid_map() -> Result<MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    Ok(MapHandle::create(
        MapType::Hash,
        Some("pids"),
        size_of::<u32>() as u32,
        size_of::<u8>() as u32,
        8192,
        &opts,
    )?)
}

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
        if *BOOT_EPOCH_NS.read().unwrap() == 0 {
            let ns_since_boot =
                Duration::from(time::clock_gettime(ClockId::CLOCK_BOOTTIME).unwrap()).as_nanos();
            let start = SystemTime::now();
            let ns_since_epoch = start
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_nanos();
            *BOOT_EPOCH_NS.write().unwrap() = (ns_since_epoch - ns_since_boot) as u64;
        }
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

    // fn register_new_targets(
    //     &mut self,
    //     executor: &mut Executor,
    //     time_sensitive_collector_tx: Sender<Box<dyn Collect + Send>>,
    // ) -> Result<()> {
    //     executor
    //         .clone
    //         .poll_events()?
    //         .into_iter()
    //         .for_each(|clone_event| match clone_event {
    //             CloneEvent::NewThread { pid, tid, .. } => {
    //                 if let Some(_) = self.targets.get(&tid) {
    //                     return;
    //                 }

    //                 self.targets.insert(
    //                     tid,
    //                     Target::new(
    //                         tid,
    //                         executor.futex.clone(),
    //                         executor.ipc.clone(),
    //                         self.config.data_directory.clone(),
    //                         &format!("thread/{}/{}", pid, tid),
    //                         self.kfile_socket_map.clone(),
    //                         time_sensitive_collector_tx.clone(),
    //                     ),
    //                 );
    //             }
    //             CloneEvent::NewProcess(_, pid) => {
    //                 executor.monitor(pid);
    //                 if let Ok(targets) = Target::get_threads(pid) {
    //                     targets.into_iter().for_each(|tid| {
    //                         self.targets.insert(
    //                             tid,
    //                             Target::new(
    //                                 tid,
    //                                 executor.futex.clone(),
    //                                 executor.ipc.clone(),
    //                                 self.config.data_directory.clone(),
    //                                 &format!("thread/{}/{}", pid, tid),
    //                                 self.kfile_socket_map.clone(),
    //                                 time_sensitive_collector_tx.clone(),
    //                             ),
    //                         );
    //                     });
    //                 }
    //             }
    //             CloneEvent::RemoveProcess(pid) => {
    //                 if let Ok(targets) = Target::get_threads(pid) {
    //                     targets.into_iter().for_each(|tid| {
    //                         self.targets.remove(&tid);
    //                     });
    //                 }
    //             }
    //             _ => {}
    //         });

    //     let new_pids = executor.futex.borrow_mut().take_new_pid_events()?;
    //     for (_, pid) in new_pids {
    //         executor.monitor(pid);
    //         if let Ok(targets) = Target::get_threads(pid) {
    //             targets.into_iter().for_each(|tid| {
    //                 self.targets.insert(
    //                     tid,
    //                     Target::new(
    //                         tid,
    //                         executor.futex.clone(),
    //                         executor.ipc.clone(),
    //                         self.config.data_directory.clone(),
    //                         &format!("thread/{}/{}", pid, tid),
    //                         self.kfile_socket_map.clone(),
    //                         time_sensitive_collector_tx.clone(),
    //                     ),
    //                 );
    //             });
    //         }
    //     }

    //     // let events = executor.ipc.borrow_mut().take_process_events()?;
    //     // for event in events {
    //     //     if let IpcEvent::NewProcess { pid, .. } = event {
    //     //         executor.monitor(pid);
    //     //         if let Ok(targets) = Target::get_threads(pid) {
    //     //             targets.into_iter().for_each(|tid| {
    //     //                 self.targets.insert(
    //     //                     tid,
    //     //                     Target::new(
    //     //                         tid,
    //     //                         executor.futex.clone(),
    //     //                         executor.ipc.clone(),
    //     //                         self.config.data_directory.clone(),
    //     //                         &format!("thread/{}/{}", pid, tid),
    //     //                         self.kfile_socket_map.clone(),
    //     //                     ),
    //     //                 );
    //     //             });
    //     //         }
    //     //     }
    //     // }

    //     Ok(())
    // }

    // fn sample_targets(&mut self) {
    //     let mut targets_remove = Vec::new();
    //     self.targets.iter_mut().for_each(|(tid, target)| {
    //         if let Err(_e) = target.sample() {
    //             println!("Remove target {tid}");
    //             targets_remove.push(*tid)
    //         }
    //     });

    //     for tid in targets_remove {
    //         self.targets.remove(&tid);
    //     }
    // }

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

    // fn sample_system_metrics(&mut self) -> Result<()> {
    //     for metric in self.system_metrics.iter_mut() {
    //         metric.sample()?;
    //         metric.store()?;
    //     }

    //     Ok(())
    // }

    fn write_fs_version(&self) -> Result<()> {
        fs::create_dir_all(&*self.config.data_directory)?;
        fs::write(
            format!("{}/version.txt", self.config.data_directory),
            "0.2.0\n",
        )?;
        Ok(())
    }

    pub fn run(mut self) -> Result<()> {
        // self.write_fs_version()?;
        self.register_sighandler();
        // let mut executor = Executor::new(self.terminate_flag.clone())?;
        self.start_timer_thread();
        let time_sensitive_collector_tx = TimeSensitive::init_thread(
            self.terminate_flag.clone(),
            Duration::from_millis(self.config.period),
        );

        // let targets = Target::search_targets_regex(
        //     "jbd2",
        //     true,
        //     self.config.data_directory.clone(),
        //     &mut executor,
        //     self.kfile_socket_map.clone(),
        //     time_sensitive_collector_tx.clone(),
        // )?;
        // targets.into_iter().for_each(|target| {
        //     self.targets.insert(target.tid, target);
        // });

        let pid_map = create_pid_map()?;
        if let Some(process_name) = &self.config.process_name {
            // let targets = Target::search_targets_regex(
            //     &process_name,
            //     false,
            //     self.config.data_directory.clone(),
            //     &mut executor,
            //     self.kfile_socket_map.clone(),
            //     time_sensitive_collector_tx.clone(),
            // )?;
            // targets.into_iter().for_each(|target| {
            //     self.targets.insert(target.tid, target);
            // });
        } else if let Some(pids) = &self.config.pids {
            for pid in pids {
                pid_map.update(
                    &(*pid as u32).to_ne_bytes(),
                    &1u8.to_ne_bytes(),
                    MapFlags::ANY,
                )?;
                // executor.monitor(*pid as usize);
                // let tids = Target::get_threads(*pid as usize)?;
                // tids.into_iter().for_each(|tid| {
                //     self.targets.insert(
                //         tid,
                //         Target::new(
                //             tid,
                //             executor.futex.clone(),
                //             executor.ipc.clone(),
                //             self.config.data_directory.clone(),
                //             &format!("thread/{}/{}", pid, tid),
                //             self.kfile_socket_map.clone(),
                //             time_sensitive_collector_tx.clone(),
                //         ),
                //     );
                // });
            }
        }
        let euid = unsafe { geteuid() };
        let uid = env::var("SUDO_UID")?.parse::<u32>()?;
        unsafe { seteuid(uid) };
        let path = "./data/prism-db.db3";
        let conn = Connection::open(&path)?;
        unsafe { seteuid(euid) };

        let mut iowait_open_object = MaybeUninit::uninit();
        let mut iowait = sub::iowait::IOWait::new(&mut iowait_open_object, &conn).unwrap();

        let mut vfs_open_object = MaybeUninit::uninit();
        let mut vfs = Vfs::new(&mut vfs_open_object, &conn, pid_map.as_fd()).unwrap();

        let mut futex_open_object = MaybeUninit::uninit();
        let mut futex = Futex::new(&mut futex_open_object, pid_map.as_fd(), &conn).unwrap();

        // self.system_metrics.push(Box::new(IOWait::new(
        //     executor.io_wait.clone(),
        //     Some(self.config.data_directory.clone()),
        // )));
        // self.system_metrics.push(Box::new(EventPollCollection::new(
        //     executor.ipc.clone(),
        //     self.kfile_socket_map.clone(),
        //     self.config.data_directory.clone(),
        // )));

        let rx_timer = self.rx_timer.take().unwrap();
        loop {
            rx_timer.recv().unwrap();
            if *self.terminate_flag.lock().unwrap() == true {
                break;
            }

            iowait.sample()?;
            vfs.sample()?;
            futex.sample()?;
            // self.sample_targets();
            // self.sample_system_metrics()?;
            // self.register_new_targets(&mut executor, time_sensitive_collector_tx.clone())?;
        }

        Ok(())
    }
}
