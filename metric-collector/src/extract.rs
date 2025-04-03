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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use std::{env, mem::MaybeUninit};

use crate::sub::{
    futex::Futex, iowait::IOWait, muxio::Muxio, net::Net, taskstats::TaskStats, vfs::Vfs,
};
use duckdb::Connection;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use libc::{geteuid, seteuid};
use log::info;

use crate::{configure::Config, execute::programs::clone::CloneEvent, metrics::Collect};
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

fn create_pid_rb() -> Result<MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    Ok(MapHandle::create(
        MapType::RingBuf,
        Some("pid_rb"),
        0,
        0,
        (size_of::<u32>() * 8192) as u32,
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

    fn write_fs_version(&self) -> Result<()> {
        fs::create_dir_all(&*self.config.data_directory)?;
        fs::write(
            format!("{}/version.txt", self.config.data_directory),
            "0.2.0\n",
        )?;
        Ok(())
    }

    pub fn run(mut self) -> Result<()> {
        self.register_sighandler();
        self.start_timer_thread();
        let time_sensitive_collector_tx = TimeSensitive::init_thread(
            self.terminate_flag.clone(),
            Duration::from_millis(self.config.period),
        );

        let pid_map = create_pid_map()?;
        let pid_rb = create_pid_rb()?;
        let init_pids = Vec::new();

        if let Some(process_name) = &self.config.process_name {
            init_pids.extend(Target::search_targets_regex(&process_name, false))?
        }

        if let Some(pids) = &self.config.pids {
            init_pids.extend(pids);
        }

        init_pids.into_iter.for_each(|pid| {
            pid_map.update(
                &(*pid as u32).to_ne_bytes(),
                &1u8.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        });

        let euid = unsafe { geteuid() };
        let uid = env::var("SUDO_UID")?.parse::<u32>()?;
        unsafe { seteuid(uid) };
        let path = "./data/prism-db.db3";
        let conn = Connection::open(&path)?;
        unsafe { seteuid(euid) };

        let mut iowait_open_object = MaybeUninit::uninit();
        let mut iowait = IOWait::new(&mut iowait_open_object, &conn).unwrap();

        let mut vfs_open_object = MaybeUninit::uninit();
        let mut vfs =
            Vfs::new(&mut vfs_open_object, &conn, pid_map.as_fd(), pid_rb.as_fd()).unwrap();

        let mut futex_open_object = MaybeUninit::uninit();
        let mut futex = Futex::new(
            &mut futex_open_object,
            pid_map.as_fd(),
            pid_rb.as_fd(),
            &conn,
        )
        .unwrap();

        let mut net_open_object = MaybeUninit::uninit();
        let mut net = Net::new(
            &mut net_open_object,
            &conn,
            pid_map.as_fd(),
            pid_rb.as_fd(),
            vfs.skel.maps.samples.as_fd(),
            vfs.skel.maps.pending.as_fd(),
            vfs.skel.maps.to_update.as_fd(),
        )
        .unwrap();

        let mut muxio = Muxio::new(pid_map.as_fd(), &conn).unwrap();

        let mut taskstats = TaskStats::new(&pid_map, pid_rb, &conn)?;

        let rx_timer = self.rx_timer.take().unwrap();
        loop {
            rx_timer.recv().unwrap();
            while let Ok(_) = rx_timer.try_recv() {}
            if *self.terminate_flag.lock().unwrap() == true {
                break;
            }

            let start = Instant::now();
            iowait.sample()?;
            let iowait_elapsed = start.elapsed().as_nanos();
            vfs.sample()?;
            let vfs_elapsed = start.elapsed().as_nanos();
            let vfs_acct = vfs_elapsed - iowait_elapsed;
            futex.sample()?;
            let futex_elapsed = start.elapsed().as_nanos();
            let futex_acct = futex_elapsed - vfs_elapsed;
            net.sample()?;
            let net_elapsed = start.elapsed().as_nanos();
            let net_acct = net_elapsed - futex_elapsed;
            muxio.sample()?;
            let muxio_elapsed = start.elapsed().as_nanos();
            let muxio_acct = muxio_elapsed - net_elapsed;
            taskstats.sample()?;
            info!(
                "sample loop elapsed time: {}ms io[{}%] vfs[{}%] futex[{}%] net[{}%] muxio[{}%]",
                muxio_elapsed / 1_000_000,
                iowait_elapsed * 100 / muxio_elapsed,
                vfs_acct * 100 / muxio_elapsed,
                futex_acct * 100 / muxio_elapsed,
                net_acct * 100 / muxio_elapsed,
                muxio_acct * 100 / muxio_elapsed,
            );
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
                    let start = Instant::now();
                    while let Ok(collector) = collector_rx.try_recv() {
                        collectors.push(collector);
                    }
                    for collector in collectors.iter_mut() {
                        collector.sample();
                        collector.store();
                    }
                    info!(
                        "time sensitive loop duration: {}ms",
                        start.elapsed().as_millis()
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
