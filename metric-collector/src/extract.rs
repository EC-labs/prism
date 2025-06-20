use anyhow::Result;
use bus::Bus;
use ctrlc;
use duckdb::{Connection, ToSql};
use libbpf_rs::{libbpf_sys::{self, libbpf_set_print}, MapCore, MapFlags, MapHandle, MapType};
use libc::{geteuid, seteuid};
use log::{info, warn, error};
use nix::time::{self, ClockId};
use regex::Regex;
use std::{
    env, fs, mem::MaybeUninit, os::fd::AsFd, ptr::null, sync::{
        mpsc::{self, Receiver},
        Arc, Mutex, RwLock,
    }, thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}
};
use syn::{Expr, Item, Lit};

use crate::{
    configure::Config,
    sub::{
        self,
        discovery::Discovery,
        futex::Futex,
        iowait::IOWait,
        muxio::Muxio,
        net::Net,
        taskstats::{TaskStatsIter, TaskStatsTrace},
        vfs::Vfs,
        process_context,
        MAX_ENTRIES,
    },
    target,
};

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
        MAX_ENTRIES as u32,
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
        (size_of::<u32>() as u64 * MAX_ENTRIES) as u32,
        &opts,
    )?)
}

pub struct Extractor {
    terminate_flag: Arc<Mutex<bool>>,
    config: Config,
    rx_timer: Option<Receiver<bool>>,
    conn: Connection,
}

impl Extractor {
    pub fn new(config: Config) -> Result<Self> {
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

        sub::bump_memlock_rlimit()?;

        let euid = unsafe { geteuid() };
        let uid = env::var("SUDO_UID")?.parse::<u32>()?;
        unsafe { seteuid(uid) };
        let conn = Connection::open(&*config.prism_store)?;
        unsafe { seteuid(euid) };

        Self::insert_linux_consts(&conn)?;
        Ok(Self {
            conn,
            config,
            terminate_flag: Arc::new(Mutex::new(false)),
            rx_timer: None,
        })
    }

    fn insert_linux_consts(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
            CREATE OR REPLACE TABLE linux_consts (
                const_type VARCHAR,
                const_name VARCHAR,   
                value UINTEGER,
            );
            ",
        )?;
        let mut appender = conn.appender("linux_consts")?;

        let src = fs::read_to_string("metric-collector/src/sub/include/linux/bindings.rs")?;
        let syntax = syn::parse_file(&src).expect("Unable to parse file");
        for item in syntax.items {
            let Item::Const(itemconst) = item else {
                continue;
            };
            let Expr::Lit(exprlit) = *itemconst.expr else {
                continue;
            };
            let Lit::Int(litint) = exprlit.lit else {
                continue;
            };

            let identifier = itemconst.ident.to_string();
            let literal = litint.base10_parse::<u32>()?;

            let re = Regex::new(r"sock_type_(.*)").unwrap();
            if let Some(captures) = re.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"socket_type" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }

            let re = Regex::new(r"(AF_.*)").unwrap();
            if let Some(captures) = re.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"socket_family" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }

            let re = Regex::new(r"(IPPROTO_.*)").unwrap();
            if let Some(captures) = re.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"family_protocol" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }

            let re = Regex::new(r"(.*_MAGIC)").unwrap();
            if let Some(captures) = re.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"fs_magic" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }
        }

        return Ok(());
    }

    fn register_sighandler(&self) {
        let terminate_flag = self.terminate_flag.clone();
        ctrlc::set_handler(move || {
            let mut terminate_flag = terminate_flag.lock().unwrap();
            info!("received termination signal");
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

    pub fn run(mut self) -> Result<()> {
        self.register_sighandler();
        self.start_timer_thread();

        info!("starting bpf programs");
        let pid_map = create_pid_map()?;
        let pid_rb = create_pid_rb()?;
        let mut init_pids: Vec<usize> = Vec::new();

        if let Some(process_name) = &self.config.process_name {
            init_pids.extend(target::search_targets_regex(&process_name, false)?);
        }

        if let Some(pids) = &self.config.pids {
            init_pids.extend(pids.clone());
        }

        for pid in init_pids {
            pid_map.update(
                &(pid as u32).to_ne_bytes(),
                &1u8.to_ne_bytes(),
                MapFlags::ANY,
            )?
        }

        // To broadcast when a new pid is registered
        let mut pid_bus = Bus::new(100);
        let discovery_rx = pid_bus.add_rx();
        let process_context_rx = pid_bus.add_rx();

        let conn = &self.conn;

        let mut iowait_open_object = MaybeUninit::uninit();
        let mut iowait = IOWait::new(&mut iowait_open_object, conn).unwrap();

        let mut vfs_open_object = MaybeUninit::uninit();
        let mut vfs =
            Vfs::new(&mut vfs_open_object, conn, pid_map.as_fd(), pid_rb.as_fd()).unwrap();

        let mut futex_open_object = MaybeUninit::uninit();
        let mut futex = Futex::new(
            &mut futex_open_object,
            pid_map.as_fd(),
            pid_rb.as_fd(),
            conn,
        )
        .unwrap();

        let mut net_open_object = MaybeUninit::uninit();
        let mut net = Net::new(
            &mut net_open_object,
            conn,
            pid_map.as_fd(),
            pid_rb.as_fd(),
            vfs.skel.maps.samples.as_fd(),
            vfs.skel.maps.pending.as_fd(),
            vfs.skel.maps.to_update.as_fd(),
        )
        .unwrap();

        let mut discovery = Discovery::new(
            conn,
            self.config.machine_id,
            MapHandle::try_from(&pid_map)?,
            MapHandle::try_from(&pid_rb)?,
            MapHandle::try_from(&net.skel.maps.socket_context)?,
            MapHandle::try_from(&net.skel.maps.rb)?,
            discovery_rx
        )
        .unwrap();

        let mut taskstats_open_object = MaybeUninit::uninit();
        let mut taskstats =
            TaskStatsTrace::new(&mut taskstats_open_object, &conn, pid_map.as_fd())?;

        let mut muxio = Muxio::new(pid_map.as_fd(), conn).unwrap();

        TimeSensitive::init_thread(
            self.terminate_flag.clone(),
            Duration::from_millis(self.config.period),
            pid_map,
            pid_rb,
            pid_bus,
            conn.try_clone()?,
        );

        let process_context = process_context::init_thread(
            self.terminate_flag.clone(),
            conn, 
            process_context_rx
        )?;

        let rx_timer = self.rx_timer.take().unwrap();
        info!("starting metric collection loop");
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
            discovery.sample();
            let discovery_elapsed = start.elapsed().as_nanos();
            let discovery_acct = discovery_elapsed - net_elapsed;
            taskstats.sample()?;
            let taskstats_elapsed = start.elapsed().as_nanos();
            let taskstats_acct = taskstats_elapsed - discovery_elapsed;
            // muxio.sample()?;
            let muxio_elapsed = start.elapsed().as_nanos();
            let muxio_acct = muxio_elapsed - taskstats_elapsed;

            if muxio_elapsed > 1_000_000_000 {
                warn!(
                    "sample loop exceeded 1s: {}ms io[{}%] vfs[{}%] futex[{}%] net[{}%] discovery[{}%] taskstats[{}%] muxio[{}%]",
                    muxio_elapsed / 1_000_000,
                    iowait_elapsed * 100 / muxio_elapsed,
                    vfs_acct * 100 / muxio_elapsed,
                    futex_acct * 100 / muxio_elapsed,
                    net_acct * 100 / muxio_elapsed,
                    discovery_acct * 100 / muxio_elapsed,
                    taskstats_acct * 100 / muxio_elapsed,
                    muxio_acct * 100 / muxio_elapsed,
                );
            } else if muxio_elapsed > 10_000_000_000 {
                error!(
                    "sample loop exceeded 10s: {}ms io[{}%] vfs[{}%] futex[{}%] net[{}%] discovery[{}%] taskstats[{}%] muxio[{}%]",
                    muxio_elapsed / 1_000_000,
                    iowait_elapsed * 100 / muxio_elapsed,
                    vfs_acct * 100 / muxio_elapsed,
                    futex_acct * 100 / muxio_elapsed,
                    net_acct * 100 / muxio_elapsed,
                    discovery_acct * 100 / muxio_elapsed,
                    taskstats_acct * 100 / muxio_elapsed,
                    muxio_acct * 100 / muxio_elapsed,
                );
            }
        }

        Ok(())
    }
}

pub struct TimeSensitive;

impl TimeSensitive {
    pub fn init_thread(
        terminate_flag: Arc<Mutex<bool>>,
        sample_interval: Duration,
        pid_map: MapHandle,
        pid_rb: MapHandle,
        pid_bus: Bus<u32>,
        conn: Connection,
    ) {
        let sample_rx = Self::start_timer_thread(terminate_flag.clone(), sample_interval);
        thread::Builder::new()
            .name("ts-collect".to_string())
            .spawn(move || {
                let mut taskstats = TaskStatsIter::new(pid_map, pid_rb, &conn, pid_bus)?;
                loop {
                    sample_rx.recv()?;
                    while let Ok(_) = sample_rx.try_recv() {}
                    if *terminate_flag.lock().unwrap() == true {
                        break;
                    }
                    let start = Instant::now();
                    taskstats.sample()?;
                    let elapsed_us = start.elapsed().as_micros();
                    if elapsed_us > 10_000 {
                        warn!(
                            "time sensitive loop duration: {}us",
                            start.elapsed().as_micros()
                        );
                    }
                }
                Ok(()) as Result<()>
            })
            .expect("Failed to create ts-collect thread");
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
