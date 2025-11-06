use anyhow::Result;
use bus::Bus;
use ctrlc;
use duckdb::{Connection, ToSql};
use lazy_static::lazy_static;
use libbpf_rs::{libbpf_sys, set_print, MapCore, MapFlags, MapHandle, MapType, PrintLevel};
use libc::{geteuid, seteuid};
use log::{debug, error, info, trace, warn, LevelFilter};
use nix::time::{self, ClockId};
use regex::Regex;
use std::{
    env,
    mem::MaybeUninit,
    os::fd::AsFd,
    sync::{
        mpsc::{self, Receiver},
        Arc, Mutex, RwLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use syn::{Expr, Item, Lit};

use crate::{
    configure::Config,
    sub::{
        self,
        discovery::Discovery,
        futex::Futex,
        iowait::IOWait,
        mux::Muxio,
        net::Net,
        process_context,
        taskstats::{TaskStatsIter, TaskStatsTrace},
        vfs::Vfs,
        MAX_ENTRIES,
    },
    target,
};

lazy_static! {
    static ref SOCK_TYPE: Regex = Regex::new(r"sock_type_(.*)").unwrap();
    static ref SOCK_FAMILY: Regex = Regex::new(r"(AF_.*)").unwrap();
    static ref IPPROTO: Regex = Regex::new(r"(IPPROTO_.*)").unwrap();
    static ref FS_MAGIC: Regex = Regex::new(r"(.*_MAGIC)").unwrap();
}

pub static BOOT_EPOCH_NS: RwLock<u64> = RwLock::new(0);

pub fn boot_to_epoch(boot_ns: u64) -> u64 {
    *BOOT_EPOCH_NS.read().unwrap() + boot_ns
}

fn filter_print(level: PrintLevel, msg: String) {
    if msg.contains("Exclusivity flag on, cannot modify")
        || msg.contains("Cannot find specified filter chain")
    {
        trace!("Ignoring msg: {}", msg.trim_end());
        return;
    }

    match level {
        PrintLevel::Debug => debug!("{}", msg.trim_end()),
        PrintLevel::Info => info!("{}", msg.trim_end()),
        PrintLevel::Warn => warn!("{}", msg.trim_end()),
    };
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

        match log::max_level() {
            LevelFilter::Trace => set_print(Some((PrintLevel::Debug, filter_print))),
            LevelFilter::Debug => set_print(Some((PrintLevel::Debug, filter_print))),
            LevelFilter::Info => set_print(Some((PrintLevel::Info, filter_print))),
            LevelFilter::Warn => set_print(Some((PrintLevel::Warn, filter_print))),
            LevelFilter::Error => set_print(Some((PrintLevel::Warn, filter_print))),
            LevelFilter::Off => set_print(None),
        };

        sub::bump_memlock_rlimit()?;

        let euid = unsafe { geteuid() };
        let uid = env::var("SUDO_UID")
            .unwrap_or(format!("{euid}"))
            .parse::<u32>()?;
        unsafe { seteuid(uid) };
        let conn = Connection::open(&*config.prism_store)?;
        unsafe { seteuid(euid) };

        if let Err(e) = std::fs::write("/proc/sys/kernel/sched_schedstats", b"1") {
            warn!("Could not enable sched_schedstats: {e}");
        }
        if let Err(e) = std::fs::write("/proc/sys/kernel/task_delayacct", b"1") {
            warn!("Could not enable task_delayacct: {e}");
        }

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

        let src = include_str!("sub/include/linux/bindings.rs");
        let syntax = syn::parse_file(src).expect("Unable to parse file");
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

            if let Some(captures) = SOCK_TYPE.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"socket_type" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }

            if let Some(captures) = SOCK_FAMILY.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"socket_family" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }

            if let Some(captures) = IPPROTO.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"family_protocol" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }

            if let Some(captures) = FS_MAGIC.captures(&identifier) {
                let const_name = captures.get(1).unwrap().as_str();
                appender.append_row([&"fs_magic" as &dyn ToSql, &const_name, &literal])?;
                continue;
            }
        }

        Ok(())
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
                while !(*terminate_flag.lock().unwrap()) {
                    thread::sleep(Duration::from_millis(period));
                    if tx_timer.send(true).is_err() {
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
            init_pids.extend(target::search_targets_regex(process_name, false)?);
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
        let mut iowait =
            IOWait::new(&mut iowait_open_object, conn, self.config.machine_id).unwrap();

        let mut vfs_open_object = MaybeUninit::uninit();
        let mut vfs = Vfs::new(
            &mut vfs_open_object,
            conn,
            pid_map.as_fd(),
            pid_rb.as_fd(),
            self.config.machine_id,
        )
        .unwrap();

        let mut futex_open_object = MaybeUninit::uninit();
        let mut futex = Futex::new(
            &mut futex_open_object,
            pid_map.as_fd(),
            pid_rb.as_fd(),
            conn,
            self.config.machine_id,
        )
        .unwrap();

        let mut muxio_open_object = MaybeUninit::uninit();
        let mut muxio = Muxio::new(
            &mut muxio_open_object,
            pid_map.as_fd(),
            conn,
            self.config.machine_id,
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
            self.config.machine_id,
        )
        .unwrap();

        let mut discovery = Discovery::new(
            conn,
            self.config.machine_id,
            MapHandle::try_from(&pid_map)?,
            MapHandle::try_from(&pid_rb)?,
            MapHandle::try_from(&net.skel.maps.socket_context)?,
            MapHandle::try_from(&net.skel.maps.rb)?,
            discovery_rx,
        )
        .unwrap();

        let mut taskstats_open_object = MaybeUninit::uninit();
        let mut taskstats = TaskStatsTrace::new(
            &mut taskstats_open_object,
            conn,
            pid_map.as_fd(),
            MapHandle::try_from(&pid_rb)?,
            self.config.machine_id,
        )?;

        TimeSensitive::init_thread(
            self.terminate_flag.clone(),
            Duration::from_millis(self.config.period),
            pid_map,
            pid_rb,
            pid_bus,
            conn.try_clone()?,
            self.config.machine_id,
        );

        process_context::init_thread(
            self.terminate_flag.clone(),
            conn,
            process_context_rx,
            self.config.machine_id,
        )?;

        let rx_timer = self.rx_timer.take().unwrap();
        info!("starting metric collection loop");
        loop {
            rx_timer.recv().unwrap();
            while rx_timer.try_recv().is_ok() {}
            if *self.terminate_flag.lock().unwrap() {
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
            muxio.sample()?;
            let muxio_elapsed = start.elapsed().as_nanos();
            let muxio_acct = muxio_elapsed - futex_elapsed;
            net.sample()?;
            let net_elapsed = start.elapsed().as_nanos();
            let net_acct = net_elapsed - muxio_elapsed;
            discovery.sample()?;
            let discovery_elapsed = start.elapsed().as_nanos();
            let discovery_acct = discovery_elapsed - net_elapsed;
            taskstats.sample()?;
            let taskstats_elapsed = start.elapsed().as_nanos();
            let taskstats_acct = taskstats_elapsed - discovery_elapsed;

            if taskstats_elapsed > 1_000_000_000 {
                warn!(
                    "sample loop exceeded 1s: {}ms io[{}%] vfs[{}%] futex[{}%] muxio[{}%] net[{}%] discovery[{}%] taskstats[{}%]",
                    taskstats_elapsed / 1_000_000,
                    iowait_elapsed * 100 / taskstats_elapsed,
                    vfs_acct * 100 / taskstats_elapsed,
                    futex_acct * 100 / taskstats_elapsed,
                    muxio_acct * 100 / taskstats_elapsed,
                    net_acct * 100 / taskstats_elapsed,
                    discovery_acct * 100 / taskstats_elapsed,
                    taskstats_acct * 100 / taskstats_elapsed,
                );
            } else if taskstats_elapsed > 10_000_000_000 {
                error!(
                    "sample loop exceeded 10s: {}ms io[{}%] vfs[{}%] futex[{}%] muxio[{}%] net[{}%] discovery[{}%] taskstats[{}%]",
                    taskstats_elapsed / 1_000_000,
                    iowait_elapsed * 100 / taskstats_elapsed,
                    vfs_acct * 100 / taskstats_elapsed,
                    futex_acct * 100 / taskstats_elapsed,
                    muxio_acct * 100 / taskstats_elapsed,
                    net_acct * 100 / taskstats_elapsed,
                    discovery_acct * 100 / taskstats_elapsed,
                    taskstats_acct * 100 / taskstats_elapsed,
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
        machine_id: u32,
    ) {
        let sample_rx = Self::start_timer_thread(terminate_flag.clone(), sample_interval);
        thread::Builder::new()
            .name("ts-collect".to_string())
            .spawn(move || {
                let mut taskstats =
                    TaskStatsIter::new(pid_map, pid_rb, &conn, pid_bus, machine_id)?;
                loop {
                    sample_rx.recv()?;
                    while sample_rx.try_recv().is_ok() {}
                    if *terminate_flag.lock().unwrap() {
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
                if *terminate_flag.lock().unwrap() {
                    break;
                }
                sample_tx.send(true).expect("Failed to send timer signal");
            })
            .expect("Failed to create ts-timer thread");
        sample_rx
    }
}
