use eyre::{eyre, OptionExt, Result};
use lru_time_cache::LruCache;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::prelude::*,
    mem,
    net::Ipv4Addr,
    path::Path,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::execute::programs::{
    ipc::{IpcEvent, IpcProgram, TargetFile},
    BOOT_EPOCH_NS,
};

use super::Collect;
use super::ToCsv;

pub type KFile = (u32, u64);

pub struct Ipc {
    ipc_program: Rc<RefCell<IpcProgram>>,
    tid: usize,
    sample_instant_ns: Option<u128>,
    sockets: Sockets,
    pipes: Pipes,
}

impl Ipc {
    pub fn new(
        ipc_program: Rc<RefCell<IpcProgram>>,
        tid: usize,
        root_directory: Rc<str>,
        target_subdirectory: &str,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Socket>>>,
    ) -> Self {
        Self {
            ipc_program,
            tid,
            sample_instant_ns: None,
            sockets: Sockets::new(
                format!("{}/{}/ipc", root_directory, target_subdirectory),
                kfile_socket_map,
            ),
            pipes: Pipes::new(format!("{}/{}/ipc", root_directory, target_subdirectory)),
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::ReadStart { .. }
            | IpcEvent::ReadEnd { .. }
            | IpcEvent::WriteStart { .. }
            | IpcEvent::WriteEnd { .. } => {
                self.pipes.process_event(event)?;
            }
            IpcEvent::RecvStart { .. }
            | IpcEvent::RecvEnd { .. }
            | IpcEvent::SendStart { .. }
            | IpcEvent::SendEnd { .. } => {
                self.sockets.process_event(event)?;
            }
            _ => {
                return Err(eyre!(format!("Expected ipc event. Got {:?}", event)));
            }
        }

        Ok(())
    }
}

impl Collect for Ipc {
    fn sample(&mut self) -> Result<()> {
        let events = self.ipc_program.borrow_mut().take_tid_events(self.tid)?;

        let sample_instant = SystemTime::now();
        self.sample_instant_ns = Some(
            sample_instant
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_nanos(),
        );

        for event in events {
            self.process_event(event)?;
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        let epoch_ns = self
            .sample_instant_ns
            .take()
            .ok_or_eyre("Missing sample instant")?;

        self.sockets.store(epoch_ns)?;
        self.pipes.store(epoch_ns)?;

        Ok(())
    }
}

struct Pipes {
    stream_map: HashMap<TargetFile, u64>,
    sum_stream_wait_ns: u64,
    pending: HashMap<TargetFile, u64>,
    last_terminated: HashSet<TargetFile>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
    active: HashSet<TargetFile>,
    wait_depth: u32,
}

impl Pipes {
    fn new(target_subdirectory: String) -> Self {
        Self {
            target_subdirectory,
            stream_map: HashMap::new(),
            sum_stream_wait_ns: 0,
            pending: HashMap::new(),
            last_terminated: HashSet::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
            active: HashSet::new(),
            wait_depth: 0,
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::ReadStart {
                sb_id,
                inode_id,
                ns_since_boot,
                ..
            }
            | IpcEvent::WriteStart {
                sb_id,
                inode_id,
                ns_since_boot,
                ..
            } => {
                let target_file = TargetFile::Inode {
                    device: sb_id,
                    inode_id,
                };
                self.pending.insert(target_file, ns_since_boot);
            }
            IpcEvent::ReadEnd {
                sb_id,
                inode_id,
                ns_elapsed,
                ..
            }
            | IpcEvent::WriteEnd {
                sb_id,
                inode_id,
                ns_elapsed,
                ..
            } => {
                let target_file = TargetFile::Inode {
                    device: sb_id,
                    inode_id,
                };
                self.pending.remove(&target_file);
                let entry = self.stream_map.entry(target_file.clone()).or_insert(0);
                self.last_terminated.insert(target_file);
                *entry += ns_elapsed;
                self.sum_stream_wait_ns += ns_elapsed;
            }
            IpcEvent::EpollItemAdd {
                target_file,
                ns_since_boot,
                ..
            } => {
                if self.wait_depth > 0 {
                    self.pending
                        .entry(target_file.clone())
                        .or_insert(ns_since_boot);
                }
                self.stream_map.entry(target_file.clone()).or_insert(0);
                self.active.insert(target_file);
            }
            IpcEvent::EpollItemRemove {
                target_file,
                ns_since_boot,
                ..
            } => {
                if let Some(start_ns_since_boot) = self.pending.remove(&target_file) {
                    self.stream_map
                        .entry(target_file.clone())
                        .or_insert(ns_since_boot - start_ns_since_boot);
                }
                self.active.remove(&target_file);
            }
            IpcEvent::EpollWaitStart { ns_since_boot, .. } => {
                self.wait_depth += 1;
                for target_file in self.active.iter() {
                    self.pending
                        .entry(target_file.to_owned())
                        .or_insert(ns_since_boot);
                }
            }
            IpcEvent::EpollWaitEnd { ns_since_boot, .. } => {
                self.wait_depth = i64::max(self.wait_depth as i64 - 1, 0) as u32;
                if self.wait_depth > 0 {
                    return Ok(());
                }

                let pending = mem::replace(&mut self.pending, HashMap::new());
                for (target_file, start_ns_since_boot) in pending {
                    let entry = self.stream_map.entry(target_file.clone()).or_insert(0);
                    *entry += ns_since_boot - start_ns_since_boot;
                    self.sum_stream_wait_ns += ns_since_boot - start_ns_since_boot;
                    self.last_terminated.insert(target_file);
                }
            }
            IpcEvent::EpollItemReady { target_file, .. } => {
                self.stream_map.entry(target_file.clone()).or_insert(0);
                self.active.insert(target_file);
            }
            _ => {
                return Err(eyre!(format!("Expected pipe event. Got {:?}", event)));
            }
        }
        Ok(())
    }

    fn store(&mut self, epoch_ns: u128) -> Result<()> {
        if self.last_terminated.len() == 0 && self.pending.len() == 0 {
            return Ok(());
        }

        self.store_streams(epoch_ns)?;
        self.store_aggregated_stream(epoch_ns)?;
        Ok(())
    }

    fn store_streams(&mut self, epoch_ns: u128) -> Result<()> {
        let last_terminated = mem::replace(&mut self.last_terminated, HashSet::new());
        let keys = self.pending.keys().into_iter().map(|key| key.clone());
        let target_files = HashSet::from_iter(keys);
        let target_files = target_files.union(&last_terminated);

        for target_file in target_files {
            let epoch_ms = epoch_ns / 1_000_000;
            let pending = if let Some(ns_since_boot) = self.pending.get(target_file) {
                epoch_ns - (*BOOT_EPOCH_NS.read().unwrap() + *ns_since_boot as u128)
            } else {
                0
            };
            let cached_wait = *self.stream_map.get(&target_file).unwrap_or(&0);
            let cumulative_wait = pending as u64 + cached_wait;

            let sample = StreamFileSample {
                epoch_ms,
                cumulative_wait,
            };

            let file_path = match target_file {
                TargetFile::Inode { device, inode_id } => {
                    format!(
                        "{}/streams/{:?}/{:?}_{:?}.csv",
                        self.target_subdirectory,
                        (epoch_ms / (1000 * 60)) * 60,
                        device,
                        inode_id,
                    )
                }
                TargetFile::AnonInode { name, address } => {
                    format!(
                        "{}/streams/{:?}/{}_{:x}.csv",
                        self.target_subdirectory,
                        (epoch_ms / (1000 * 60)) * 60,
                        name,
                        address,
                    )
                }
            };

            let mut file = self.get_or_create_file(Path::new(&file_path), sample.csv_headers())?;
            file.write_all(sample.to_csv_row().as_bytes())?;
        }
        Ok(())
    }

    fn store_aggregated_stream(&mut self, epoch_ns: u128) -> Result<()> {
        let epoch_ms = epoch_ns / 1_000_000;
        let mut cumulative_wait = self.sum_stream_wait_ns;
        for (_, ns_since_boot) in self.pending.iter() {
            cumulative_wait +=
                (epoch_ns - (*BOOT_EPOCH_NS.read().unwrap() + *ns_since_boot as u128)) as u64;
        }
        let sample = StreamAggregatedSample {
            epoch_ms,
            cumulative_wait,
        };
        let file_path = format!(
            "{}/streams/{:?}/total.csv",
            self.target_subdirectory,
            (epoch_ms / (1000 * 60)) * 60,
        );
        let mut file = self.get_or_create_file(Path::new(&file_path), sample.csv_headers())?;
        file.write_all(sample.to_csv_row().as_bytes())?;
        Ok(())
    }

    fn get_or_create_file(&mut self, filepath: &Path, headers: &str) -> Result<&File> {
        let file = self.data_files.get(filepath.to_str().unwrap());
        if let None = file {
            let file = File::options().append(true).open(filepath);
            let file = match file {
                Err(_) => {
                    fs::create_dir_all(filepath.parent().unwrap())?;
                    let mut file = File::options().append(true).create(true).open(filepath)?;
                    file.write_all(headers.as_bytes())?;
                    file
                }
                Ok(file) => file,
            };
            self.data_files
                .insert(filepath.to_str().unwrap().into(), file);
        }

        let file = self.data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }
}

type Endpoint = (Ipv4Addr, u64);
type SrcEndpoint = Endpoint;
type DstEndpoint = Endpoint;
pub type Socket = (SrcEndpoint, Option<DstEndpoint>);

struct Sockets {
    kfile_socket_map: Rc<RefCell<HashMap<KFile, Socket>>>,
    pending: HashMap<KFile, u64>,
    kfile_map: HashMap<KFile, u64>,
    last_terminated: HashSet<KFile>,
    active: HashSet<KFile>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
    wait_depth: u32,
}

impl Sockets {
    fn new(
        target_subdirectory: String,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Socket>>>,
    ) -> Self {
        Self {
            kfile_socket_map,
            target_subdirectory,
            kfile_map: HashMap::new(),
            pending: HashMap::new(),
            last_terminated: HashSet::new(),
            active: HashSet::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
            wait_depth: 0,
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::ConnectStart {
                inode_id,
                sb_id,
                src_host,
                src_port,
                dst_host,
                dst_port,
                ..
            }
            | IpcEvent::AcceptEnd {
                inode_id,
                sb_id,
                src_host,
                src_port,
                dst_host,
                dst_port,
                ..
            } => {
                let kfile = (sb_id, inode_id);
                self.kfile_socket_map
                    .borrow_mut()
                    .entry(kfile)
                    .or_insert(((src_host, src_port), Some((dst_host, dst_port))));
            }
            IpcEvent::RecvStart {
                src_host,
                src_port,
                dst_host,
                dst_port,
                sb_id,
                inode_id,
                ns_since_boot,
                ..
            }
            | IpcEvent::SendStart {
                src_host,
                src_port,
                dst_host,
                dst_port,
                sb_id,
                inode_id,
                ns_since_boot,
                ..
            } => {
                let kfile = (sb_id, inode_id);
                self.kfile_socket_map
                    .borrow_mut()
                    .entry(kfile)
                    .or_insert(((src_host, src_port), Some((dst_host, dst_port))));
                self.pending.insert(kfile, ns_since_boot);
            }
            IpcEvent::RecvEnd { ns_elapsed, .. } | IpcEvent::SendEnd { ns_elapsed, .. } => {
                let pending = mem::replace(&mut self.pending, HashMap::new());
                for (kfile, _) in pending {
                    let entry = self.kfile_map.entry(kfile).or_insert(0);
                    *entry += ns_elapsed;
                    self.last_terminated.insert(kfile);
                }
            }
            IpcEvent::EpollItemAdd {
                target_file,
                ns_since_boot,
                ..
            } => {
                let kfile = match target_file {
                    TargetFile::Inode { device, inode_id } => (device, inode_id),
                    _ => {
                        return Err(eyre!("Unexpected target file"));
                    }
                };
                if self.wait_depth > 0 {
                    self.pending.entry(kfile).or_insert(ns_since_boot);
                }
                self.kfile_map.entry(kfile).or_insert(0);
                self.active.insert(kfile);
            }
            IpcEvent::EpollItemRemove {
                target_file,
                ns_since_boot,
                ..
            } => {
                let kfile = match target_file {
                    TargetFile::Inode { device, inode_id } => (device, inode_id),
                    _ => {
                        return Err(eyre!("Unexpected target file"));
                    }
                };
                if let Some(start_ns_since_boot) = self.pending.remove(&kfile) {
                    self.kfile_map
                        .entry(kfile.clone())
                        .or_insert(ns_since_boot - start_ns_since_boot);
                }
                self.active.remove(&kfile);
            }
            IpcEvent::EpollWaitStart { ns_since_boot, .. } => {
                self.wait_depth += 1;
                for kfile in self.active.iter() {
                    self.pending
                        .entry(kfile.to_owned())
                        .or_insert(ns_since_boot);
                }
            }
            IpcEvent::EpollWaitEnd { ns_since_boot, .. } => {
                self.wait_depth = i64::max(self.wait_depth as i64 - 1, 0) as u32;
                if self.wait_depth > 0 {
                    return Ok(());
                }

                let pending = mem::replace(&mut self.pending, HashMap::new());
                for (kfile, start_ns_since_boot) in pending {
                    let entry = self.kfile_map.entry(kfile).or_insert(0);
                    *entry += ns_since_boot - start_ns_since_boot;
                    self.last_terminated.insert(kfile);
                }
            }
            IpcEvent::EpollItemReady { target_file, .. } => {
                match target_file {
                    TargetFile::Inode { device, inode_id } => {
                        let kfile = (device, inode_id);
                        self.kfile_map.entry(kfile).or_insert(0);
                        self.active.insert(kfile);
                    }
                    _ => {
                        return Err(eyre!("Unexpected target file"));
                    }
                };
            }
            _ => {
                return Err(eyre!(format!("Expected socket event. Got {:?}", event)));
            }
        }

        Ok(())
    }

    fn get_or_create_file(&mut self, filepath: &Path, headers: &str) -> Result<&File> {
        let file = self.data_files.get(filepath.to_str().unwrap());
        if let None = file {
            let file = File::options().append(true).open(filepath);
            let file = match file {
                Err(_) => {
                    fs::create_dir_all(filepath.parent().unwrap())?;
                    let mut file = File::options().append(true).create(true).open(filepath)?;
                    file.write_all(headers.as_bytes())?;
                    file
                }
                Ok(file) => file,
            };
            self.data_files
                .insert(filepath.to_str().unwrap().into(), file);
        }

        let file = self.data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }

    fn store(&mut self, epoch_ns: u128) -> Result<()> {
        let epoch_ms = epoch_ns / 1_000_000;
        let kfiles = mem::replace(&mut self.last_terminated, HashSet::new());
        let keys = HashSet::from_iter(self.pending.keys().map(|key| key.to_owned()));
        let kfiles = kfiles.union(&keys);

        for kfile in kfiles {
            let mut cumulative_wait = self
                .pending
                .get(&kfile)
                .map(|ns_since_boot| {
                    epoch_ns - (*BOOT_EPOCH_NS.read().unwrap() + *ns_since_boot as u128)
                })
                .unwrap_or(0);
            cumulative_wait += *self.kfile_map.get(&kfile).unwrap_or(&0) as u128;
            let sample = SocketSample {
                epoch_ms,
                cumulative_wait,
            };

            let file_path =
                if let Some((src, Some(dst))) = self.kfile_socket_map.borrow().get(&kfile) {
                    format!(
                        "{}/sockets/{:?}/{}:{:?}_{}:{:?}.csv",
                        self.target_subdirectory,
                        (epoch_ms / (1000 * 60)) * 60,
                        src.0.octets().map(|elem| elem.to_string()).join("."),
                        src.1,
                        dst.0.octets().map(|elem| elem.to_string()).join("."),
                        dst.1,
                    )
                } else {
                    continue;
                };
            let mut file = self.get_or_create_file(Path::new(&file_path), sample.csv_headers())?;
            file.write_all(sample.to_csv_row().as_bytes())?;
        }

        Ok(())
    }
}

struct EventPoll {
    sockets: Sockets,
    pipes: Pipes,
}

impl EventPoll {
    fn new(
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Socket>>>,
        data_directory: Rc<str>,
        address: u64,
    ) -> Self {
        Self {
            sockets: Sockets::new(
                format!("{}/{:x}", data_directory, address),
                kfile_socket_map,
            ),
            pipes: Pipes::new(format!("{}/{:x}", data_directory, address)),
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match &event {
            IpcEvent::EpollItemAdd { fs, .. }
            | IpcEvent::EpollItemRemove { fs, .. }
            | IpcEvent::EpollItemReady { fs, .. } => {
                if &**fs == "sockfs" {
                    self.sockets.process_event(event)?;
                } else {
                    self.pipes.process_event(event)?;
                }
            }
            IpcEvent::EpollWaitStart { .. } | IpcEvent::EpollWaitEnd { .. } => {
                self.sockets.process_event(event.clone())?;
                self.pipes.process_event(event)?;
            }
            _ => {
                return Err(eyre!(format!("Expected epoll event. Got {:?}", event)));
            }
        }
        Ok(())
    }

    fn store(&mut self, sample_instant_ns: u128) -> Result<()> {
        self.sockets.store(sample_instant_ns)?;
        self.pipes.store(sample_instant_ns)
    }
}

pub struct EventPollCollection {
    event_poll_map: HashMap<u64, EventPoll>,
    ipc_program: Rc<RefCell<IpcProgram>>,
    kfile_socket_map: Rc<RefCell<HashMap<KFile, Socket>>>,
    root_directory: Rc<str>,
    sample_instant_ns: Option<u128>,
}

impl EventPollCollection {
    pub fn new(
        ipc_program: Rc<RefCell<IpcProgram>>,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Socket>>>,
        root_directory: Rc<str>,
    ) -> Self {
        Self {
            ipc_program,
            kfile_socket_map,
            root_directory: Rc::from(format!("{}/epoll", root_directory)),
            event_poll_map: HashMap::new(),
            sample_instant_ns: None,
        }
    }

    pub fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::EpollItemAdd { event_poll, .. }
            | IpcEvent::EpollItemRemove { event_poll, .. }
            | IpcEvent::EpollItemReady { event_poll, .. }
            | IpcEvent::EpollWaitStart { event_poll, .. }
            | IpcEvent::EpollWaitEnd { event_poll, .. } => {
                let event_poll = self
                    .event_poll_map
                    .entry(event_poll)
                    .or_insert(EventPoll::new(
                        self.kfile_socket_map.clone(),
                        self.root_directory.clone(),
                        event_poll,
                    ));
                event_poll.process_event(event)?;
            }
            _ => {
                return Err(eyre!(format!("Expected epoll event. Got {:?}", event)));
            }
        }

        Ok(())
    }
}

impl Collect for EventPollCollection {
    fn sample(&mut self) -> Result<()> {
        let events = self.ipc_program.borrow_mut().take_epoll_events()?;

        let sample_instant = SystemTime::now();
        self.sample_instant_ns = Some(
            sample_instant
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_nanos(),
        );

        for event in events {
            self.process_event(event)?;
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        let epoch_ns = self
            .sample_instant_ns
            .take()
            .ok_or_eyre("Missing sample instant")?;

        for (_, epoll) in self.event_poll_map.iter_mut() {
            epoll.store(epoch_ns)?
        }
        Ok(())
    }
}

struct SocketSample {
    epoch_ms: u128,
    cumulative_wait: u128,
}

impl ToCsv for SocketSample {
    fn to_csv_row(&self) -> String {
        format!("{},{}\n", self.epoch_ms, self.cumulative_wait)
    }

    fn csv_headers(&self) -> &'static str {
        "epoch_ms,socket_wait\n"
    }
}

struct StreamAggregatedSample {
    epoch_ms: u128,
    cumulative_wait: u64,
}

impl ToCsv for StreamAggregatedSample {
    fn csv_headers(&self) -> &'static str {
        "epoch_ms,stream_wait\n"
    }

    fn to_csv_row(&self) -> String {
        format!("{},{}\n", self.epoch_ms, self.cumulative_wait)
    }
}

struct StreamFileSample {
    epoch_ms: u128,
    cumulative_wait: u64,
}

impl ToCsv for StreamFileSample {
    fn to_csv_row(&self) -> String {
        format!("{},{}\n", self.epoch_ms, self.cumulative_wait)
    }

    fn csv_headers(&self) -> &'static str {
        "epoch_ms,stream_wait\n"
    }
}
