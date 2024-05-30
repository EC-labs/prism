use eyre::{eyre, Result};
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
    time::Duration,
};

use crate::execute::{
    boot_to_epoch,
    programs::ipc::{IpcEvent, IpcProgram, TargetFile},
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
        match &event {
            IpcEvent::InodeWait { fs_type, .. } => {
                if &**fs_type == "sockfs" {
                    self.sockets.process_event(event)?;
                } else {
                    self.pipes.process_event(event)?;
                }
            }
            IpcEvent::AcceptEnd { .. } | IpcEvent::ConnectStart { .. } => {
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
        let (events, sample_instant_since_boot) =
            self.ipc_program.borrow_mut().take_tid_events(self.tid)?;
        let sample_instant_epoch_ns =
            sample_instant_since_boot.map(|instant| boot_to_epoch(instant as u128));

        self.sample_instant_ns = sample_instant_epoch_ns;

        for event in events {
            self.process_event(event)?;
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        let epoch_ns = if let Some(epoch_ns) = self.sample_instant_ns.take() {
            epoch_ns
        } else {
            return Ok(());
        };

        self.sockets.store(epoch_ns)?;
        self.pipes.store(epoch_ns)?;

        Ok(())
    }
}

struct Pipes {
    stream_map: HashMap<TargetFile, u64>,
    sum_stream_wait_ns: u64,
    last_terminated: HashSet<TargetFile>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
    active: HashMap<TargetFile, u64>,
}

impl Pipes {
    fn new(target_subdirectory: String) -> Self {
        Self {
            target_subdirectory,
            stream_map: HashMap::new(),
            sum_stream_wait_ns: 0,
            last_terminated: HashSet::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
            active: HashMap::new(),
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::InodeWait {
                sb_id,
                inode_id,
                total_interval_wait_ns,
                ..
            } => {
                let target_file = TargetFile::Inode {
                    device: sb_id,
                    inode_id,
                };
                let entry = self.stream_map.entry(target_file.clone()).or_insert(0);
                *entry += total_interval_wait_ns;
                self.sum_stream_wait_ns += total_interval_wait_ns;
                self.last_terminated.insert(target_file);
            }
            IpcEvent::EpollItemAdd {
                target_file,
                contrib_snapshot,
                ..
            }
            | IpcEvent::EpollItem {
                target_file,
                contrib_snapshot,
                ..
            } => {
                self.stream_map.entry(target_file.clone()).or_insert(0);
                self.active.insert(target_file, contrib_snapshot);
            }
            IpcEvent::EpollItemRemove {
                target_file,
                contrib_snapshot,
                ..
            } => {
                self.active.remove(&target_file).map(|add_snapshot| {
                    let entry = self.stream_map.entry(target_file.clone()).or_insert(0);
                    let diff = if (contrib_snapshot as i64 - add_snapshot as i64) < 0 {
                        contrib_snapshot
                    } else {
                        contrib_snapshot - add_snapshot
                    };
                    *entry += diff;
                    self.sum_stream_wait_ns += diff;
                    self.last_terminated.insert(target_file);
                });
            }
            IpcEvent::EpollWait {
                total_interval_wait_ns,
                ..
            } => {
                for (target, add_time) in self.active.iter_mut() {
                    self.last_terminated.insert(target.clone());
                    let entry = self.stream_map.entry(target.clone()).or_insert(0);
                    let contrib =
                        i64::max(total_interval_wait_ns as i64 - *add_time as i64, 0) as u64;
                    *entry += contrib;
                    self.sum_stream_wait_ns += contrib;
                    *add_time = 0;
                }
            }
            _ => {
                return Err(eyre!(format!("Expected pipe event. Got {:?}", event)));
            }
        }
        Ok(())
    }

    fn store(&mut self, epoch_ns: u128) -> Result<()> {
        if self.last_terminated.len() == 0 {
            return Ok(());
        }

        self.store_streams(epoch_ns)?;
        self.store_aggregated_stream(epoch_ns)?;
        Ok(())
    }

    fn store_streams(&mut self, epoch_ns: u128) -> Result<()> {
        let last_terminated = mem::replace(&mut self.last_terminated, HashSet::new());

        for target_file in last_terminated {
            let epoch_ms = epoch_ns / 1_000_000;
            let cumulative_wait = *self.stream_map.get(&target_file).unwrap_or(&0);

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
        let cumulative_wait = self.sum_stream_wait_ns;

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
    kfile_map: HashMap<KFile, u64>,
    last_terminated: HashSet<KFile>,
    active: HashMap<KFile, u64>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
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
            last_terminated: HashSet::new(),
            active: HashMap::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
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
            IpcEvent::InodeWait {
                sb_id,
                inode_id,
                total_interval_wait_ns,
                ..
            } => {
                let kfile = (sb_id, inode_id);
                let entry = self.kfile_map.entry(kfile).or_insert(0);
                *entry += total_interval_wait_ns;
                self.last_terminated.insert(kfile);
            }
            IpcEvent::EpollItemAdd {
                target_file,
                contrib_snapshot,
                ..
            }
            | IpcEvent::EpollItem {
                target_file,
                contrib_snapshot,
                ..
            } => {
                let kfile = match target_file {
                    TargetFile::Inode { device, inode_id } => (device, inode_id),
                    _ => {
                        return Err(eyre!("Unexpected target file"));
                    }
                };
                self.kfile_map.entry(kfile).or_insert(0);
                self.active.insert(kfile, contrib_snapshot);
            }
            IpcEvent::EpollItemRemove {
                target_file,
                contrib_snapshot,
                ..
            } => {
                let kfile = match target_file {
                    TargetFile::Inode { device, inode_id } => (device, inode_id),
                    _ => {
                        return Err(eyre!("Unexpected target file"));
                    }
                };
                self.active.remove(&kfile).map(|add_snapshot| {
                    let entry = self.kfile_map.entry(kfile).or_insert(0);
                    *entry += if (contrib_snapshot as i64 - add_snapshot as i64) < 0 {
                        contrib_snapshot
                    } else {
                        contrib_snapshot - add_snapshot
                    };
                    self.last_terminated.insert(kfile);
                });
            }
            IpcEvent::EpollWait {
                total_interval_wait_ns,
                ..
            } => {
                for (kfile, add_time) in self.active.iter_mut() {
                    self.last_terminated.insert(*kfile);
                    let entry = self.kfile_map.entry(*kfile).or_insert(0);
                    let contrib =
                        i64::max(total_interval_wait_ns as i64 - *add_time as i64, 0) as u64;
                    *entry += contrib;
                    *add_time = 0;
                }
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

        for kfile in kfiles {
            let cumulative_wait = *self.kfile_map.get(&kfile).unwrap_or(&0) as u128;
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
            | IpcEvent::EpollItem { fs, .. } => {
                if &**fs == "sockfs" {
                    self.sockets.process_event(event)?;
                } else {
                    self.pipes.process_event(event)?;
                }
            }
            IpcEvent::EpollWait { .. } => {
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
            | IpcEvent::EpollItem { event_poll, .. }
            | IpcEvent::EpollWait { event_poll, .. } => {
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
            IpcEvent::NewSocketMap {
                sb_id,
                inode_id,
                src_host,
                src_port,
                dst_host,
                dst_port,
                ..
            } => {
                self.kfile_socket_map.borrow_mut().insert(
                    (sb_id, inode_id),
                    ((src_host, src_port), Some((dst_host, dst_port))),
                );
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
        let (events, sample_instant_since_boot) =
            self.ipc_program.borrow_mut().take_global_events()?;

        let sample_instant_epoch_ns =
            sample_instant_since_boot.map(|instant| boot_to_epoch(instant as u128));
        self.sample_instant_ns = sample_instant_epoch_ns;

        for event in events {
            self.process_event(event)?;
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        let epoch_ns = if let Some(epoch_ns) = self.sample_instant_ns.take() {
            epoch_ns
        } else {
            return Ok(());
        };

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
