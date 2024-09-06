use eyre::{eyre, Result};
use lru_time_cache::LruCache;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    io::prelude::*,
    path::Path,
    rc::Rc,
    time::Duration,
};

use crate::execute::{
    boot_to_epoch,
    programs::ipc::{Connection, IpcEvent, IpcProgram, TargetFile},
};

use super::Collect;
use super::ToCsv;

pub type KFile = (u32, u64);

pub struct Ipc {
    ipc_program: Rc<RefCell<IpcProgram>>,
    tid: usize,
    sockets: Sockets,
    pipes: Pipes,
}

impl Ipc {
    pub fn new(
        ipc_program: Rc<RefCell<IpcProgram>>,
        tid: usize,
        root_directory: Rc<str>,
        target_subdirectory: &str,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
    ) -> Self {
        Self {
            ipc_program,
            tid,
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
            IpcEvent::AcceptEnd { .. } | IpcEvent::ConnectEnd { .. } => {
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

        for event in events {
            self.process_event(event)?;
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        self.sockets.store()?;
        self.pipes.store()?;

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stats {
    accumulated_wait: u64,
    count: u64,
}

struct Pipes {
    stream_stats_map: HashMap<TargetFile, Stats>,
    snapshots: HashMap<TargetFile, VecDeque<(Option<u64>, Stats)>>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
    active: HashMap<TargetFile, u64>,
}

impl Pipes {
    fn new(target_subdirectory: String) -> Self {
        Self {
            target_subdirectory,
            stream_stats_map: HashMap::new(),
            snapshots: HashMap::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
            active: HashMap::new(),
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::InodeWait {
                fs_type,
                sb_id,
                inode_id,
                sample_instant_ns,
                total_interval_wait_ns,
                count_wait,
                ..
            } => {
                let sample_instant_epoch_ns = boot_to_epoch(sample_instant_ns as u128);
                let target_file = match &*fs_type {
                    "epoll" => TargetFile::Epoll {
                        address: u64::from_ne_bytes((inode_id as i64).to_ne_bytes()),
                    },
                    _ => TargetFile::Inode {
                        device: sb_id,
                        inode_id: inode_id as u64,
                    },
                };
                let stat = self
                    .stream_stats_map
                    .entry(target_file.clone())
                    .or_insert(Stats {
                        accumulated_wait: 0,
                        count: 0,
                    });
                stat.accumulated_wait += total_interval_wait_ns;
                stat.count = count_wait.unwrap_or(0);
                let snapshots = self
                    .snapshots
                    .entry(target_file)
                    .or_insert_with(|| VecDeque::new());
                snapshots.push_back((Some(sample_instant_epoch_ns as u64), stat.clone()));
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
                self.stream_stats_map
                    .entry(target_file.clone())
                    .or_insert(Stats {
                        accumulated_wait: 0,
                        count: 0,
                    });
                self.active.insert(target_file, contrib_snapshot);
            }
            IpcEvent::EpollItemRemove {
                target_file,
                contrib_snapshot,
                ..
            } => {
                self.active.remove(&target_file).map(|add_snapshot| {
                    let stat = self
                        .stream_stats_map
                        .entry(target_file.clone())
                        .or_insert(Stats {
                            accumulated_wait: 0,
                            count: 0,
                        });
                    let diff = if (contrib_snapshot as i64 - add_snapshot as i64) < 0 {
                        contrib_snapshot
                    } else {
                        contrib_snapshot - add_snapshot
                    };
                    stat.accumulated_wait += diff;
                    let snapshots = self
                        .snapshots
                        .entry(target_file)
                        .or_insert_with(|| VecDeque::new());
                    match snapshots.back_mut() {
                        Some((None, stat)) => {
                            *stat = stat.clone();
                        }
                        Some((Some(_), _)) | None => {
                            snapshots.push_back((None, stat.clone()));
                        }
                    }
                });
            }
            IpcEvent::EpollWait {
                total_interval_wait_ns,
                sample_instant_ns,
                ..
            } => {
                let sample_instant_epoch_ns = boot_to_epoch(sample_instant_ns as u128);

                for (target, add_time) in self.active.iter_mut() {
                    self.snapshots.entry(target.clone());
                    let stat = self
                        .stream_stats_map
                        .entry(target.clone())
                        .or_insert(Stats {
                            accumulated_wait: 0,
                            count: 0,
                        });
                    let contrib =
                        i64::max(total_interval_wait_ns as i64 - *add_time as i64, 0) as u64;
                    stat.accumulated_wait += contrib;
                    *add_time = 0;

                    let snapshots = self
                        .snapshots
                        .entry(target.clone())
                        .or_insert_with(|| VecDeque::new());
                    match snapshots.back_mut() {
                        Some((Some(_), _)) | None => {
                            snapshots
                                .push_back((Some(sample_instant_epoch_ns as u64), stat.clone()));
                        }
                        Some(snapshot) => {
                            *snapshot = (Some(sample_instant_epoch_ns as u64), stat.clone());
                        }
                    }
                }

                let snapshot_keys: HashSet<TargetFile> =
                    HashSet::from_iter(self.snapshots.keys().map(|key| key.clone()));
                let active_keys = HashSet::from_iter(self.active.keys().map(|key| key.clone()));
                let remaining = snapshot_keys.difference(&active_keys);
                for kfile in remaining {
                    let snapshots = self.snapshots.get_mut(kfile).unwrap();
                    let last = snapshots.back_mut().expect("Contain an element");
                    if let None = last.0 {
                        last.0 = Some(sample_instant_epoch_ns as u64);
                    }
                }
            }
            _ => {
                return Err(eyre!(format!("Expected pipe event. Got {:?}", event)));
            }
        }
        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        if self.snapshots.len() == 0 {
            return Ok(());
        }

        self.store_streams()?;
        Ok(())
    }

    fn store_streams(&mut self) -> Result<()> {
        let mut remove = Vec::new();

        for (target_file, snapshots) in self.snapshots.iter_mut() {
            while let Some(snapshot) = snapshots.pop_front() {
                let (epoch_ms, stat) = if let Some(epoch_ns) = snapshot.0 {
                    (epoch_ns / 1_000_000, snapshot.1)
                } else {
                    snapshots.push_front(snapshot);
                    break;
                };

                let sample = StreamFileSample {
                    epoch_ms: epoch_ms as u128,
                    cumulative_wait: stat.accumulated_wait,
                    count: stat.count,
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
                    TargetFile::Epoll { address } => {
                        format!(
                            "{}/streams/{:?}/epoll_{:x}.csv",
                            self.target_subdirectory,
                            (epoch_ms / (1000 * 60)) * 60,
                            address,
                        )
                    }
                };

                let mut file = Self::get_or_create_file(
                    &mut self.data_files,
                    Path::new(&file_path),
                    sample.csv_headers(),
                )?;
                file.write_all(sample.to_csv_row().as_bytes())?;
            }

            if snapshots.len() == 0 {
                remove.push(target_file.clone());
            }
        }
        remove.into_iter().for_each(|kfile| {
            self.snapshots.remove(&kfile);
        });

        Ok(())
    }

    fn get_or_create_file<'a>(
        data_files: &'a mut LruCache<String, File>,
        filepath: &Path,
        headers: &str,
    ) -> Result<&'a File> {
        let file = data_files.get(filepath.to_str().unwrap());
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
            data_files.insert(filepath.to_str().unwrap().into(), file);
        }

        let file = data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }
}

struct Sockets {
    kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
    kfile_stats_map: HashMap<KFile, Stats>,
    snapshots: HashMap<KFile, VecDeque<(Option<u64>, Stats)>>,
    active: HashMap<KFile, u64>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
}

impl Sockets {
    fn new(
        target_subdirectory: String,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
    ) -> Self {
        Self {
            kfile_socket_map,
            target_subdirectory,
            kfile_stats_map: HashMap::new(),
            snapshots: HashMap::new(),
            active: HashMap::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::ConnectEnd {
                inode_id,
                sb_id,
                conn,
                ..
            }
            | IpcEvent::AcceptEnd {
                inode_id,
                sb_id,
                conn,
                ..
            } => {
                let kfile = (sb_id, inode_id);
                self.kfile_socket_map
                    .borrow_mut()
                    .entry(kfile)
                    .or_insert(conn);
            }
            IpcEvent::InodeWait {
                sb_id,
                inode_id,
                sample_instant_ns,
                total_interval_wait_ns,
                count_wait,
                ..
            } => {
                let sample_instant_epoch_ns = boot_to_epoch(sample_instant_ns as u128);
                let kfile = (sb_id, inode_id as u64);
                let stat = self.kfile_stats_map.entry(kfile).or_insert(Stats {
                    accumulated_wait: 0,
                    count: 0,
                });
                stat.accumulated_wait += total_interval_wait_ns;
                stat.count = count_wait.unwrap_or(0);
                let snapshots = self
                    .snapshots
                    .entry(kfile)
                    .or_insert_with(|| VecDeque::new());
                snapshots.push_back((Some(sample_instant_epoch_ns as u64), stat.clone()));
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
                self.kfile_stats_map.entry(kfile).or_insert(Stats {
                    accumulated_wait: 0,
                    count: 0,
                });
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
                    let stat = self.kfile_stats_map.entry(kfile).or_insert(Stats {
                        accumulated_wait: 0,
                        count: 0,
                    });
                    let contrib = if (contrib_snapshot as i64 - add_snapshot as i64) < 0 {
                        contrib_snapshot
                    } else {
                        contrib_snapshot - add_snapshot
                    };
                    if contrib > 1_500_000_000 {
                        println!(
                            "Unexpected remove contrib size. {:?} {:?}",
                            contrib_snapshot, add_snapshot
                        );
                    }
                    stat.accumulated_wait += contrib;
                    let snapshots = self
                        .snapshots
                        .entry(kfile)
                        .or_insert_with(|| VecDeque::new());
                    match snapshots.back_mut() {
                        Some((None, stat)) => {
                            *stat = stat.clone();
                        }
                        Some((Some(_), _)) | None => {
                            snapshots.push_back((None, stat.clone()));
                        }
                    }
                });
            }
            IpcEvent::EpollWait {
                total_interval_wait_ns,
                sample_instant_ns,
                ..
            } => {
                let sample_instant_epoch_ns = boot_to_epoch(sample_instant_ns as u128);

                for (kfile, add_time) in self.active.iter_mut() {
                    let stat = self.kfile_stats_map.entry(*kfile).or_insert(Stats {
                        accumulated_wait: 0,
                        count: 0,
                    });
                    let contrib =
                        i64::max(total_interval_wait_ns as i64 - *add_time as i64, 0) as u64;
                    if contrib > 1_500_000_000 {
                        println!("Unexpected epoll wait contrib size. {:?}", event);
                    }
                    stat.accumulated_wait += contrib;
                    *add_time = 0;

                    let snapshots = self
                        .snapshots
                        .entry(*kfile)
                        .or_insert_with(|| VecDeque::new());
                    match snapshots.back_mut() {
                        Some((Some(_), _)) | None => {
                            snapshots
                                .push_back((Some(sample_instant_epoch_ns as u64), stat.clone()));
                        }
                        Some(snapshot) => {
                            *snapshot = (Some(sample_instant_epoch_ns as u64), stat.clone());
                        }
                    }
                }

                let snapshot_keys: HashSet<(u32, u64)> =
                    HashSet::from_iter(self.snapshots.keys().map(|key| key.clone()));
                let active_keys = HashSet::from_iter(self.active.keys().map(|key| key.clone()));
                let remaining = snapshot_keys.difference(&active_keys);
                for kfile in remaining {
                    let snapshots = self.snapshots.get_mut(kfile).unwrap();
                    let last = snapshots.back_mut().expect("Contain an element");
                    if let None = last.0 {
                        last.0 = Some(sample_instant_epoch_ns as u64);
                    }
                }
            }
            _ => {
                return Err(eyre!(format!("Expected socket event. Got {:?}", event)));
            }
        }

        Ok(())
    }

    fn rename<'a>(
        data_files: &'a mut LruCache<String, File>,
        old: &Path,
        new: &Path,
    ) -> Result<()> {
        let old = old.to_str().unwrap().into();
        let new = new.to_str().unwrap().into();

        let file = data_files.remove(old);
        if let Some(file) = file {
            fs::rename(&old, &new)?;
            data_files.insert(new, file);
        }
        Ok(())
    }

    fn get_or_create_file<'a>(
        data_files: &'a mut LruCache<String, File>,
        filepath: &Path,
        headers: &str,
    ) -> Result<&'a File> {
        let file = data_files.get(filepath.to_str().unwrap());
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
            data_files.insert(filepath.to_str().unwrap().into(), file);
        }

        let file = data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }

    fn store(&mut self) -> Result<()> {
        let mut remove = Vec::new();

        for (kfile, snapshots) in self.snapshots.iter_mut() {
            while let Some(snapshot) = snapshots.pop_front() {
                let (epoch_ms, stat) = if let Some(epoch_ns) = snapshot.0 {
                    (epoch_ns / 1_000_000, snapshot.1)
                } else {
                    snapshots.push_front(snapshot);
                    break;
                };

                let sample = SocketSample {
                    epoch_ms: epoch_ms as u128,
                    cumulative_wait: stat.accumulated_wait,
                    count: stat.count,
                };
                let kfile_path = format!(
                    "{}/sockets/{:?}/{}_{}.csv",
                    self.target_subdirectory,
                    (epoch_ms / (1000 * 60)) * 60,
                    kfile.0,
                    kfile.1,
                );
                let file_path = match self.kfile_socket_map.borrow().get(&kfile) {
                    Some(Connection::Ipv4 {
                        src_host,
                        src_port,
                        dst_host,
                        dst_port,
                    }) => format!(
                        "{}/sockets/{:?}/ipv4_{}:{}_{}:{}.csv",
                        self.target_subdirectory,
                        (epoch_ms / (1000 * 60)) * 60,
                        src_host.octets().map(|elem| elem.to_string()).join("."),
                        src_port,
                        dst_host.octets().map(|elem| elem.to_string()).join("."),
                        dst_port,
                    ),
                    Some(Connection::Ipv6 {
                        src_host,
                        src_port,
                        dst_host,
                        dst_port,
                    }) => format!(
                        "{}/sockets/{:?}/ipv6_[{}]:{}_[{}]:{}.csv",
                        self.target_subdirectory,
                        (epoch_ms / (1000 * 60)) * 60,
                        src_host
                            .segments()
                            .map(|elem| format!("{:x}", elem))
                            .join(":"),
                        src_port,
                        dst_host
                            .segments()
                            .map(|elem| format!("{:x}", elem))
                            .join(":"),
                        dst_port,
                    ),
                    Some(Connection::Unix {
                        src_address,
                        dst_address,
                    }) => format!(
                        "{}/sockets/{:?}/unix_{:#x}_{:#x}.csv",
                        self.target_subdirectory,
                        (epoch_ms / (1000 * 60)) * 60,
                        src_address,
                        dst_address
                    ),
                    _ => format!(
                        "{}/sockets/{:?}/{}_{}.csv",
                        self.target_subdirectory,
                        (epoch_ms / (1000 * 60)) * 60,
                        kfile.0,
                        kfile.1,
                    ),
                };

                if kfile_path != file_path {
                    Self::rename(
                        &mut self.data_files,
                        Path::new(&kfile_path),
                        Path::new(&file_path),
                    )?;
                }

                let mut file = Self::get_or_create_file(
                    &mut self.data_files,
                    Path::new(&file_path),
                    sample.csv_headers(),
                )?;
                file.write_all(sample.to_csv_row().as_bytes())?;
            }

            if snapshots.len() == 0 {
                remove.push(*kfile);
            }
        }

        remove.into_iter().for_each(|kfile| {
            self.snapshots.remove(&kfile);
        });

        Ok(())
    }
}

struct EventPoll {
    sockets: Sockets,
    pipes: Pipes,
}

impl EventPoll {
    fn new(
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
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

    fn store(&mut self) -> Result<()> {
        self.sockets.store()?;
        self.pipes.store()
    }
}

pub struct EventPollCollection {
    event_poll_map: HashMap<u64, EventPoll>,
    ipc_program: Rc<RefCell<IpcProgram>>,
    kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
    root_directory: Rc<str>,
}

impl EventPollCollection {
    pub fn new(
        ipc_program: Rc<RefCell<IpcProgram>>,
        kfile_socket_map: Rc<RefCell<HashMap<KFile, Connection>>>,
        root_directory: Rc<str>,
    ) -> Self {
        Self {
            ipc_program,
            kfile_socket_map,
            root_directory: Rc::from(format!("{}/global/epoll", root_directory)),
            event_poll_map: HashMap::new(),
        }
    }

    pub fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::EpollItemAdd { event_poll, .. }
            | IpcEvent::EpollItemRemove { event_poll, .. }
            | IpcEvent::EpollItem { event_poll, .. }
            | IpcEvent::EpollWait { event_poll, .. } => {
                let event_poll = self.event_poll_map.entry(event_poll).or_insert_with(|| {
                    EventPoll::new(
                        self.kfile_socket_map.clone(),
                        self.root_directory.clone(),
                        event_poll,
                    )
                });
                event_poll.process_event(event)?;
            }
            IpcEvent::NewSocketMap {
                sb_id,
                inode_id,
                conn,
                ..
            } => {
                self.kfile_socket_map
                    .borrow_mut()
                    .insert((sb_id, inode_id), conn);
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
        let events = self.ipc_program.borrow_mut().take_global_events()?;

        for event in events {
            self.process_event(event)?;
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        for (_, epoll) in self.event_poll_map.iter_mut() {
            epoll.store()?
        }
        Ok(())
    }
}

struct SocketSample {
    epoch_ms: u128,
    cumulative_wait: u64,
    count: u64,
}

impl ToCsv for SocketSample {
    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{}\n",
            self.epoch_ms, self.cumulative_wait, self.count
        )
    }

    fn csv_headers(&self) -> &'static str {
        "epoch_ms,socket_wait,count\n"
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
    count: u64,
}

impl ToCsv for StreamFileSample {
    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{}\n",
            self.epoch_ms, self.cumulative_wait, self.count
        )
    }

    fn csv_headers(&self) -> &'static str {
        "epoch_ms,stream_wait,count\n"
    }
}

#[cfg(test)]
mod tests {
    use eyre::Result;
    use indoc::indoc;
    use std::{
        cell::RefCell,
        collections::HashMap,
        env::temp_dir,
        fs,
        io::prelude::*,
        rc::Rc,
        sync::{Arc, Mutex},
    };

    use crate::{
        execute::programs::{
            ipc::{IpcProgram, TargetFile},
            pipe,
        },
        metrics::{
            ipc::{EventPollCollection, Ipc, Stats},
            Collect,
        },
    };

    mod ipc_sockets {
        use super::*;

        #[test]
        fn socket_two_consecutive_inode_samples() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t90098\tAF_INET\t127.0.0.1\t7878\t127.0.0.1\t50058
                AcceptEnd\texample-applica\t24239\tsockfs\t8\t90098\tAF_INET\t127.0.0.1\t7878\t127.0.0.1\t50058\t19446862145009

                => start map statistics
                @inode_map[example-applica, 24239, sockfs, 8, 90098]: (2848, 1)

                SampleInstant\t19447107025962
                => end map statistics

                => start map statistics
                @inode_map[example-applica, 24239, sockfs, 8, 90098]: (43106, 1)

                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let tmp_dir = temp_dir();
            let mut ipc = Ipc::new(
                ipc_program.clone(),
                24239,
                Rc::from(tmp_dir.to_str().unwrap()),
                "thread/24239/24239",
                Rc::new(RefCell::new(HashMap::new())),
            );

            ipc.sample()?;

            let snapshots = ipc.sockets.snapshots.remove(&(8, 90098));
            assert!(snapshots.is_some());

            let mut snapshots = snapshots.unwrap();
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: 2848,
                        count: 1
                    }
                ))
            );
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19448107034740),
                    Stats {
                        accumulated_wait: 2848 + 43106,
                        count: 1
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn store_snapshots() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t90098\tAF_INET\t127.0.0.1\t7878\t127.0.0.1\t50058
                AcceptEnd\texample-applica\t24239\tsockfs\t8\t90098\tAF_INET\t127.0.0.1\t7878\t127.0.0.1\t50058\t19446862145009

                => start map statistics
                @inode_map[example-applica, 24239, sockfs, 8, 90098]: (2848, 1)

                SampleInstant\t19447107025962
                => end map statistics

                => start map statistics
                @inode_map[example-applica, 24239, sockfs, 8, 90098]: (43106, 1)

                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let tmp_dir = tempdir::TempDir::new("")?;
            let mut ipc = Ipc::new(
                ipc_program.clone(),
                24239,
                Rc::from(tmp_dir.path().to_str().unwrap()),
                "thread/24239/24239",
                Rc::new(RefCell::new(HashMap::new())),
            );

            ipc.sample()?;
            ipc.store()?;
            assert!(ipc.sockets.snapshots.len() == 0);

            let contents = fs::read_to_string(format!(
                "{}/thread/24239/24239/ipc/sockets/19440/ipv4_127.0.0.1:7878_127.0.0.1:50058.csv",
                tmp_dir.path().to_str().unwrap()
            ))?;
            assert_eq!(
                indoc! {"
                epoch_ms,socket_wait,count
                19447107,2848,1
                19448107,45954,1
            "},
                contents
            );

            Ok(())
        }
    }

    mod ipc_pipes {
        use super::*;

        #[test]
        fn socket_two_consecutive_inode_samples() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                AcceptEnd\texample-applica\t24239\tdevpts\t8\t90098\tAF_INET\t127.0.0.1\t7878\t127.0.0.1\t50058\t19446862145009

                => start map statistics
                @inode_map[example-applica, 24239, devpts, 8, 90098]: (2848, 1)

                SampleInstant\t19447107025962
                => end map statistics

                => start map statistics
                @inode_map[example-applica, 24239, devpts, 8, 90098]: (43106, 1)

                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let tmp_dir = temp_dir();
            let mut ipc = Ipc::new(
                ipc_program.clone(),
                24239,
                Rc::from(tmp_dir.to_str().unwrap()),
                "thread/24239/24239",
                Rc::new(RefCell::new(HashMap::new())),
            );

            ipc.sample()?;

            let snapshots = ipc.pipes.snapshots.remove(&TargetFile::Inode {
                device: 8,
                inode_id: 90098,
            });
            assert!(snapshots.is_some());

            let mut snapshots = snapshots.unwrap();
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: 2848,
                        count: 1
                    }
                ))
            );
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19448107034740),
                    Stats {
                        accumulated_wait: 2848 + 43106,
                        count: 1
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn store_snapshots() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                AcceptEnd\texample-applica\t24239\tdevpts\t8\t90098\tAF_INET\t127.0.0.1\t7878\t127.0.0.1\t50058\t19446862145009

                => start map statistics
                @inode_map[example-applica, 24239, devpts, 8, 90098]: (2848, 1)

                SampleInstant\t19447107025962
                => end map statistics

                => start map statistics
                @inode_map[example-applica, 24239, devpts, 8, 90098]: (43106, 1)

                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let tmp_dir = tempdir::TempDir::new("")?;
            let mut ipc = Ipc::new(
                ipc_program.clone(),
                24239,
                Rc::from(tmp_dir.path().to_str().unwrap()),
                "thread/24239/24239",
                Rc::new(RefCell::new(HashMap::new())),
            );

            ipc.sample()?;
            ipc.store()?;

            assert!(ipc.pipes.snapshots.len() == 0);

            let contents = fs::read_to_string(format!(
                "{}/thread/24239/24239/ipc/streams/19440/8_90098.csv",
                tmp_dir.path().to_str().unwrap()
            ))?;
            assert_eq!(
                indoc! {"
                    epoch_ms,stream_wait,count
                    19447107,2848,1
                    19448107,45954,1
                "},
                contents
            );

            Ok(())
        }
    }

    mod eventpoll_sockets {
        use super::*;

        #[test]
        fn socket_empty_snapshot() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t80672\t127.0.0.1\t50046\t127.0.0.1\t7878
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.sockets.snapshots.remove(&(8, 80672));
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 1);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    None,
                    Stats {
                        accumulated_wait: 578800067,
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn socket_filled_snapshot() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t80672\t127.0.0.1\t50046\t127.0.0.1\t7878
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.sockets.snapshots.remove(&(8, 80672));
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 1);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: 578800067,
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn remove_and_add_active_socket() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t80672\t127.0.0.1\t50046\t127.0.0.1\t7878
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.sockets.snapshots.remove(&(8, 80672));
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 1);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291) + (289679399 - 200000000),
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn two_consecutive_bpf_samples_last_pending() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t80672\t127.0.0.1\t50046\t127.0.0.1\t7878
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.sockets.snapshots.remove(&(8, 80672));
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 2);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291) + (289679399 - 200000000),
                        count: 0,
                    }
                ))
            );
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    None,
                    Stats {
                        accumulated_wait: (1016301358 - 437501291)
                            + (289679399 - 200000000)
                            + (1016301358 - 437501291),
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn two_consecutive_bpf_samples() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t80672\t127.0.0.1\t50046\t127.0.0.1\t7878
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 914973709
                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.sockets.snapshots.remove(&(8, 80672));
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 2);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291) + (289679399 - 200000000),
                        count: 0,
                    }
                ))
            );
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19448107034740),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291)
                            + (289679399 - 200000000)
                            + (1016301358 - 437501291),
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn two_consecutive_bpf_samples_store() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                NewSocketMap\tsockfs\t8\t80672\tAF_INET\t127.0.0.1\t50046\t127.0.0.1\t7878
                ConnectEnd\tepoll_server\t24354\tsockfs\t8\t80672\tAF_INET\t127.0.0.1\t50046\t127.0.0.1\t7878\t111111111\t1034
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tsockfs\t8\t80672\t19446834063942\t1016301358

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 914973709
                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let tmp_dir = tempdir::TempDir::new("")?;
            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(tmp_dir.path().to_str().unwrap()),
            );

            event_polls.sample()?;
            event_polls.store()?;

            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let event_poll = event_poll.unwrap();
            let snapshots = event_poll.sockets.snapshots;
            assert!(snapshots.len() == 0);

            let contents = fs::read_to_string(format!(
                "{}/global/epoll/ffff98dd8179e0c0/sockets/19440/ipv4_127.0.0.1:50046_127.0.0.1:7878.csv",
                tmp_dir.path().to_str().unwrap()
            ))?;
            assert_eq!(
                contents,
                indoc! {"
                    epoch_ms,socket_wait,count
                    19447107,668479466,0
                    19448107,1247279533,0
                "}
            );

            Ok(())
        }
    }

    mod eventpoll_pipes {
        use super::*;

        #[test]
        fn empty_snapshot() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.pipes.snapshots.remove(&TargetFile::Inode {
                device: 8,
                inode_id: 80672,
            });
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 1);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    None,
                    Stats {
                        accumulated_wait: 578800067,
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn filled_snapshot() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.pipes.snapshots.remove(&TargetFile::Inode {
                device: 8,
                inode_id: 80672,
            });
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 1);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: 578800067,
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn remove_and_add_active() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.pipes.snapshots.remove(&TargetFile::Inode {
                device: 8,
                inode_id: 80672,
            });
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 1);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291) + (289679399 - 200000000),
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn two_consecutive_bpf_samples_last_pending() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.pipes.snapshots.remove(&TargetFile::Inode {
                device: 8,
                inode_id: 80672,
            });
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 2);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291) + (289679399 - 200000000),
                        count: 0,
                    }
                ))
            );
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    None,
                    Stats {
                        accumulated_wait: (1016301358 - 437501291)
                            + (289679399 - 200000000)
                            + (1016301358 - 437501291),
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn two_consecutive_bpf_samples() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 914973709
                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(temp_dir().to_str().unwrap()),
            );

            event_polls.sample()?;
            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let mut event_poll = event_poll.unwrap();
            let snapshots = event_poll.pipes.snapshots.remove(&TargetFile::Inode {
                device: 8,
                inode_id: 80672,
            });
            assert!(snapshots.is_some());
            let mut snapshots = snapshots.unwrap();

            assert_eq!(snapshots.len(), 2);
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19447107025962),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291) + (289679399 - 200000000),
                        count: 0,
                    }
                ))
            );
            assert_eq!(
                snapshots.pop_front(),
                Some((
                    Some(19448107034740),
                    Stats {
                        accumulated_wait: (1016301358 - 437501291)
                            + (289679399 - 200000000)
                            + (1016301358 - 437501291),
                        count: 0,
                    }
                ))
            );

            Ok(())
        }

        #[test]
        fn two_consecutive_bpf_samples_store() -> Result<()> {
            let (rx, mut tx) = pipe();
            let ipc_program = Rc::new(RefCell::new(
                IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
            ));

            let bpf_content = indoc! {"
                HEADER

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358
                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t200000000

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 289679399
                SampleInstant\t19447107025962
                => end map statistics

                EpollAdd\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446544512965\t437501291
                EpollRemove\tepoll_server\t24354\t0xffff98dd8179e0c0\tdevpts\t8\t80672\t19446834063942\t1016301358

                => start map statistics
                @epoll_map[0xffff98dd8179e0c0]: 914973709
                SampleInstant\t19448107034740
                => end map statistics
            "};
            tx.write_all(bpf_content.as_bytes())?;
            while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

            let tmp_dir = tempdir::TempDir::new("")?;
            let mut event_polls = EventPollCollection::new(
                ipc_program.clone(),
                Rc::new(RefCell::new(HashMap::new())),
                Rc::from(tmp_dir.path().to_str().unwrap()),
            );

            event_polls.sample()?;
            event_polls.store()?;

            let event_poll = event_polls
                .event_poll_map
                .remove(&(0xffff98dd8179e0c0 as u64));
            assert!(event_poll.is_some());

            let event_poll = event_poll.unwrap();
            let snapshots = event_poll.sockets.snapshots;
            assert!(snapshots.len() == 0);

            let contents = fs::read_to_string(format!(
                "{}/global/epoll/ffff98dd8179e0c0/streams/19440/8_80672.csv",
                tmp_dir.path().to_str().unwrap()
            ))?;
            assert_eq!(
                contents,
                indoc! {"
                    epoch_ms,stream_wait,count
                    19447107,668479466,0
                    19448107,1247279533,0
                "}
            );

            Ok(())
        }
    }

    #[test]
    fn epoll_inode() -> Result<()> {
        let (rx, mut tx) = pipe();
        let ipc_program = Rc::new(RefCell::new(
            IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
        ));

        let bpf_content = indoc! {"
            HEADER

            NewSocketMap\tsockfs\t8\t2519815\tAF_INET\t127.0.0.1\t60958\t127.0.0.1\t7878
            EpollAdd\tepoll_server\t357171\t0xffff96892f1e7b00\tsockfs\t8\t2519815\t521457873233008\t861999000

            => start map statistics
            @inode_map[epoll_server, 357171,                           epoll, 0, -115959031497984]: (862007004, 12)
            @inode_pending[epoll_server, 357171,                           epoll, 0, -115959031497984]: 521457873417016

            @epoll_map[0xffff96892f1e7b00]: 861999871
            @epoll_pending[0xffff96892f1e7b00]: 521457873417016
            SampleInstant\t521457925386742
            => end map statistics
        "};
        tx.write_all(bpf_content.as_bytes())?;
        while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

        let tmp_dir = tempdir::TempDir::new("")?;
        let mut event_polls = EventPollCollection::new(
            ipc_program.clone(),
            Rc::new(RefCell::new(HashMap::new())),
            Rc::from(tmp_dir.path().to_str().unwrap()),
        );

        event_polls.sample()?;
        event_polls.store()?;

        let event_poll = event_polls
            .event_poll_map
            .remove(&(0xffff96892f1e7b00 as u64));
        assert!(event_poll.is_some());

        let event_poll = event_poll.unwrap();
        let snapshots = event_poll.sockets.snapshots;
        assert!(snapshots.len() == 0);

        let contents = fs::read_to_string(format!(
            "{}/global/epoll/ffff96892f1e7b00/sockets/521400/ipv4_127.0.0.1:60958_127.0.0.1:7878.csv",
            tmp_dir.path().to_str().unwrap()
        ))?;
        assert_eq!(
            contents,
            indoc! {"
                epoch_ms,socket_wait,count
                521457925,51970597,0
            "}
        );

        let mut ipc = Ipc::new(
            ipc_program.clone(),
            357171,
            Rc::from(tmp_dir.path().to_str().unwrap()),
            "thread/357171/357171",
            Rc::new(RefCell::new(HashMap::new())),
        );

        ipc.sample()?;
        ipc.store()?;

        assert!(ipc.pipes.snapshots.len() == 0);
        let contents = fs::read_to_string(format!(
            "{}/thread/357171/357171/ipc/streams/521400/epoll_ffff96892f1e7b00.csv",
            tmp_dir.path().to_str().unwrap()
        ))?;
        assert_eq!(
            indoc! {"
                epoch_ms,stream_wait,count
                521457925,913976730,12
            "},
            contents
        );

        Ok(())
    }

    #[test]
    fn epoll_inode_ipv6() -> Result<()> {
        let (rx, mut tx) = pipe();
        let ipc_program = Rc::new(RefCell::new(
            IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
        ));

        let bpf_content = indoc! {"
            HEADER

            NewSocketMap\tsockfs\t8\t1031455\tAF_INET6\t::1\t3001\t::1\t55774
            AcceptEnd\tepoll_server\t67967\tsockfs\t8\t1031455\tAF_INET6\t::1\t3001\t::1\t55774\t330488529582598
            EpollAdd\tepoll_server\t67967\t0xffff9d5c4f7ca840\tsockfs\t8\t1031455\t330488529608026\t248242602

            => start map statistics
            @inode_map[epoll_server, 67967, sockfs, 8, 1031455]: (30594, 5)
            @inode_pending[epoll_server, 67967,                           epoll, 0, -108455180588992]: 330489199386315
            @epoll_map[0xffff9d5c4f7ca840]: 586287502
            @epoll_pending[0xffff9d5c4f7ca840]: 330489199386315
            SampleInstant\t330489281294037
            => end map statistics
        "};
        tx.write_all(bpf_content.as_bytes())?;
        while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

        let tmp_dir = tempdir::TempDir::new("")?;
        let mut event_polls = EventPollCollection::new(
            ipc_program.clone(),
            Rc::new(RefCell::new(HashMap::new())),
            Rc::from(tmp_dir.path().to_str().unwrap()),
        );

        event_polls.sample()?;
        event_polls.store()?;

        let event_poll = event_polls
            .event_poll_map
            .remove(&(0xffff9d5c4f7ca840 as u64));
        assert!(event_poll.is_some());

        let event_poll = event_poll.unwrap();
        let snapshots = event_poll.sockets.snapshots;
        assert!(snapshots.len() == 0);

        let contents = fs::read_to_string(format!(
            "{}/global/epoll/ffff9d5c4f7ca840/sockets/330480/ipv6_[0:0:0:0:0:0:0:1]:3001_[0:0:0:0:0:0:0:1]:55774.csv",
            tmp_dir.path().to_str().unwrap()
        ))?;
        assert_eq!(
            contents,
            indoc! {"
                epoch_ms,socket_wait,count
                330489281,419952622,0
            "}
        );

        let mut ipc = Ipc::new(
            ipc_program.clone(),
            67967,
            Rc::from(tmp_dir.path().to_str().unwrap()),
            "thread/67967/67967",
            Rc::new(RefCell::new(HashMap::new())),
        );

        ipc.sample()?;
        ipc.store()?;

        assert!(ipc.sockets.snapshots.len() == 0);
        let contents = fs::read_to_string(format!(
            "{}/thread/67967/67967/ipc/sockets/330480/ipv6_[0:0:0:0:0:0:0:1]:3001_[0:0:0:0:0:0:0:1]:55774.csv",
            tmp_dir.path().to_str().unwrap()
        ))?;
        assert_eq!(
            indoc! {"
                epoch_ms,socket_wait,count
                330489281,30594,5
            "},
            contents
        );

        assert!(ipc.pipes.snapshots.len() == 0);
        let contents = fs::read_to_string(format!(
            "{}/thread/67967/67967/ipc/streams/330480/epoll_ffff9d5c4f7ca840.csv",
            tmp_dir.path().to_str().unwrap()
        ))?;
        assert_eq!(
            indoc! {"
                epoch_ms,stream_wait,count
                330489281,81907722,0
            "},
            contents
        );

        Ok(())
    }

    #[test]
    fn epoll_inode_unix() -> Result<()> {
        let (rx, mut tx) = pipe();
        let ipc_program = Rc::new(RefCell::new(
            IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap(),
        ));

        let bpf_content = indoc! {"
            HEADER

            NewSocketMap\tsockfs\t8\t1051498\tAF_UNIX\t0xffff9d5c5c4d3300\t0xffff9d5c5c4d1100
            => start map statistics
            @inode_pending[unix-accept-con, 143866, sockfs, 8, 1051498]: 332665199498858
            SampleInstant\t332665569307417
            => end map statistics

            NewProcess\tunix-accept-con\t143868
            NewSocketMap\tsockfs\t8\t1057237\tAF_UNIX\t0xffff9d5c5c4d1100\t0xffff9d5c5c4d3300
            => start map statistics
            @inode_map[unix-accept-con, 143866, devpts, 24, 8]: (8184, 1)
            @inode_map[unix-accept-con, 143866, sockfs, 8, 1051498]: (630338761, 1)
            @inode_map[unix-accept-con, 143868, sockfs, 8, 1057237]: (5879, 1)
            @inode_pending[unix-accept-con, 143866, sockfs, 8, 1051498]: 332666199674298
            SampleInstant\t332666569304709
            => end map statistics
        "};
        tx.write_all(bpf_content.as_bytes())?;
        while let Ok(0) = ipc_program.borrow_mut().poll_events() {}

        let tmp_dir = tempdir::TempDir::new("")?;
        let kfile_socket_map = Rc::new(RefCell::new(HashMap::new()));
        let mut event_polls = EventPollCollection::new(
            ipc_program.clone(),
            kfile_socket_map.clone(),
            Rc::from(tmp_dir.path().to_str().unwrap()),
        );

        event_polls.sample()?;
        event_polls.store()?;

        let mut ipc = Ipc::new(
            ipc_program.clone(),
            143866,
            Rc::from(tmp_dir.path().to_str().unwrap()),
            "thread/143866/143866",
            kfile_socket_map.clone(),
        );

        ipc.sample()?;
        ipc.store()?;

        assert!(ipc.sockets.snapshots.len() == 0);
        let contents = fs::read_to_string(format!(
            "{}/thread/143866/143866/ipc/sockets/332640/unix_0xffff9d5c5c4d3300_0xffff9d5c5c4d1100.csv",
            tmp_dir.path().to_str().unwrap()
        ))?;
        assert_eq!(
            indoc! {"
                epoch_ms,socket_wait,count
                332665569,369808559,0
                332666569,1369777731,1
            "},
            contents
        );

        let mut ipc = Ipc::new(
            ipc_program.clone(),
            143868,
            Rc::from(tmp_dir.path().to_str().unwrap()),
            "thread/143868/143868",
            kfile_socket_map,
        );

        ipc.sample()?;
        ipc.store()?;

        assert!(ipc.sockets.snapshots.len() == 0);
        let contents = fs::read_to_string(format!(
            "{}/thread/143868/143868/ipc/sockets/332640/unix_0xffff9d5c5c4d1100_0xffff9d5c5c4d3300.csv",
            tmp_dir.path().to_str().unwrap()
        ))?;
        assert_eq!(
            indoc! {"
                epoch_ms,socket_wait,count
                332666569,5879,1
            "},
            contents
        );

        Ok(())
    }
}
