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
    ipc::{IpcEvent, IpcProgram},
    BOOT_EPOCH_NS,
};

use super::Collect;
use super::ToCsv;

type KFile = (u32, u64);

pub struct Ipc {
    ipc_program: Rc<RefCell<IpcProgram>>,
    stream_map: HashMap<KFile, u64>,
    sum_stream_wait_ns: u64,
    pending: HashMap<KFile, u64>,
    last_terminated: HashSet<KFile>,
    tid: usize,
    data_files: LruCache<String, File>,
    sample_instant_ns: Option<u128>,
    target_subdirectory: String,
    sockets: Sockets,
}

impl Ipc {
    pub fn new(
        ipc_program: Rc<RefCell<IpcProgram>>,
        tid: usize,
        root_directory: Rc<str>,
        target_subdirectory: &str,
    ) -> Self {
        Self {
            ipc_program,
            tid,
            stream_map: HashMap::new(),
            sum_stream_wait_ns: 0,
            pending: HashMap::new(),
            last_terminated: HashSet::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
            sample_instant_ns: None,
            target_subdirectory: format!("{}/{}/ipc", root_directory, target_subdirectory),
            sockets: Sockets::new(root_directory, target_subdirectory),
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        println!("{:?}", event);
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
                self.pending.insert((sb_id, inode_id), ns_since_boot);
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
                let kfile = (sb_id, inode_id);
                let entry = self.stream_map.entry(kfile).or_insert(0);
                self.last_terminated.insert(kfile);
                self.pending.remove(&kfile);
                *entry += ns_elapsed;
                self.sum_stream_wait_ns += ns_elapsed;
            }
            IpcEvent::RecvStart { .. }
            | IpcEvent::RecvEnd { .. }
            | IpcEvent::SendStart { .. }
            | IpcEvent::SendEnd { .. } => {
                self.sockets.process_event(event)?;
            }
            _ => {
                println!("{:?}", event);
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

    fn store_streams(&mut self, epoch_ns: u128) -> Result<()> {
        let last_terminated = mem::replace(&mut self.last_terminated, HashSet::new());
        let keys = self.pending.keys().into_iter().map(|key| (key.0, key.1));
        let kfiles: HashSet<KFile> = HashSet::from_iter(keys);
        let kfiles = kfiles.union(&last_terminated);

        for kfile in kfiles {
            let epoch_ms = epoch_ns / 1_000_000;
            let pending = if let Some(ns_since_boot) = self.pending.get(&kfile) {
                epoch_ns - (*BOOT_EPOCH_NS.read().unwrap() + *ns_since_boot as u128)
            } else {
                0
            };
            let cached_wait = *self.stream_map.get(&kfile).unwrap_or(&0);
            let cumulative_wait = pending as u64 + cached_wait;

            let sample = StreamFileSample {
                epoch_ms,
                cumulative_wait,
            };

            let file_path = format!(
                "{}/streams/{:?}/{:?}_{:?}.csv",
                self.target_subdirectory,
                (epoch_ms / (1000 * 60)) * 60,
                kfile.0,
                kfile.1,
            );
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

        if self.last_terminated.len() == 0 && self.pending.len() == 0 {
            return Ok(());
        }

        self.store_streams(epoch_ns)?;
        self.store_aggregated_stream(epoch_ns)?;

        Ok(())
    }
}

type Endpoint = (Ipv4Addr, u64);
type SrcEndpoint = Endpoint;
type DstEndpoint = Endpoint;
type Socket = (SrcEndpoint, DstEndpoint);

struct Sockets {
    pending: Option<(Socket, u64)>,
    socket_map: HashMap<(SrcEndpoint, DstEndpoint), u64>,
    last_terminated: HashSet<(SrcEndpoint, DstEndpoint)>,
    data_files: LruCache<String, File>,
    target_subdirectory: String,
}

impl Sockets {
    fn new(root_directory: Rc<str>, target_subdirectory: &str) -> Self {
        Self {
            socket_map: HashMap::new(),
            pending: None,
            last_terminated: HashSet::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
            target_subdirectory: format!("{}/{}/ipc", root_directory, target_subdirectory),
        }
    }

    fn process_event(&mut self, event: IpcEvent) -> Result<()> {
        match event {
            IpcEvent::RecvStart {
                src_host,
                src_port,
                dst_host,
                dst_port,
                ns_since_boot,
                ..
            }
            | IpcEvent::SendStart {
                src_host,
                src_port,
                dst_host,
                dst_port,
                ns_since_boot,
                ..
            } => {
                self.pending = Some((((src_host, src_port), (dst_host, dst_port)), ns_since_boot));
            }
            IpcEvent::RecvEnd { ns_elapsed, .. } | IpcEvent::SendEnd { ns_elapsed, .. } => {
                let (socket, _) = self.pending.take().ok_or_eyre("Invalid sockets state")?;
                let entry = self.socket_map.entry(socket).or_insert(0);
                self.last_terminated.insert(socket);
                *entry += ns_elapsed;
            }
            _ => {
                return Err(eyre!(format!("Unexpected event {:?}", event)));
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
        let mut sockets = mem::replace(&mut self.last_terminated, HashSet::new());
        self.pending.map(|(socket, _)| sockets.insert(socket));

        for socket in sockets {
            let mut cumulative_wait = self
                .pending
                .map(|(pending_sock, ns_since_boot)| {
                    if pending_sock == socket {
                        epoch_ns - (*BOOT_EPOCH_NS.read().unwrap() + ns_since_boot as u128)
                    } else {
                        0
                    }
                })
                .unwrap_or(0);
            cumulative_wait += *self.socket_map.get(&socket).unwrap_or(&0) as u128;
            let sample = SocketSample {
                epoch_ms,
                cumulative_wait,
            };

            let file_path = format!(
                "{}/sockets/{:?}/{}:{:?}_{}:{:?}.csv",
                self.target_subdirectory,
                (epoch_ms / (1000 * 60)) * 60,
                socket.0 .0.octets().map(|elem| elem.to_string()).join("."),
                socket.0 .1,
                socket.1 .0.octets().map(|elem| elem.to_string()).join("."),
                socket.1 .1,
            );
            let mut file = self.get_or_create_file(Path::new(&file_path), sample.csv_headers())?;
            file.write_all(sample.to_csv_row().as_bytes())?;
            println!("{}", file_path);
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
