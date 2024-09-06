use eyre::{eyre, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    collections::HashMap,
    io::Read,
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    process::{Child, Command},
    rc::Rc,
    str::FromStr,
    sync::{
        mpsc::{Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    thread,
};

use crate::execute::BpfReader;

lazy_static! {
    static ref REGEX_PATTERN: Regex = Regex::new(r"^@(\w+)\[(.*)\]: (.*)$").unwrap();
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Connection {
    Ipv4 {
        src_host: Ipv4Addr,
        src_port: u64,
        dst_host: Ipv4Addr,
        dst_port: u64,
    },
    Ipv6 {
        src_host: Ipv6Addr,
        src_port: u64,
        dst_host: Ipv6Addr,
        dst_port: u64,
    },
    Unix {
        src_address: u64,
        dst_address: u64,
    },
}

#[derive(Debug, Clone)]
enum IpcBpfEvent {
    NoOp,
    NewProcess {
        comm: Rc<str>,
        pid: usize,
    },
    NewSocketMap {
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        conn: Connection,
    },
    AcceptStart,
    AcceptEnd {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        conn: Connection,
    },
    ConnectStart,
    ConnectEnd {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        conn: Connection,
    },
    UnhandledFileMode {
        comm: Rc<str>,
        tid: usize,
        fs: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        mode: u64,
    },
    UnhandledSockFam {
        comm: Rc<str>,
        tid: usize,
        fs: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        family: u32,
    },
    EpollItemAdd {
        comm: Rc<str>,
        tid: usize,
        event_poll: u64,
        fs: Rc<str>,
        target_file: TargetFile,
        ns_since_boot: u64,
        contrib_snapshot: u64,
    },
    EpollItemRemove {
        comm: Rc<str>,
        tid: usize,
        event_poll: u64,
        fs: Rc<str>,
        target_file: TargetFile,
        ns_since_boot: u64,
        contrib_snapshot: u64,
    },
    EpollItem {
        comm: Rc<str>,
        tid: usize,
        event_poll: u64,
        fs: Rc<str>,
        target_file: TargetFile,
        ns_since_boot: u64,
        contrib_snapshot: u64,
    },
    MapStatsStart,
    SampleInstant {
        ns_since_boot: u64,
    },
    MapStatsEnd,
    InodeMapCached {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: i64,
        count: u64,
        total_ns: u64,
    },
    InodeMapPending {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: i64,
        ns_since_boot: u64,
    },
    EpollMapCached {
        event_poll: u64,
        total_ns: u64,
    },
    EpollMapPending {
        event_poll: u64,
        ns_since_boot: u64,
    },
    Unexpected {
        data: String,
    },
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum TargetFile {
    AnonInode { name: Rc<str>, address: u64 },
    Inode { device: u32, inode_id: u64 },
    Epoll { address: u64 },
}

impl IpcBpfEvent {
    fn parse_line(event_string: &str) -> Result<Self> {
        if event_string.starts_with("@") {
            Self::from_summary_stats_string(event_string)
        } else if event_string.starts_with("=>") {
            Self::from_stats_closure_string(event_string)
        } else {
            Self::from_trace_string(event_string)
        }
    }

    fn from_summary_stats_string(event_string: &str) -> Result<Self> {
        let captures = REGEX_PATTERN
            .captures(&event_string)
            .ok_or(eyre!("Unexpected event string"))?;
        let mut cap_iter = captures.iter();
        cap_iter.next();

        let map_type = cap_iter.next().unwrap().unwrap().as_str();
        match map_type {
            "inode_map" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let mut key_elements = key.split(", ");

                let value = cap_iter.next().unwrap().unwrap().as_str();
                let value = &value[1..value.len() - 1];
                let mut value_elements = value.split(", ");

                let total_ns = value_elements.next().unwrap().parse().unwrap();
                let count = value_elements.next().unwrap().parse().unwrap();

                Ok(Self::InodeMapCached {
                    comm: Rc::from(key_elements.next().unwrap()),
                    tid: key_elements.next().unwrap().parse().unwrap(),
                    fs_type: Rc::from(key_elements.next().unwrap().trim()),
                    sb_id: key_elements.next().unwrap().parse().unwrap(),
                    inode_id: key_elements.next().unwrap().parse().unwrap(),
                    total_ns,
                    count,
                })
            }
            "inode_pending" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let value = cap_iter.next().unwrap().unwrap().as_str();
                let mut key_elements = key.split(", ");

                Ok(Self::InodeMapPending {
                    comm: Rc::from(key_elements.next().unwrap()),
                    tid: key_elements.next().unwrap().parse().unwrap(),
                    fs_type: Rc::from(key_elements.next().unwrap().trim()),
                    sb_id: key_elements.next().unwrap().parse().unwrap(),
                    inode_id: key_elements.next().unwrap().parse().unwrap(),
                    ns_since_boot: value.parse().unwrap(),
                })
            }
            "epoll_map" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let value = cap_iter.next().unwrap().unwrap().as_str();

                let event_poll = key.trim_start_matches("0x");
                let event_poll = u64::from_str_radix(event_poll, 16).unwrap();

                Ok(Self::EpollMapCached {
                    event_poll,
                    total_ns: value.parse().unwrap(),
                })
            }
            "epoll_pending" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let value = cap_iter.next().unwrap().unwrap().as_str();

                let event_poll = key.trim_start_matches("0x");
                let event_poll = u64::from_str_radix(event_poll, 16).unwrap();

                Ok(Self::EpollMapPending {
                    event_poll,
                    ns_since_boot: value.parse().unwrap(),
                })
            }
            _ => Err(eyre!("Invalid map type")),
        }
    }

    fn from_stats_closure_string(event_string: &str) -> Result<Self> {
        if event_string.starts_with("=> start") {
            Ok(Self::MapStatsStart {})
        } else if event_string.starts_with("=> end") {
            Ok(Self::MapStatsEnd {})
        } else {
            Err(eyre!(""))
        }
    }

    fn from_trace_string(event_string: &str) -> Result<Self> {
        let mut elements = event_string.split("\t");
        let event = match elements.next().unwrap().trim() {
            "AcceptStart" => Self::AcceptStart,
            "AcceptEnd" => {
                let comm = Rc::from(elements.next().unwrap());
                let tid = elements.next().unwrap().parse().unwrap();
                let fs_type = Rc::from(elements.next().unwrap());
                let sb_id = elements.next().unwrap().parse().unwrap();
                let inode_id = elements.next().unwrap().parse().unwrap();
                let conn = match elements.next().unwrap() {
                    "AF_INET" => Connection::Ipv4 {
                        src_host: Ipv4Addr::from_str(elements.next().unwrap()).unwrap(),
                        src_port: elements.next().unwrap().parse().unwrap(),
                        dst_host: Ipv4Addr::from_str(elements.next().unwrap()).unwrap(),
                        dst_port: elements.next().unwrap().parse().unwrap(),
                    },
                    "AF_INET6" => Connection::Ipv6 {
                        src_host: Ipv6Addr::from_str(elements.next().unwrap()).unwrap(),
                        src_port: elements.next().unwrap().parse().unwrap(),
                        dst_host: Ipv6Addr::from_str(elements.next().unwrap()).unwrap(),
                        dst_port: elements.next().unwrap().parse().unwrap(),
                    },
                    "AF_UNIX" => Connection::Unix {
                        src_address: u64::from_str_radix(
                            elements.next().unwrap().trim_start_matches("0x"),
                            16,
                        )
                        .unwrap(),
                        dst_address: u64::from_str_radix(
                            elements.next().unwrap().trim_start_matches("0x"),
                            16,
                        )?,
                    },
                    _ => return Err(eyre!("Unexpected socket family type")),
                };
                Self::AcceptEnd {
                    comm,
                    tid,
                    fs_type,
                    sb_id,
                    inode_id,
                    conn,
                }
            }
            "ConnectStart" => Self::ConnectStart,
            "ConnectEnd" => {
                let comm = Rc::from(elements.next().unwrap());
                let tid = elements.next().unwrap().parse().unwrap();
                let fs_type = Rc::from(elements.next().unwrap());
                let sb_id = elements.next().unwrap().parse().unwrap();
                let inode_id = elements.next().unwrap().parse().unwrap();
                let conn = match elements.next().unwrap() {
                    "AF_INET" => Connection::Ipv4 {
                        src_host: Ipv4Addr::from_str(elements.next().unwrap()).unwrap(),
                        src_port: elements.next().unwrap().parse().unwrap(),
                        dst_host: Ipv4Addr::from_str(elements.next().unwrap()).unwrap(),
                        dst_port: elements.next().unwrap().parse().unwrap(),
                    },
                    "AF_INET6" => Connection::Ipv6 {
                        src_host: Ipv6Addr::from_str(elements.next().unwrap()).unwrap(),
                        src_port: elements.next().unwrap().parse().unwrap(),
                        dst_host: Ipv6Addr::from_str(elements.next().unwrap()).unwrap(),
                        dst_port: elements.next().unwrap().parse().unwrap(),
                    },
                    "AF_UNIX" => Connection::Unix {
                        src_address: u64::from_str_radix(
                            elements.next().unwrap().trim_start_matches("0x"),
                            16,
                        )
                        .unwrap(),
                        dst_address: u64::from_str_radix(
                            elements.next().unwrap().trim_start_matches("0x"),
                            16,
                        )
                        .unwrap(),
                    },
                    _ => return Err(eyre!("Unexpected socket family type")),
                };
                Self::ConnectEnd {
                    comm,
                    tid,
                    fs_type,
                    sb_id,
                    inode_id,
                    conn,
                }
            }
            "EpollAdd" => {
                let comm = Rc::from(elements.next().unwrap());
                let tid = elements.next().unwrap().parse().unwrap();
                let event_poll = elements.next().unwrap().trim_start_matches("0x");
                let event_poll = u64::from_str_radix(event_poll, 16).unwrap();
                let fs: Rc<str> = Rc::from(elements.next().unwrap());
                let target_file = if &*fs == "anon_inodefs" {
                    let name = Rc::from(elements.next().unwrap());
                    let address = elements.next().unwrap().trim_start_matches("0x");
                    let address = u64::from_str_radix(address, 16).unwrap();
                    TargetFile::AnonInode { name, address }
                } else {
                    TargetFile::Inode {
                        device: elements.next().unwrap().parse().unwrap(),
                        inode_id: elements.next().unwrap().parse().unwrap(),
                    }
                };
                Self::EpollItemAdd {
                    comm,
                    tid,
                    event_poll,
                    fs,
                    target_file,
                    ns_since_boot: elements.next().unwrap().parse().unwrap(),
                    contrib_snapshot: elements.next().unwrap().parse().unwrap(),
                }
            }
            "EpollRemove" => {
                let comm = Rc::from(elements.next().unwrap());
                let tid = elements.next().unwrap().parse().unwrap();
                let event_poll = elements.next().unwrap().trim_start_matches("0x");
                let event_poll = u64::from_str_radix(event_poll, 16).unwrap();
                let fs: Rc<str> = Rc::from(elements.next().unwrap());
                let target_file = if &*fs == "anon_inodefs" {
                    let name = Rc::from(elements.next().unwrap());
                    let address = elements.next().unwrap().trim_start_matches("0x");
                    let address = u64::from_str_radix(address, 16).unwrap();
                    TargetFile::AnonInode { name, address }
                } else {
                    TargetFile::Inode {
                        device: elements.next().unwrap().parse().unwrap(),
                        inode_id: elements.next().unwrap().parse().unwrap(),
                    }
                };
                Self::EpollItemRemove {
                    comm,
                    tid,
                    event_poll,
                    fs,
                    target_file,
                    ns_since_boot: elements.next().unwrap().parse().unwrap(),
                    contrib_snapshot: elements.next().unwrap().parse().unwrap(),
                }
            }
            "EpiPoll" => {
                let comm = Rc::from(elements.next().unwrap());
                let tid = elements.next().unwrap().parse().unwrap();
                let event_poll = elements.next().unwrap().trim_start_matches("0x");
                let event_poll = u64::from_str_radix(event_poll, 16).unwrap();
                let fs: Rc<str> = Rc::from(elements.next().unwrap());
                let target_file = if &*fs == "anon_inodefs" {
                    let name = Rc::from(elements.next().unwrap());
                    let address = elements.next().unwrap().trim_start_matches("0x");
                    let address = u64::from_str_radix(address, 16).unwrap();
                    TargetFile::AnonInode { name, address }
                } else {
                    TargetFile::Inode {
                        device: elements.next().unwrap().parse().unwrap(),
                        inode_id: elements.next().unwrap().parse().unwrap(),
                    }
                };
                Self::EpollItem {
                    comm,
                    tid,
                    event_poll,
                    fs,
                    target_file,
                    ns_since_boot: elements.next().unwrap().parse().unwrap(),
                    contrib_snapshot: elements.next().unwrap().parse().unwrap(),
                }
            }
            "NewSocketMap" => {
                let fs_type = Rc::from(elements.next().unwrap());
                let sb_id = elements.next().unwrap().parse().unwrap();
                let inode_id = elements.next().unwrap().parse().unwrap();
                let conn = match elements.next().unwrap() {
                    "AF_INET" => Connection::Ipv4 {
                        src_host: Ipv4Addr::from_str(elements.next().unwrap()).unwrap(),
                        src_port: elements.next().unwrap().parse().unwrap(),
                        dst_host: Ipv4Addr::from_str(elements.next().unwrap()).unwrap(),
                        dst_port: elements.next().unwrap().parse().unwrap(),
                    },
                    "AF_INET6" => Connection::Ipv6 {
                        src_host: Ipv6Addr::from_str(elements.next().unwrap()).unwrap(),
                        src_port: elements.next().unwrap().parse().unwrap(),
                        dst_host: Ipv6Addr::from_str(elements.next().unwrap()).unwrap(),
                        dst_port: elements.next().unwrap().parse().unwrap(),
                    },
                    "AF_UNIX" => Connection::Unix {
                        src_address: u64::from_str_radix(
                            elements.next().unwrap().trim_start_matches("0x"),
                            16,
                        )
                        .unwrap(),
                        dst_address: u64::from_str_radix(
                            elements.next().unwrap().trim_start_matches("0x"),
                            16,
                        )?,
                    },
                    _ => return Err(eyre!("Unexpected socket family type")),
                };
                Self::NewSocketMap {
                    fs_type,
                    sb_id,
                    inode_id,
                    conn,
                }
            }
            "NewProcess" => Self::NewProcess {
                comm: Rc::from(elements.next().unwrap()),
                pid: elements.next().unwrap().parse().unwrap(),
            },
            "SampleInstant" => Self::SampleInstant {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
            },
            "UnhandledFileMode" => Self::UnhandledFileMode {
                comm: Rc::from(elements.next().unwrap()),
                tid: elements.next().unwrap().parse().unwrap(),
                fs: elements.next().unwrap().into(),
                sb_id: elements.next().unwrap().parse().unwrap(),
                inode_id: elements.next().unwrap().parse().unwrap(),
                mode: u64::from_str_radix(elements.next().unwrap(), 16).unwrap(),
            },
            "UnhandledSockFam" => Self::UnhandledSockFam {
                comm: Rc::from(elements.next().unwrap()),
                tid: elements.next().unwrap().parse().unwrap(),
                fs: elements.next().unwrap().into(),
                sb_id: elements.next().unwrap().parse().unwrap(),
                inode_id: elements.next().unwrap().parse().unwrap(),
                family: elements.next().unwrap().parse().unwrap(),
            },
            _ => {
                return Err(eyre!("Invalid trace data"));
            }
        };

        Ok(event)
    }
}

impl From<Vec<u8>> for IpcBpfEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        if event_string.len() == 0 {
            return Self::NoOp {};
        }
        Self::parse_line(&event_string).unwrap_or(Self::Unexpected { data: event_string })
    }
}

#[derive(Debug, Clone)]
pub enum IpcEvent {
    NewProcess {
        comm: Rc<str>,
        pid: usize,
    },
    NewSocketMap {
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        conn: Connection,
    },
    AcceptEnd {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        conn: Connection,
    },
    ConnectEnd {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        conn: Connection,
    },
    EpollItemAdd {
        comm: Rc<str>,
        tid: usize,
        event_poll: u64,
        fs: Rc<str>,
        target_file: TargetFile,
        ns_since_boot: u64,
        contrib_snapshot: u64,
    },
    EpollItemRemove {
        comm: Rc<str>,
        tid: usize,
        event_poll: u64,
        fs: Rc<str>,
        target_file: TargetFile,
        ns_since_boot: u64,
        contrib_snapshot: u64,
    },
    EpollItem {
        comm: Rc<str>,
        tid: usize,
        event_poll: u64,
        fs: Rc<str>,
        target_file: TargetFile,
        ns_since_boot: u64,
        contrib_snapshot: u64,
    },
    EpollWait {
        event_poll: u64,
        sample_instant_ns: u64,
        total_interval_wait_ns: u64,
    },
    InodeWait {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: i64,
        sample_instant_ns: u64,
        total_interval_wait_ns: u64,
        count_wait: Option<u64>,
    },
}

impl IpcEvent {
    fn is_global(&self) -> bool {
        match self {
            Self::EpollItemRemove { .. }
            | Self::EpollItemAdd { .. }
            | Self::EpollItem { .. }
            | Self::EpollWait { .. }
            | Self::NewSocketMap { .. } => true,
            _ => false,
        }
    }

    fn get_inode_wait_tid(&self) -> Result<usize> {
        match self {
            Self::InodeWait { tid, .. } => Ok(*tid),
            _ => Err(eyre!("Not IpcEvent::InodeWait.")),
        }
    }

    fn from_stats_closure_entry(
        entry: (Option<IpcBpfEvent>, Option<IpcBpfEvent>),
        current_instant_ns: u64,
        previous_instant_ns: Option<u64>,
    ) -> Result<Self> {
        match entry {
            (
                Some(IpcBpfEvent::InodeMapCached {
                    comm,
                    tid,
                    fs_type,
                    sb_id,
                    inode_id,
                    total_ns,
                    count,
                }),
                Some(IpcBpfEvent::InodeMapPending { ns_since_boot, .. }),
            ) => {
                let pending = if let Some(prev) = previous_instant_ns {
                    if ns_since_boot > prev {
                        current_instant_ns - ns_since_boot
                    } else {
                        current_instant_ns - prev
                    }
                } else {
                    current_instant_ns - ns_since_boot
                };

                let cached = total_ns;

                Ok(IpcEvent::InodeWait {
                    comm,
                    tid,
                    fs_type,
                    sb_id,
                    inode_id,
                    sample_instant_ns: current_instant_ns,
                    total_interval_wait_ns: cached + pending,
                    count_wait: Some(count),
                })
            }
            (
                Some(IpcBpfEvent::InodeMapCached {
                    comm,
                    tid,
                    fs_type,
                    sb_id,
                    inode_id,
                    total_ns,
                    count,
                }),
                None,
            ) => Ok(IpcEvent::InodeWait {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                sample_instant_ns: current_instant_ns,
                total_interval_wait_ns: total_ns,
                count_wait: Some(count),
            }),
            (
                None,
                Some(IpcBpfEvent::InodeMapPending {
                    comm,
                    tid,
                    fs_type,
                    sb_id,
                    inode_id,
                    ns_since_boot,
                }),
            ) => {
                let pending = if let Some(prev) = previous_instant_ns {
                    if ns_since_boot > prev {
                        current_instant_ns - ns_since_boot
                    } else {
                        current_instant_ns - prev
                    }
                } else {
                    i64::max(current_instant_ns as i64 - ns_since_boot as i64, 0) as u64
                };

                Ok(IpcEvent::InodeWait {
                    comm,
                    tid,
                    fs_type,
                    sb_id,
                    inode_id,
                    sample_instant_ns: current_instant_ns,
                    total_interval_wait_ns: pending,
                    count_wait: None,
                })
            }
            (
                Some(IpcBpfEvent::EpollMapCached {
                    event_poll,
                    total_ns,
                }),
                Some(IpcBpfEvent::EpollMapPending { ns_since_boot, .. }),
            ) => {
                let pending = if let Some(prev) = previous_instant_ns {
                    if ns_since_boot > prev {
                        current_instant_ns - ns_since_boot
                    } else {
                        current_instant_ns - prev
                    }
                } else {
                    i64::max(current_instant_ns as i64 - ns_since_boot as i64, 0) as u64
                };

                let cached = total_ns;

                Ok(IpcEvent::EpollWait {
                    event_poll,
                    sample_instant_ns: current_instant_ns,
                    total_interval_wait_ns: cached + pending,
                })
            }
            (
                Some(IpcBpfEvent::EpollMapCached {
                    event_poll,
                    total_ns,
                }),
                None,
            ) => Ok(IpcEvent::EpollWait {
                event_poll,
                sample_instant_ns: current_instant_ns,
                total_interval_wait_ns: total_ns,
            }),
            (
                None,
                Some(IpcBpfEvent::EpollMapPending {
                    event_poll,
                    ns_since_boot,
                }),
            ) => {
                let pending = if let Some(prev) = previous_instant_ns {
                    if ns_since_boot > prev {
                        current_instant_ns - ns_since_boot
                    } else {
                        current_instant_ns - prev
                    }
                } else {
                    i64::max(current_instant_ns as i64 - ns_since_boot as i64, 0) as u64
                };
                Ok(IpcEvent::EpollWait {
                    event_poll,
                    sample_instant_ns: current_instant_ns,
                    total_interval_wait_ns: pending,
                })
            }
            _ => Err(eyre!("Inconsistent stats closure entry state")),
        }
    }
}

#[derive(Debug)]
pub struct NoMapping;

impl std::fmt::Display for NoMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "No mapping")
    }
}

impl std::error::Error for NoMapping {}

impl TryFrom<IpcBpfEvent> for IpcEvent {
    type Error = NoMapping;

    fn try_from(event: IpcBpfEvent) -> Result<Self, Self::Error> {
        match event {
            IpcBpfEvent::NewProcess { comm, pid } => Ok(Self::NewProcess { comm, pid }),
            IpcBpfEvent::AcceptEnd {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                conn,
            } => Ok(IpcEvent::AcceptEnd {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                conn,
            }),
            IpcBpfEvent::ConnectEnd {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                conn,
            } => Ok(IpcEvent::ConnectEnd {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                conn,
            }),
            IpcBpfEvent::NewSocketMap {
                fs_type,
                sb_id,
                inode_id,
                conn,
            } => Ok(IpcEvent::NewSocketMap {
                fs_type,
                sb_id,
                inode_id,
                conn,
            }),
            IpcBpfEvent::EpollItemAdd {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            } => Ok(IpcEvent::EpollItemAdd {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            }),
            IpcBpfEvent::EpollItemRemove {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            } => Ok(IpcEvent::EpollItemRemove {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            }),
            IpcBpfEvent::EpollItem {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            } => Ok(IpcEvent::EpollItem {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            }),
            _ => Err(NoMapping {}),
        }
    }
}

enum IpcProgramState {
    OutStatClosure,
    InStatClosure(Option<u64>),
}

#[derive(PartialEq, Eq, Hash)]
enum StatsClosureKey {
    Inode {
        comm: Rc<str>,
        tid: usize,
        device: u32,
        inode_id: i64,
    },
    EventPoll {
        address: u64,
    },
}

pub struct IpcProgram {
    header_lines: u8,
    current_event: Option<Vec<u8>>,
    child: Option<Child>,
    rx: Receiver<Arc<[u8]>>,
    events: HashMap<usize, Vec<IpcEvent>>,
    global_events: Option<Vec<IpcEvent>>,
    new_process_events: Option<Vec<IpcEvent>>,
    state: IpcProgramState,
    stats_closure_events: HashMap<StatsClosureKey, (Option<IpcBpfEvent>, Option<IpcBpfEvent>)>,
    prev_instant_ns: Option<u64>,
    latest_instant_ns: Option<u64>,
}

impl IpcProgram {
    pub fn new(terminate_flag: Arc<Mutex<bool>>, pid: u32) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        let (bpf_pipe_rx, bpf_pipe_tx) = super::bpf_pipe(1 << 21);
        let child = Command::new("bpftrace")
            .args(["./metric-collector/src/bpf/ipc.bt", &format!("{:?}", pid)])
            .stdout(bpf_pipe_tx)
            .spawn()?;
        Self::start_bpf_reader(tx, bpf_pipe_rx, terminate_flag);

        Ok(Self {
            rx,
            child: Some(child),
            header_lines: 0,
            current_event: None,
            events: HashMap::new(),
            global_events: None,
            new_process_events: None,
            stats_closure_events: HashMap::new(),
            state: IpcProgramState::OutStatClosure,
            prev_instant_ns: None,
            latest_instant_ns: None,
        })
    }

    pub fn custom_reader<R>(reader: R, terminate_flag: Arc<Mutex<bool>>) -> Result<Self>
    where
        R: Read + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        Self::start_bpf_reader(tx, reader, terminate_flag);

        Ok(Self {
            rx,
            child: None,
            header_lines: 0,
            current_event: None,
            events: HashMap::new(),
            global_events: None,
            new_process_events: None,
            stats_closure_events: HashMap::new(),
            state: IpcProgramState::OutStatClosure,
            prev_instant_ns: None,
            latest_instant_ns: None,
        })
    }

    fn start_bpf_reader<R>(
        tx: Sender<Arc<[u8]>>,
        mut bpf_pipe_rx: R,
        terminate_flag: Arc<Mutex<bool>>,
    ) where
        R: Read + Send + 'static,
    {
        thread::Builder::new()
            .name("ipc_recv".to_string())
            .spawn(move || loop {
                if *terminate_flag.lock().unwrap() == true {
                    break;
                }
                let mut buf: [u8; 65536] = [0; 65536];
                let res = bpf_pipe_rx.read(&mut buf);
                if let Ok(bytes) = res {
                    if bytes == 0 {
                        break;
                    }

                    if let Err(_) = tx.send(Arc::from(&buf[..bytes])) {
                        break;
                    };
                }
            })
            .unwrap();
    }

    pub fn poll_events(&mut self) -> Result<usize> {
        loop {
            let res = self.rx.try_recv();

            let buf = match res {
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(e) => return Err(e.into()),
                Ok(buf) => buf,
            };

            let mut iterator = buf.into_iter();
            if !self.header_read() {
                self.handle_header(&mut iterator);
            }

            while let Some(event) = self.handle_event(&mut iterator) {
                let event = IpcBpfEvent::from(event);
                match event {
                    IpcBpfEvent::NewProcess { .. } => {
                        let events = self.new_process_events.get_or_insert_with(|| Vec::new());
                        events.push(IpcEvent::try_from(event)?);
                    }
                    IpcBpfEvent::NewSocketMap { .. } => {
                        let event = IpcEvent::try_from(event)?;
                        let events = self.global_events.get_or_insert_with(|| Vec::new());
                        events.push(event);
                    }
                    IpcBpfEvent::AcceptEnd { tid, .. } | IpcBpfEvent::ConnectEnd { tid, .. } => {
                        let event = IpcEvent::try_from(event)?;
                        let entry = self.events.entry(tid).or_insert(Vec::new());
                        entry.push(event);
                    }
                    IpcBpfEvent::EpollItemAdd { ns_since_boot, .. }
                    | IpcBpfEvent::EpollItemRemove { ns_since_boot, .. }
                    | IpcBpfEvent::EpollItem { ns_since_boot, .. } => {
                        let event = IpcEvent::try_from(event)?;
                        let events = self.global_events.get_or_insert_with(|| Vec::new());
                        events.push(event);
                        self.latest_instant_ns = Some(ns_since_boot);
                    }
                    IpcBpfEvent::MapStatsStart => {
                        self.state = IpcProgramState::InStatClosure(None);
                    }
                    IpcBpfEvent::SampleInstant { ns_since_boot } => {
                        if let IpcProgramState::InStatClosure(sample_interval) = &mut self.state {
                            sample_interval
                                .replace(ns_since_boot)
                                .map_or(Ok(()), |_| Err(eyre!("Unexpected state.\nUpon receiving a 'SampleInstant' event InStatClosure should not have a sample interval measurement.")))?;
                        } else {
                            return Err(eyre!("Ipc program should be in state InStatClosure. In state OutStatClosure"));
                        }
                    }
                    IpcBpfEvent::MapStatsEnd => {
                        let ns_since_boot =
                            if let IpcProgramState::InStatClosure(Some(ns_since_boot)) = self.state
                            {
                                ns_since_boot
                            } else {
                                return Err(eyre!("Inconsistent ipc program state"));
                            };
                        self.state = IpcProgramState::OutStatClosure;
                        self.latest_instant_ns = Some(ns_since_boot);

                        let closure_events =
                            mem::replace(&mut self.stats_closure_events, HashMap::new());
                        closure_events
                            .into_iter()
                            .map(|(_, entry)| {
                                let event = IpcEvent::from_stats_closure_entry(
                                    entry,
                                    ns_since_boot,
                                    self.prev_instant_ns,
                                )?;

                                if event.is_global() {
                                    self.global_events
                                        .get_or_insert_with(|| Vec::new())
                                        .push(event);
                                } else {
                                    self.events
                                        .entry(event.get_inode_wait_tid()?)
                                        .or_insert(Vec::new())
                                        .push(event);
                                }

                                Ok(())
                            })
                            .collect::<Result<Vec<()>>>()?;
                        self.prev_instant_ns = Some(ns_since_boot)
                    }
                    IpcBpfEvent::InodeMapCached {
                        ref comm,
                        ref tid,
                        ref sb_id,
                        ref inode_id,
                        ..
                    } => {
                        let key = StatsClosureKey::Inode {
                            comm: comm.clone(),
                            tid: *tid,
                            inode_id: *inode_id,
                            device: *sb_id,
                        };
                        let entry = self.stats_closure_events.entry(key).or_insert((None, None));
                        entry.0 = Some(event);
                    }
                    IpcBpfEvent::InodeMapPending {
                        ref comm,
                        ref tid,
                        ref sb_id,
                        ref inode_id,
                        ..
                    } => {
                        let key = StatsClosureKey::Inode {
                            comm: comm.clone(),
                            tid: *tid,
                            inode_id: *inode_id,
                            device: *sb_id,
                        };
                        let entry = self.stats_closure_events.entry(key).or_insert((None, None));
                        entry.1 = Some(event);
                    }
                    IpcBpfEvent::EpollMapCached { event_poll, .. } => {
                        let key = StatsClosureKey::EventPoll {
                            address: event_poll,
                        };
                        let entry = self.stats_closure_events.entry(key).or_insert((None, None));
                        entry.0 = Some(event);
                    }
                    IpcBpfEvent::EpollMapPending { event_poll, .. } => {
                        let key = StatsClosureKey::EventPoll {
                            address: event_poll,
                        };
                        let entry = self.stats_closure_events.entry(key).or_insert((None, None));
                        entry.1 = Some(event)
                    }
                    IpcBpfEvent::NoOp | IpcBpfEvent::AcceptStart | IpcBpfEvent::ConnectStart => {}
                    _ => {
                        println!("Unexpected ipc event {:?}", event);
                    }
                }
            }
        }
        Ok(self.events.len() + self.global_events.as_ref().map(|v| v.len()).unwrap_or(0))
    }

    pub fn take_tid_events(&mut self, tid: usize) -> Result<Vec<IpcEvent>> {
        let res = self.poll_events();
        let events = self.events.remove(&tid).unwrap_or(Vec::new());
        match (res, events.len() > 0) {
            (_, true) => Ok(events),
            (Ok(_), false) => Ok(events),
            (Err(e), false) => Err(e),
        }
    }

    pub fn take_global_events(&mut self) -> Result<Vec<IpcEvent>> {
        let res = self.poll_events();
        let events = self.global_events.take().unwrap_or(Vec::new());
        match (res, events.len() > 0) {
            (_, true) => Ok(events),
            (Ok(_), false) => Ok(events),
            (Err(e), false) => Err(e),
        }
    }

    pub fn take_process_events(&mut self) -> Result<Vec<IpcEvent>> {
        let res = self.poll_events();
        let events = self.new_process_events.take().unwrap_or(Vec::new());
        match (res, events.len() > 0) {
            (_, true) => Ok(events),
            (Ok(_), false) => Ok(events),
            (Err(e), false) => Err(e),
        }
    }
}

impl BpfReader for IpcProgram {
    fn header_read(&self) -> bool {
        self.header_lines == 1
    }

    fn header_lines_get_mut(&mut self) -> &mut u8 {
        &mut self.header_lines
    }

    fn current_event_as_mut(&mut self) -> Option<&mut Vec<u8>> {
        self.current_event.as_mut()
    }

    fn set_current_event(&mut self, val: Vec<u8>) {
        self.current_event = Some(val);
    }

    fn take_current_event(&mut self) -> Option<Vec<u8>> {
        self.current_event.take()
    }
}

impl Drop for IpcProgram {
    fn drop(&mut self) {
        if let None = self.child {
            return;
        }

        if let Err(why) = self.child.as_mut().unwrap().kill() {
            println!("Failed to kill futex {}", why);
        }
    }
}

#[cfg(test)]
mod tests {

    mod ipcbpfevent {
        use std::{net::Ipv4Addr, rc::Rc};

        use eyre::{eyre, Result};

        use super::super::{Connection, IpcBpfEvent, TargetFile};

        #[test]
        fn inode_map() -> Result<()> {
            let line = "@inode_map[tokio-runtime-w, 1257489, devpts, 24, 8]: (25617349, 1)";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::InodeMapCached {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                count,
                total_ns,
            } = event
            {
                assert_eq!(comm, Rc::from("tokio-runtime-w"));
                assert_eq!(tid, 1257489);
                assert_eq!(fs_type, Rc::from("devpts"));
                assert_eq!(sb_id, 24);
                assert_eq!(inode_id, 8);
                assert_eq!(count, 1);
                assert_eq!(total_ns, 25617349);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn inode_pending() -> Result<()> {
            let line = "@inode_pending[tokio-runtime-w, 1257489, devpts, 24, 8]: 1234";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::InodeMapPending {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                ns_since_boot,
            } = event
            {
                assert_eq!(comm, Rc::from("tokio-runtime-w"));
                assert_eq!(tid, 1257489);
                assert_eq!(fs_type, Rc::from("devpts"));
                assert_eq!(sb_id, 24);
                assert_eq!(inode_id, 8);
                assert_eq!(ns_since_boot, 1234);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn epoll_map() -> Result<()> {
            let line = "@epoll_map[0xffff8b2c5b49c000]: 25721222";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::EpollMapCached {
                event_poll,
                total_ns,
            } = event
            {
                assert_eq!(&format!("{:x}", event_poll), "ffff8b2c5b49c000");
                assert_eq!(total_ns, 25721222);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn epoll_pending() -> Result<()> {
            let line = "@epoll_pending[0xffff8b2c5b49c000]: 25721222";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::EpollMapPending {
                event_poll,
                ns_since_boot,
            } = event
            {
                assert_eq!(&format!("{:x}", event_poll), "ffff8b2c5b49c000");
                assert_eq!(ns_since_boot, 25721222);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn map_stats_start() -> Result<()> {
            let line = "=> start map statistics";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::MapStatsStart {} = event {
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn map_stats_end() -> Result<()> {
            let line = "=> end map statistics";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::MapStatsEnd {} = event {
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn accept_end() -> Result<()> {
            let line = "AcceptEnd  \tepoll_server\t339840\tsockfs\t8\t16067228\tAF_INET\t127.0.0.1\t3001\t127.0.0.1\t53520\t535862448460614\t1111111111";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            let conn_cmp = Connection::Ipv4 {
                src_host: Ipv4Addr::new(127, 0, 0, 1),
                src_port: 3001,
                dst_host: Ipv4Addr::new(127, 0, 0, 1),
                dst_port: 53520,
            };

            if let IpcBpfEvent::AcceptEnd {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                conn,
            } = event
            {
                assert_eq!(&*comm, "epoll_server");
                assert_eq!(tid, 339840);
                assert_eq!(&*fs_type, "sockfs");
                assert_eq!(sb_id, 8);
                assert_eq!(inode_id, 16067228);
                assert_eq!(conn, conn_cmp);
            } else {
                return Err(eyre!(format!("Incorrect bpf event. {:?}", event)));
            }

            Ok(())
        }

        #[test]
        fn connect_start() -> Result<()> {
            let line =
                "ConnectEnd\tepoll_server\t339840\tsockfs\t8\t16052952\tAF_INET\t127.0.0.1\t39432\t127.0.0.1\t7878\t111111111111\t1034";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            let conn_cmp = Connection::Ipv4 {
                src_host: Ipv4Addr::new(127, 0, 0, 1),
                src_port: 39432,
                dst_host: Ipv4Addr::new(127, 0, 0, 1),
                dst_port: 7878,
            };

            if let IpcBpfEvent::ConnectEnd {
                comm,
                tid,
                fs_type,
                sb_id,
                inode_id,
                conn,
            } = event
            {
                assert_eq!(&*comm, "epoll_server");
                assert_eq!(tid, 339840);
                assert_eq!(&*fs_type, "sockfs");
                assert_eq!(sb_id, 8);
                assert_eq!(inode_id, 16052952);
                assert_eq!(conn, conn_cmp);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn new_socket_map() -> Result<()> {
            let line =
                "NewSocketMap\tsockfs\t8\t16052952\tAF_INET\t127.0.0.1\t39432\t127.0.0.1\t7878";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));
            let conn_cmp = Connection::Ipv4 {
                src_host: Ipv4Addr::new(127, 0, 0, 1),
                src_port: 39432,
                dst_host: Ipv4Addr::new(127, 0, 0, 1),
                dst_port: 7878,
            };

            if let IpcBpfEvent::NewSocketMap {
                fs_type,
                sb_id,
                inode_id,
                conn,
            } = event
            {
                assert_eq!(&*fs_type, "sockfs");
                assert_eq!(sb_id, 8);
                assert_eq!(inode_id, 16052952);
                assert_eq!(conn, conn_cmp);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn new_process() -> Result<()> {
            let line = "NewProcess\texample-applica\t334444";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));
            if let IpcBpfEvent::NewProcess { comm, pid } = event {
                assert_eq!(&*comm, "example-applica");
                assert_eq!(pid, 334444);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn epoll_add() -> Result<()> {
            let line = "EpollAdd\tepoll_server\t339840\t0xffff8b2c5b49c000\tsockfs\t8\t16052950\t534439341112792\t600572454";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::EpollItemAdd {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            } = event
            {
                assert_eq!(&*comm, "epoll_server");
                assert_eq!(tid, 339840);
                assert_eq!(&format!("{:x}", event_poll), "ffff8b2c5b49c000");
                assert_eq!(&*fs, "sockfs");
                assert_eq!(
                    target_file,
                    TargetFile::Inode {
                        device: 8,
                        inode_id: 16052950
                    }
                );
                assert_eq!(ns_since_boot, 534439341112792);
                assert_eq!(contrib_snapshot, 600572454);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn epoll_remove() -> Result<()> {
            let line = "EpollRemove\tepoll_server\t339840\t0xffff8b2c5b49c000\tsockfs\t8\t16052952\t534439657922636\t1206546100";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::EpollItemRemove {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            } = event
            {
                assert_eq!(&*comm, "epoll_server");
                assert_eq!(tid, 339840);
                assert_eq!(&format!("{:x}", event_poll), "ffff8b2c5b49c000");
                assert_eq!(&*fs, "sockfs");
                assert_eq!(
                    target_file,
                    TargetFile::Inode {
                        device: 8,
                        inode_id: 16052952
                    }
                );
                assert_eq!(ns_since_boot, 534439657922636);
                assert_eq!(contrib_snapshot, 1206546100);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn epoll_item_inode() -> Result<()> {
            let line = "EpiPoll\tepoll_server\t339840\t0xffff8b2c5b49c000\tsockfs\t8\t3754233\t538189292768153\t948293676";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::EpollItem {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            } = event
            {
                assert_eq!(&*comm, "epoll_server");
                assert_eq!(tid, 339840);
                assert_eq!(&format!("{:x}", event_poll), "ffff8b2c5b49c000");
                assert_eq!(&*fs, "sockfs");
                assert_eq!(
                    target_file,
                    TargetFile::Inode {
                        device: 8,
                        inode_id: 3754233
                    }
                );
                assert_eq!(ns_since_boot, 538189292768153);
                assert_eq!(contrib_snapshot, 948293676);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }

        #[test]
        fn epoll_item_anon_inode() -> Result<()> {
            let line = "EpiPoll\tepoll_server\t339840\t0xffff8b2c5b49c000\tanon_inodefs\t[eventfd]\t0xffff8b2c5fb38000\t538285701874848\t159578";
            let event = IpcBpfEvent::from(Vec::from(line.as_bytes()));

            if let IpcBpfEvent::EpollItem {
                comm,
                tid,
                event_poll,
                fs,
                target_file,
                ns_since_boot,
                contrib_snapshot,
            } = event
            {
                assert_eq!(&*comm, "epoll_server");
                assert_eq!(tid, 339840);
                assert_eq!(&format!("{:x}", event_poll), "ffff8b2c5b49c000");
                assert_eq!(&*fs, "anon_inodefs");
                assert_eq!(
                    target_file,
                    TargetFile::AnonInode {
                        name: "[eventfd]".into(),
                        address: 0xffff8b2c5fb38000
                    }
                );
                assert_eq!(ns_since_boot, 538285701874848);
                assert_eq!(contrib_snapshot, 159578);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }

            Ok(())
        }
    }

    mod ipcprogram {
        use crate::execute::programs::{self, ipc::IpcProgram};
        use eyre::{eyre, Result};
        use indoc::indoc;
        use std::{
            io::prelude::*,
            sync::{Arc, Mutex},
            thread,
            time::Duration,
        };

        #[test]
        fn account_global() -> Result<()> {
            let (rx, mut tx) = programs::pipe();
            let mut program = IpcProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap();
            let block = indoc! {"
                HEADER

                EpollAdd\tepoll_server\t339840\t0xffff8b2c5b49c000\tsockfs\t8\t16052950\t125\t25721222
            "};
            tx.write(block.as_bytes())?;
            for _ in 0..5 {
                if program.poll_events()? != 0 {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(100));
            }

            Err(eyre!("Program did not account return global events length"))
        }
    }
}
