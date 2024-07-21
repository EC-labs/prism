use eyre::{eyre, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::os::unix::prelude::*;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::{
    io::prelude::*,
    mem,
    process::{Child, Command},
    thread,
};

use crate::execute::BpfReader;

lazy_static! {
    static ref REGEX_PATTERN: Regex = Regex::new(r"^@(\w+)\[(.*)\]: (.*)$").unwrap();
}

#[derive(Debug)]
pub enum IowaitEvent {
    Requests {
        ns_since_boot: u64,
        part0: u32,
        device: u32,
        tid: usize,
        pid: usize,
        sector_cnt: usize,
    },
}

impl IowaitEvent {
    fn from_stats_closure_entry(
        key: StatsClosureKey,
        value: usize,
        sample_instant_ns: u64,
    ) -> Self {
        Self::Requests {
            ns_since_boot: sample_instant_ns,
            part0: key.part0,
            device: key.device,
            tid: key.tid,
            pid: key.pid,
            sector_cnt: value,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IowaitBpfEvent {
    NoOp,
    MapStatsStart,
    MapStatsEnd,
    MapCompleted {
        part0: u32,
        device: u32,
        tid: usize,
        pid: usize,
        sector_cnt: usize,
    },
    MapPending {
        ns_since_boot: u64,
        part0: u32,
        device: u32,
        sector: u64,
        sector_cnt: usize,
        is_write: bool,
        op: u8,
        status: u32,
        tid: usize,
        pid: usize,
    },
    SampleInstant {
        ns_since_boot: u64,
    },
    Unexpected {
        data: String,
    },
}

impl IowaitBpfEvent {
    fn parse_line(event_string: &str) -> Result<Self> {
        if event_string.starts_with("@") {
            Self::from_summary_stats_string(event_string)
        } else if event_string.starts_with("=>") {
            Self::from_stats_closure_string(event_string)
        } else {
            Self::from_trace_string(event_string)
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
        let mut elements = event_string.split_whitespace();
        let event = match elements.next().unwrap() {
            "SampleInstant" => Self::SampleInstant {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
            },
            _ => {
                return Err(eyre!("Invalid trace data"));
            }
        };

        Ok(event)
    }

    fn from_summary_stats_string(event_string: &str) -> Result<Self> {
        let captures = REGEX_PATTERN
            .captures(&event_string)
            .ok_or(eyre!("Unexpected event string"))?;
        let mut cap_iter = captures.iter();
        cap_iter.next();

        let map_type = cap_iter.next().unwrap().unwrap().as_str();
        match map_type {
            "completed" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let mut key_elements = key.split(", ");

                let value = cap_iter.next().unwrap().unwrap().as_str();

                Ok(Self::MapCompleted {
                    part0: key_elements.next().unwrap().parse().unwrap(),
                    device: key_elements.next().unwrap().parse().unwrap(),
                    tid: key_elements.next().unwrap().parse().unwrap(),
                    pid: key_elements.next().unwrap().parse().unwrap(),
                    sector_cnt: value.parse().unwrap(),
                })
            }
            "pending" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let mut key_elements = key.split(", ");
                let value = cap_iter.next().unwrap().unwrap().as_str();
                let value = &value[1..value.len() - 1];
                let mut value_elements = value.split(", ");

                Ok(Self::MapPending {
                    part0: key_elements.next().unwrap().parse().unwrap(),
                    device: key_elements.next().unwrap().parse().unwrap(),
                    sector: key_elements.next().unwrap().parse().unwrap(),
                    is_write: key_elements.next().unwrap().parse::<i8>().unwrap() > 0,
                    op: key_elements.next().unwrap().parse().unwrap(),
                    status: key_elements.next().unwrap().parse().unwrap(),
                    ns_since_boot: value_elements.next().unwrap().parse().unwrap(),
                    tid: value_elements.next().unwrap().parse().unwrap(),
                    pid: value_elements.next().unwrap().parse().unwrap(),
                    sector_cnt: value_elements.next().unwrap().parse().unwrap(),
                })
            }
            _ => Err(eyre!("Invalid map type")),
        }
    }
}

impl From<Vec<u8>> for IowaitBpfEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        if event_string.len() == 0 {
            return Self::NoOp {};
        }
        Self::parse_line(&event_string).unwrap_or(Self::Unexpected { data: event_string })
    }
}

#[derive(PartialEq, Eq, Hash)]
struct StatsClosureKey {
    part0: u32,
    device: u32,
    pid: usize,
    tid: usize,
}

pub struct IOWaitProgram {
    child: Option<Child>,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
    events: Option<Vec<IowaitEvent>>,
    stats_closure_events: HashMap<StatsClosureKey, usize>,
    sample_instant_ns: Option<u64>,
    rx: Receiver<Arc<[u8]>>,
}

impl IOWaitProgram {
    pub fn new(terminate_flag: Arc<Mutex<bool>>) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();

        let (bpf_pipe_rx, bpf_pipe_tx) = super::pipe();
        let res = unsafe { libc::fcntl(bpf_pipe_rx.as_raw_fd(), libc::F_SETPIPE_SZ, 1048576) };
        if res != 0 {
            println!("Non-zero fcntl return {:?}", res);
        }
        let res = unsafe { libc::fcntl(bpf_pipe_tx.as_raw_fd(), libc::F_SETPIPE_SZ, 1048576) };
        if res != 0 {
            println!("Non-zero fcntl return {:?}", res);
        }
        let child = Command::new("bpftrace")
            .args(["./metric-collector/src/bpf/io_wait.bt"])
            .stdout(bpf_pipe_tx)
            .spawn()?;
        Self::start_bpf_reader(tx, bpf_pipe_rx, terminate_flag);
        Ok(Self {
            rx,
            child: Some(child),
            header_lines: 0,
            current_event: None,
            stats_closure_events: HashMap::new(),
            sample_instant_ns: None,
            events: None,
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
            .name("iowait_recv".to_string())
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
}

impl BpfReader for IOWaitProgram {
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

impl IOWaitProgram {
    pub fn custom_reader<R: Read + Send + 'static>(
        reader: R,
        terminate_flag: Arc<Mutex<bool>>,
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self::start_bpf_reader(tx, reader, terminate_flag);
        Self {
            rx,
            child: None,
            header_lines: 0,
            current_event: None,
            stats_closure_events: HashMap::new(),
            sample_instant_ns: None,
            events: None,
        }
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
                let event = IowaitBpfEvent::from(event);
                match event {
                    IowaitBpfEvent::NoOp {} => {}
                    IowaitBpfEvent::MapStatsStart {} => {}
                    IowaitBpfEvent::MapStatsEnd {} => {
                        let sample_instant_ns = self.sample_instant_ns.take().unwrap();
                        let closure_events =
                            mem::replace(&mut self.stats_closure_events, HashMap::new());
                        closure_events.into_iter().for_each(|(key, value)| {
                            let events = self.events.get_or_insert_with(|| Vec::new());
                            events.push(IowaitEvent::from_stats_closure_entry(
                                key,
                                value,
                                sample_instant_ns,
                            ));
                        });
                    }
                    IowaitBpfEvent::MapPending {
                        pid,
                        tid,
                        part0,
                        device,
                        sector_cnt,
                        ..
                    } => {
                        let key = StatsClosureKey {
                            pid,
                            tid,
                            part0,
                            device,
                        };
                        let entry = self.stats_closure_events.entry(key).or_insert(0);
                        *entry += sector_cnt;
                    }
                    IowaitBpfEvent::MapCompleted {
                        pid,
                        tid,
                        part0,
                        device,
                        sector_cnt,
                    } => {
                        let key = StatsClosureKey {
                            pid,
                            tid,
                            part0,
                            device,
                        };
                        let entry = self.stats_closure_events.entry(key).or_insert(0);
                        *entry += sector_cnt;
                    }
                    IowaitBpfEvent::SampleInstant { ns_since_boot } => {
                        self.sample_instant_ns = Some(ns_since_boot);
                    }
                    IowaitBpfEvent::Unexpected { data } => {
                        println!("Unexpected iowait event. {:?}", data)
                    }
                }
            }
        }
        Ok(self.events.as_ref().map_or(0, |events| events.len()))
    }

    pub fn take_events(&mut self) -> Result<Vec<IowaitEvent>> {
        let res = self.poll_events();
        match res {
            Ok(_) => Ok(self.events.take().unwrap_or(Vec::new())),
            Err(e) => {
                let events = self.events.take();
                if events.is_some() {
                    Ok(events.unwrap())
                } else {
                    Err(e)
                }
            }
        }
    }
}

impl Drop for IOWaitProgram {
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
    mod iowaitbpfevents {
        use super::super::IowaitBpfEvent;
        use eyre::{eyre, Result};

        #[test]
        fn no_op() {
            let line = "";
            let event = IowaitBpfEvent::from(Vec::from(line.as_bytes()));
            assert_eq!(event, IowaitBpfEvent::NoOp {})
        }

        #[test]
        fn map_completed() -> Result<()> {
            let line = "@completed[271581184, 271581187, 632, 631]: 22616";
            let event = IowaitBpfEvent::from(Vec::from(line.as_bytes()));
            if let IowaitBpfEvent::MapCompleted {
                part0,
                device,
                tid,
                pid,
                sector_cnt,
            } = event
            {
                assert_eq!(part0, 271581184);
                assert_eq!(device, 271581187);
                assert_eq!(tid, 632);
                assert_eq!(pid, 631);
                assert_eq!(sector_cnt, 22616);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }
            Ok(())
        }

        #[test]
        fn map_pending() -> Result<()> {
            let line =
                "@pending[271581184, 271581187, 1649015544, 1, 1, 0]: (1421282887324, 632, 631, 8)";
            let event = IowaitBpfEvent::from(Vec::from(line.as_bytes()));
            if let IowaitBpfEvent::MapPending {
                ns_since_boot,
                part0,
                device,
                sector,
                sector_cnt,
                is_write,
                op,
                status,
                tid,
                pid,
            } = event
            {
                assert_eq!(part0, 271581184);
                assert_eq!(device, 271581187);
                assert_eq!(sector, 1649015544);
                assert_eq!(is_write, true);
                assert_eq!(op, 1);
                assert_eq!(status, 0);
                assert_eq!(ns_since_boot, 1421282887324);
                assert_eq!(tid, 632);
                assert_eq!(pid, 631);
                assert_eq!(sector_cnt, 8);
            } else {
                return Err(eyre!("Incorrect bpf event"));
            }
            Ok(())
        }

        #[test]
        fn map_stats_start() {
            let line = "=> start map statistics";
            let event = IowaitBpfEvent::from(Vec::from(line.as_bytes()));
            assert_eq!(event, IowaitBpfEvent::MapStatsStart {});
        }

        #[test]
        fn map_stats_end() {
            let line = "=> end map statistics";
            let event = IowaitBpfEvent::from(Vec::from(line.as_bytes()));
            assert_eq!(event, IowaitBpfEvent::MapStatsEnd {});
        }

        #[test]
        fn sample_instant() {
            let line = "SampleInstant   1421348499285";
            let event = IowaitBpfEvent::from(Vec::from(line.as_bytes()));
            assert_eq!(
                event,
                IowaitBpfEvent::SampleInstant {
                    ns_since_boot: 1421348499285
                }
            );
        }
    }
}
