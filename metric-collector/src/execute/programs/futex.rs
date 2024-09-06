use eyre::{eyre, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    collections::HashMap,
    io::prelude::*,
    mem,
    process::{Child, Command},
    rc::Rc,
    sync::{
        mpsc::{self, Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    thread,
};

use crate::execute::BpfReader;

lazy_static! {
    static ref REGEX_PATTERN: Regex = Regex::new(r"^@(\w+)\[(.*)\]: (.*)$").unwrap();
}

#[derive(PartialEq, Eq, Debug)]
enum FutexBpfEvent {
    NoOp,
    NewProcess {
        comm: Rc<str>,
        pid: usize,
    },
    Unexpected {
        data: String,
    },
    UnhandledOpcode {
        opcode: String,
    },
    WaitElapsed {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        total_interval_wait_ns: u64,
        count_interval_wait: usize,
    },
    WaitPending {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        ns_since_boot: u64,
    },
    Wake {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        count: usize,
    },
    SampleInstant {
        ns_since_boot: u64,
    },
    MapStatsStart,
    MapStatsEnd,
}

impl FutexBpfEvent {
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
            "wait_elapsed" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let mut key_elements = key.split(", ");

                let value = cap_iter.next().unwrap().unwrap().as_str();
                let value = &value[1..value.len() - 1];
                let mut value_elements = value.split(", ");

                Ok(Self::WaitElapsed {
                    tid: key_elements.next().unwrap().parse().unwrap(),
                    root_pid: key_elements.next().unwrap().parse().unwrap(),
                    uaddr: key_elements.next().unwrap().into(),
                    total_interval_wait_ns: value_elements.next().unwrap().parse().unwrap(),
                    count_interval_wait: value_elements.next().unwrap().parse().unwrap(),
                })
            }
            "wait_pending" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let mut key_elements = key.split(", ");

                let value = cap_iter.next().unwrap().unwrap().as_str();
                let value = &value[1..value.len() - 1];
                let mut value_elements = value.split(", ");

                Ok(Self::WaitPending {
                    tid: key_elements.next().unwrap().parse().unwrap(),
                    ns_since_boot: value_elements.next().unwrap().parse().unwrap(),
                    root_pid: value_elements.next().unwrap().parse().unwrap(),
                    uaddr: value_elements.next().unwrap().into(),
                })
            }
            "wake" => {
                let key = cap_iter.next().unwrap().unwrap().as_str();
                let mut key_elements = key.split(", ");

                let value = cap_iter.next().unwrap().unwrap().as_str();
                let mut value_elements = value.split(", ");

                Ok(Self::Wake {
                    tid: key_elements.next().unwrap().parse().unwrap(),
                    root_pid: key_elements.next().unwrap().parse().unwrap(),
                    uaddr: key_elements.next().unwrap().into(),
                    count: value_elements.next().unwrap().parse().unwrap(),
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
        let mut elements = event_string.split_whitespace();
        match elements.next().unwrap() {
            "UnhandledOpcode" => Ok(Self::UnhandledOpcode {
                opcode: elements.next().unwrap().into(),
            }),
            "NewProcess" => Ok(Self::NewProcess {
                comm: elements.next().unwrap().into(),
                pid: elements.next().unwrap().parse().unwrap(),
            }),
            "SampleInstant" => Ok(Self::SampleInstant {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
            }),
            _ => Ok(Self::Unexpected {
                data: event_string.into(),
            }),
        }
    }
}

impl From<Vec<u8>> for FutexBpfEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        if event_string.len() == 0 {
            return Self::NoOp {};
        }
        Self::parse_line(&event_string).unwrap_or(Self::Unexpected { data: event_string })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FutexEvent {
    Wait {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        sample_instant_ns: u64,
        total_interval_wait_ns: u64,
        count: usize,
    },
    Wake {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        sample_instant_ns: u64,
        count: usize,
    },
}

impl FutexEvent {
    fn from_stats_closure_value(
        entry: StatsClosureValue,
        current_instant_ns: u64,
        previous_instant_ns: Option<u64>,
    ) -> Result<Self> {
        match entry {
            StatsClosureValue::Wait(
                None,
                Some(FutexBpfEvent::WaitPending {
                    tid,
                    root_pid,
                    uaddr,
                    ns_since_boot,
                }),
            ) => {
                let pending = if let Some(prev) = previous_instant_ns {
                    if ns_since_boot > prev {
                        i64::max(current_instant_ns as i64 - ns_since_boot as i64, 0) as u64
                    } else {
                        current_instant_ns - prev
                    }
                } else {
                    i64::max(current_instant_ns as i64 - ns_since_boot as i64, 0) as u64
                };

                Ok(Self::Wait {
                    tid,
                    root_pid,
                    uaddr,
                    sample_instant_ns: current_instant_ns,
                    total_interval_wait_ns: pending,
                    count: 0,
                })
            }
            StatsClosureValue::Wait(
                Some(FutexBpfEvent::WaitElapsed {
                    tid,
                    root_pid,
                    uaddr,
                    total_interval_wait_ns,
                    count_interval_wait,
                }),
                None,
            ) => Ok(Self::Wait {
                tid,
                root_pid,
                uaddr,
                sample_instant_ns: current_instant_ns,
                total_interval_wait_ns,
                count: count_interval_wait,
            }),
            StatsClosureValue::Wait(
                Some(FutexBpfEvent::WaitElapsed {
                    tid,
                    root_pid,
                    uaddr,
                    total_interval_wait_ns,
                    count_interval_wait,
                }),
                Some(FutexBpfEvent::WaitPending { ns_since_boot, .. }),
            ) => {
                let pending = if let Some(prev) = previous_instant_ns {
                    if ns_since_boot > prev {
                        i64::max(current_instant_ns as i64 - ns_since_boot as i64, 0) as u64
                    } else {
                        current_instant_ns - prev
                    }
                } else {
                    i64::max(current_instant_ns as i64 - ns_since_boot as i64, 0) as u64
                };

                Ok(Self::Wait {
                    tid,
                    root_pid,
                    uaddr,
                    sample_instant_ns: current_instant_ns,
                    total_interval_wait_ns: total_interval_wait_ns + pending,
                    count: count_interval_wait,
                })
            }
            StatsClosureValue::Wake(FutexBpfEvent::Wake {
                tid,
                root_pid,
                uaddr,
                count,
            }) => Ok(Self::Wake {
                tid,
                root_pid,
                uaddr,
                count,
                sample_instant_ns: current_instant_ns,
            }),
            _ => Err(eyre!(format!(
                "Inconsistent stat closure value state {:?}.",
                entry
            ))),
        }
    }
}

// impl ToCsv for FutexEvent {
//     fn to_csv_row(&self) -> String {
//         match self {
//             FutexEvent::Wake {
//                 tid,
//                 root_pid,
//                 uaddr,
//                 ns_since_boot,
//                 ..
//             } => {
//                 let epoch_ns = *BOOT_EPOCH_NS.read().unwrap() + ns_since_boot;
//                 format!("{},{},{},{}\n", epoch_ns, tid, root_pid, uaddr,)
//             }
//             FutexEvent::Elapsed {
//                 tid,
//                 root_pid,
//                 uaddr,
//                 ns_since_boot,
//                 ns_elapsed,
//                 ..
//             } => {
//                 let end_epoch_ns = *BOOT_EPOCH_NS.read().unwrap() + ns_since_boot;
//                 let start_epoch_ns = end_epoch_ns - ns_elapsed;
//                 format!(
//                     "{},{},{},{},{},{}\n",
//                     start_epoch_ns, end_epoch_ns, ns_elapsed, tid, root_pid, uaddr,
//                 )
//             }
//             _ => {
//                 todo!()
//             }
//         }
//     }

//     fn csv_headers(&self) -> &'static str {
//         match self {
//             FutexEvent::Wake { .. } => "epoch_ns,tid,root_pid,uaddr\n",
//             FutexEvent::Elapsed { .. } => {
//                 "start_epoch_ns,end_epoch_ns,elapsed_ns,tid,root_pid,uaddr\n"
//             }
//             _ => {
//                 todo!()
//             }
//         }
//     }
// }

enum FutexProgramState {
    OutStatClosure,
    InStatClosure(Option<u64>),
}

#[derive(PartialEq, Eq, Hash)]
enum StatsClosureKey {
    Wait {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
    },
    Wake {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
    },
}

#[derive(Debug)]
enum StatsClosureValue {
    Wait(Option<FutexBpfEvent>, Option<FutexBpfEvent>),
    Wake(FutexBpfEvent),
}

pub struct FutexProgram {
    child: Option<Child>,
    rx: Receiver<Arc<[u8]>>,
    events: HashMap<usize, Vec<FutexEvent>>,
    new_pids: Option<Vec<(Rc<str>, usize)>>,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
    state: FutexProgramState,
    stats_closure_events: HashMap<StatsClosureKey, StatsClosureValue>,
    prev_instant_ns: Option<u64>,
}

impl BpfReader for FutexProgram {
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

impl FutexProgram {
    pub fn new(pid: u32, terminate_flag: Arc<Mutex<bool>>) -> Result<Self> {
        let (bpf_pipe_rx, bpf_pipe_tx) = super::bpf_pipe(1_048_576);
        let (tx, rx) = mpsc::channel();
        let child = Command::new("bpftrace")
            .args([
                "./metric-collector/src/bpf/futex_wait.bt",
                &format!("{}", pid),
            ])
            .stdout(bpf_pipe_tx)
            .spawn()?;
        Self::start_bpf_reader(tx, bpf_pipe_rx, terminate_flag);
        Ok(Self {
            child: Some(child),
            rx,
            events: HashMap::new(),
            header_lines: 0,
            current_event: None,
            new_pids: None,
            state: FutexProgramState::OutStatClosure,
            stats_closure_events: HashMap::new(),
            prev_instant_ns: None,
        })
    }

    pub fn custom_reader<R: Read + Send + 'static>(
        reader: R,
        terminate_flag: Arc<Mutex<bool>>,
    ) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        Self::start_bpf_reader(tx, reader, terminate_flag);

        Ok(Self {
            rx,
            child: None,
            header_lines: 0,
            current_event: None,
            events: HashMap::new(),
            new_pids: None,
            stats_closure_events: HashMap::new(),
            state: FutexProgramState::OutStatClosure,
            prev_instant_ns: None,
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
            .name("futex_recv".to_string())
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
                let event = FutexBpfEvent::from(event);
                match event {
                    FutexBpfEvent::NewProcess { pid, comm } => {
                        let new_pids = self.new_pids.get_or_insert_with(|| Vec::new());
                        new_pids.push((comm.clone(), pid));
                    }
                    FutexBpfEvent::MapStatsStart => {
                        self.state = FutexProgramState::InStatClosure(None);
                    }
                    FutexBpfEvent::SampleInstant { ns_since_boot } => {
                        if let FutexProgramState::InStatClosure(sample_instant_ns) = &mut self.state
                        {
                            *sample_instant_ns = Some(ns_since_boot);
                        }
                    }
                    FutexBpfEvent::MapStatsEnd => {
                        let ns_since_boot =
                            if let FutexProgramState::InStatClosure(Some(ns_since_boot)) =
                                self.state
                            {
                                ns_since_boot
                            } else {
                                return Err(eyre!("Inconsistent ipc program state"));
                            };
                        self.state = FutexProgramState::OutStatClosure;

                        let events = mem::replace(&mut self.stats_closure_events, HashMap::new());
                        events.into_iter().for_each(|(_, entry)| {
                            let event = FutexEvent::from_stats_closure_value(
                                entry,
                                ns_since_boot,
                                self.prev_instant_ns,
                            )
                            .expect("Unsuccesful conversion from stat closure entry to FutexEvent");
                            if let FutexEvent::Wait { tid, .. } | FutexEvent::Wake { tid, .. } =
                                event
                            {
                                let tevents = self.events.entry(tid).or_insert_with(|| Vec::new());
                                tevents.push(event);
                            }
                        });
                        self.prev_instant_ns = Some(ns_since_boot);
                    }
                    FutexBpfEvent::UnhandledOpcode { .. } => {
                        println!("Futex unhandled opcode. {:?}", event);
                    }
                    FutexBpfEvent::Unexpected { .. } => {
                        println!("Futex unexpected event. {:?}", event);
                    }
                    FutexBpfEvent::WaitElapsed {
                        tid,
                        root_pid,
                        ref uaddr,
                        ..
                    } => {
                        let key = StatsClosureKey::Wait {
                            tid,
                            root_pid,
                            uaddr: uaddr.clone(),
                        };
                        let entry = self
                            .stats_closure_events
                            .entry(key)
                            .or_insert(StatsClosureValue::Wait(None, None));
                        if let StatsClosureValue::Wait(elapsed, _pending) = entry {
                            *elapsed = Some(event);
                        }
                    }
                    FutexBpfEvent::WaitPending {
                        tid,
                        root_pid,
                        ref uaddr,
                        ..
                    } => {
                        let key = StatsClosureKey::Wait {
                            tid,
                            root_pid,
                            uaddr: uaddr.clone(),
                        };
                        let entry = self
                            .stats_closure_events
                            .entry(key)
                            .or_insert(StatsClosureValue::Wait(None, None));
                        if let StatsClosureValue::Wait(_elapsed, pending) = entry {
                            *pending = Some(event);
                        }
                    }
                    FutexBpfEvent::Wake {
                        tid,
                        root_pid,
                        ref uaddr,
                        ..
                    } => {
                        let key = StatsClosureKey::Wake {
                            tid,
                            root_pid,
                            uaddr: uaddr.clone(),
                        };
                        self.stats_closure_events
                            .entry(key)
                            .or_insert(StatsClosureValue::Wake(event));
                    }
                    FutexBpfEvent::NoOp => {}
                }
            }
        }
        Ok(self.events.len())
    }

    pub fn take_futex_events(&mut self, tid: usize) -> Result<Vec<FutexEvent>> {
        let res = self.poll_events();
        let events = self.events.remove(&tid).unwrap_or(Vec::new());
        match (res, events.len() > 0) {
            (_, true) => Ok(events),
            (Ok(_), false) => Ok(events),
            (Err(e), false) => Err(e),
        }
    }

    pub fn take_new_pid_events(&mut self) -> Result<Vec<(Rc<str>, usize)>> {
        self.poll_events()?;
        Ok(self.new_pids.take().unwrap_or(Vec::new()))
    }
}

impl Drop for FutexProgram {
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
    use super::{FutexBpfEvent, FutexProgram};
    use eyre::{eyre, Result};

    mod futex_event {
        use super::*;

        #[test]
        fn trace_map_stats_start() {
            let line = "=> start map statistics";
            let event = FutexBpfEvent::from(Vec::from(line.as_bytes()));
            assert_eq!(event, FutexBpfEvent::MapStatsStart);
        }

        #[test]
        fn trace_map_stats_end() {
            let line = "=> end map statistics";
            let event = FutexBpfEvent::from(Vec::from(line.as_bytes()));
            assert_eq!(event, FutexBpfEvent::MapStatsEnd);
        }

        #[test]
        fn trace_sample_instant() {
            let line = "SampleInstant  	65383570923944";
            let event = FutexBpfEvent::from(Vec::from(line.as_bytes()));
            assert_eq!(
                event,
                FutexBpfEvent::SampleInstant {
                    ns_since_boot: 65383570923944
                }
            );
        }

        #[test]
        fn map_wait_elapsed() -> Result<()> {
            let line = "@wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (847638877, 4)";
            let event = FutexBpfEvent::from(Vec::from(line.as_bytes()));
            if let FutexBpfEvent::WaitElapsed {
                tid,
                root_pid,
                uaddr,
                total_interval_wait_ns,
                count_interval_wait,
            } = event
            {
                assert_eq!(tid, 8955);
                assert_eq!(root_pid, 8877);
                assert_eq!(&*uaddr, "0x7c3dd4f85fb0");
                assert_eq!(total_interval_wait_ns, 847638877);
                assert_eq!(count_interval_wait, 4);
            } else {
                return Err(eyre!("Incorrect FutexBpfEvent"));
            }
            Ok(())
        }

        #[test]
        fn map_wait_pending() -> Result<()> {
            let line = "@wait_pending[8955]: (65384418811815, 8877, 0x7c3dd4f85fb0)";
            let event = FutexBpfEvent::from(Vec::from(line.as_bytes()));
            if let FutexBpfEvent::WaitPending {
                tid,
                root_pid,
                uaddr,
                ns_since_boot,
            } = event
            {
                assert_eq!(tid, 8955);
                assert_eq!(root_pid, 8877);
                assert_eq!(&*uaddr, "0x7c3dd4f85fb0");
                assert_eq!(ns_since_boot, 65384418811815);
            } else {
                return Err(eyre!("Incorrect FutexBpfEvent"));
            }

            Ok(())
        }

        #[test]
        fn map_wake() -> Result<()> {
            let line = "@wake[8986, 8877, 0x7c3cfc00560c]: 1";
            let event = FutexBpfEvent::from(Vec::from(line.as_bytes()));
            if let FutexBpfEvent::Wake {
                tid,
                root_pid,
                uaddr,
                count,
            } = event
            {
                assert_eq!(tid, 8986);
                assert_eq!(root_pid, 8877);
                assert_eq!(&*uaddr, "0x7c3cfc00560c");
                assert_eq!(count, 1);
            } else {
                return Err(eyre!("Incorrect FutexBpfEvent"));
            }

            Ok(())
        }
    }

    mod futex_program {
        use indoc::indoc;
        use std::{
            io::prelude::*,
            rc::Rc,
            sync::{Arc, Mutex},
        };

        use super::super::FutexEvent;
        use super::*;
        use crate::execute::programs;

        #[test]
        fn single_wait_elapsed() -> Result<()> {
            let (rx, mut tx) = programs::pipe();
            let mut program = FutexProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap();
            let bpf_content = indoc! {"
                HEADER 

                => start map statistics
                @wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (847638877, 4)
                SampleInstant  	65384570945103
                => end map statistics
            "};
            tx.write(bpf_content.as_bytes())?;
            while let Ok(0) = program.poll_events() {}

            let event = program
                .take_futex_events(8955)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(
                event,
                FutexEvent::Wait {
                    tid: 8955,
                    root_pid: 8877,
                    uaddr: Rc::from("0x7c3dd4f85fb0"),
                    sample_instant_ns: 65384570945103,
                    total_interval_wait_ns: 847638877,
                    count: 4
                }
            );

            Ok(())
        }

        #[test]
        fn single_wait_elapsed_and_pending() -> Result<()> {
            let (rx, mut tx) = programs::pipe();
            let mut program = FutexProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap();
            let bpf_content = indoc! {"
                HEADER 

                => start map statistics
                @wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (847638877, 4)
                @wait_pending[8955]: (65384418811815, 8877, 0x7c3dd4f85fb0)
                SampleInstant  	65384570945103
                => end map statistics
            "};
            tx.write(bpf_content.as_bytes())?;
            while let Ok(0) = program.poll_events() {}

            let event = program
                .take_futex_events(8955)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(
                event,
                FutexEvent::Wait {
                    tid: 8955,
                    root_pid: 8877,
                    uaddr: Rc::from("0x7c3dd4f85fb0"),
                    sample_instant_ns: 65384570945103,
                    total_interval_wait_ns: 847638877 + (65384570945103 - 65384418811815),
                    count: 4
                }
            );

            Ok(())
        }

        #[test]
        fn single_pending() -> Result<()> {
            let (rx, mut tx) = programs::pipe();
            let mut program = FutexProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap();
            let bpf_content = indoc! {"
                HEADER 

                => start map statistics
                @wait_pending[8955]: (65384418811815, 8877, 0x7c3dd4f85fb0)
                SampleInstant  	65384570945103
                => end map statistics
            "};
            tx.write(bpf_content.as_bytes())?;
            while let Ok(0) = program.poll_events() {}

            let event = program
                .take_futex_events(8955)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(
                event,
                FutexEvent::Wait {
                    tid: 8955,
                    root_pid: 8877,
                    uaddr: Rc::from("0x7c3dd4f85fb0"),
                    sample_instant_ns: 65384570945103,
                    total_interval_wait_ns: 65384570945103 - 65384418811815,
                    count: 0
                }
            );

            Ok(())
        }

        #[test]
        fn single_wake() -> Result<()> {
            let (rx, mut tx) = programs::pipe();
            let mut program = FutexProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap();
            let bpf_content = indoc! {"
                HEADER 

                => start map statistics
                @wake[8986, 8877, 0x7c3cfc00560c]: 1
                SampleInstant  	65384570945103
                => end map statistics
            "};
            tx.write(bpf_content.as_bytes())?;
            while let Ok(0) = program.poll_events() {}

            let event = program
                .take_futex_events(8986)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(
                event,
                FutexEvent::Wake {
                    tid: 8986,
                    root_pid: 8877,
                    uaddr: Rc::from("0x7c3cfc00560c"),
                    sample_instant_ns: 65384570945103,
                    count: 1
                }
            );

            Ok(())
        }

        #[test]
        fn two_consecutive_map_stat_closures() -> Result<()> {
            let (rx, mut tx) = programs::pipe();
            let mut program = FutexProgram::custom_reader(rx, Arc::new(Mutex::new(false))).unwrap();
            let bpf_content = indoc! {"
                HEADER 

                => start map statistics
                @wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (847638877, 4)
                @wait_pending[8955]: (65384418811815, 8877, 0x7c3dd4f85fb0)
                SampleInstant  	65384570945103
                => end map statistics

                => start map statistics
                @wait_elapsed[8955, 8877, 0x7c3dd4f85fb0]: (748486373, 4)
                @wait_pending[8955]: (65385319694788, 8877, 0x7c3dd4f85fb0)
                SampleInstant  	65385570860594
                => end map statistics
            "};
            tx.write(bpf_content.as_bytes())?;
            while let Ok(0) = program.poll_events() {}

            let mut events = program.take_futex_events(8955).unwrap();
            events.sort_by(|a, b| {
                let a_instant = match a {
                    FutexEvent::Wake {
                        sample_instant_ns, ..
                    }
                    | FutexEvent::Wait {
                        sample_instant_ns, ..
                    } => sample_instant_ns,
                };
                let b_instant = match b {
                    FutexEvent::Wake {
                        sample_instant_ns, ..
                    }
                    | FutexEvent::Wait {
                        sample_instant_ns, ..
                    } => sample_instant_ns,
                };
                a_instant.partial_cmp(b_instant).unwrap()
            });
            let mut events_iter = events.into_iter();
            assert_eq!(
                events_iter.next().unwrap(),
                FutexEvent::Wait {
                    tid: 8955,
                    root_pid: 8877,
                    uaddr: Rc::from("0x7c3dd4f85fb0"),
                    sample_instant_ns: 65384570945103,
                    total_interval_wait_ns: 847638877 + (65384570945103 - 65384418811815),
                    count: 4
                }
            );
            assert_eq!(
                events_iter.next().unwrap(),
                FutexEvent::Wait {
                    tid: 8955,
                    root_pid: 8877,
                    uaddr: Rc::from("0x7c3dd4f85fb0"),
                    sample_instant_ns: 65385570860594,
                    total_interval_wait_ns: 748486373 + (65385570860594 - 65385319694788),
                    count: 4
                }
            );

            Ok(())
        }
    }
}
