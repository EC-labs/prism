use eyre::Result;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::process::{Child, Command};
use std::rc::Rc;
use std::{fs::File, io::prelude::*};

use super::BOOT_EPOCH_NS;
use crate::metrics::ToCsv;

#[derive(Debug)]
pub enum FutexEvent {
    Start {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        ns_since_boot: u128,
    },
    Elapsed {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        ns_since_boot: u128,
        ns_elapsed: u128,
        ret: i32,
    },
    Wake {
        tid: usize,
        root_pid: usize,
        uaddr: Rc<str>,
        ns_since_boot: u128,
        ret: i32,
    },
    NewProcess {
        comm: Rc<str>,
        pid: usize,
    },
    UnhandledOpcode {
        opcode: String,
    },
    Unexpected {
        data: String,
    },
}

impl From<Vec<u8>> for FutexEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        let event_string = event_string.replace(" ", "");

        let mut elements = event_string.split("\t");
        match elements.next().unwrap() {
            "WaitStart" => Self::Start {
                tid: elements.next().unwrap().parse().unwrap(),
                root_pid: elements.next().unwrap().parse().unwrap(),
                uaddr: Rc::from(elements.next().unwrap()),
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
            },
            "WaitElapsed" => Self::Elapsed {
                tid: elements.next().unwrap().parse().unwrap(),
                root_pid: elements.next().unwrap().parse().unwrap(),
                uaddr: Rc::from(elements.next().unwrap()),
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                ns_elapsed: elements.next().unwrap().parse().unwrap(),
                ret: elements.next().unwrap().parse().unwrap(),
            },
            "Wake" => Self::Wake {
                tid: elements.next().unwrap().parse().unwrap(),
                root_pid: elements.next().unwrap().parse().unwrap(),
                uaddr: Rc::from(elements.next().unwrap()),
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                ret: elements.next().unwrap().parse().unwrap(),
            },
            "UnhandledOpcode" => Self::UnhandledOpcode {
                opcode: elements.next().unwrap().into(),
            },
            "NewProcess" => Self::NewProcess {
                comm: elements.next().unwrap().into(),
                pid: elements.next().unwrap().parse().unwrap(),
            },
            _ => Self::Unexpected { data: event_string },
        }
    }
}

impl ToCsv for FutexEvent {
    fn to_csv_row(&self) -> String {
        match self {
            FutexEvent::Wake {
                tid,
                root_pid,
                uaddr,
                ns_since_boot,
                ..
            } => {
                let epoch_ns = *BOOT_EPOCH_NS.read().unwrap() + ns_since_boot;
                format!("{},{},{},{}\n", epoch_ns, tid, root_pid, uaddr,)
            }
            FutexEvent::Elapsed {
                tid,
                root_pid,
                uaddr,
                ns_since_boot,
                ns_elapsed,
                ..
            } => {
                let end_epoch_ns = *BOOT_EPOCH_NS.read().unwrap() + ns_since_boot;
                let start_epoch_ns = end_epoch_ns - ns_elapsed;
                format!(
                    "{},{},{},{},{},{}\n",
                    start_epoch_ns, end_epoch_ns, ns_elapsed, tid, root_pid, uaddr,
                )
            }
            _ => {
                todo!()
            }
        }
    }

    fn csv_headers(&self) -> &'static str {
        match self {
            FutexEvent::Wake { .. } => "epoch_ns,tid,root_pid,uaddr\n",
            FutexEvent::Elapsed { .. } => {
                "start_epoch_ns,end_epoch_ns,elapsed_ns,tid,root_pid,uaddr\n"
            }
            _ => {
                todo!()
            }
        }
    }
}

pub struct FutexProgram {
    child: Child,
    reader: File,
    events: HashMap<usize, Vec<FutexEvent>>,
    new_pids: Option<Vec<(Rc<str>, usize)>>,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
}

impl FutexProgram {
    pub fn new(pid: u32) -> Result<Self> {
        let (mut reader, writer) = super::pipe();
        super::fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let child = Command::new("bpftrace")
            .args([
                "./metric-collector/src/bpf/futex_wait.bt",
                &format!("{}", pid),
            ])
            .stdout(writer)
            .spawn()?;
        Ok(Self {
            child,
            reader,
            events: HashMap::new(),
            header_lines: 0,
            current_event: None,
            new_pids: None,
        })
    }

    fn handle_header<'a, I: Iterator<Item = &'a u8>>(&mut self, buf: &mut I) {
        while !self.header_read() {
            let newline = buf.find(|&&b| b == b'\n');
            if let Some(_) = newline {
                self.header_lines += 1;
            } else {
                break;
            }
        }
    }

    fn handle_event<'a, I: Iterator<Item = &'a u8>>(&mut self, buf: &mut I) -> Option<Vec<u8>> {
        if let None = self.current_event {
            self.current_event = Some(Vec::new());
        }

        while let Some(byte) = buf.next() {
            if *byte != b'\n' {
                self.current_event.as_mut().map(|curr| curr.push(*byte));
            } else {
                return self.current_event.take();
            }
        }
        return None;
    }

    pub fn header_read(&self) -> bool {
        self.header_lines == 1
    }

    pub fn poll_events(&mut self) -> Result<()> {
        loop {
            let mut buf: [u8; 256] = [0; 256];
            let bytes = self.reader.read(&mut buf);

            let bytes = match bytes {
                Err(error) => {
                    let kind = error.kind();
                    if kind == ErrorKind::WouldBlock {
                        break;
                    }

                    return Err(error.into());
                }
                Ok(bytes) => {
                    if bytes == 0 {
                        break;
                    }
                    bytes
                }
            };

            let mut iterator = buf[..bytes].into_iter();
            if !self.header_read() {
                self.handle_header(&mut iterator);
            }
            while let Some(event) = self.handle_event(&mut iterator) {
                let event = FutexEvent::from(event);
                match &event {
                    FutexEvent::Start { tid, .. }
                    | FutexEvent::Elapsed { tid, .. }
                    | FutexEvent::Wake { tid, .. } => {
                        let tid_events = self.events.get_mut(tid);
                        if let None = tid_events {
                            self.events.insert(*tid, Vec::new());
                        }

                        let tid_events = self.events.get_mut(tid).unwrap();
                        tid_events.push(event);
                    }
                    FutexEvent::NewProcess { pid, comm } => {
                        if let None = self.new_pids {
                            self.new_pids = Some(Vec::new());
                        }
                        let new_pids = self.new_pids.as_mut().unwrap();
                        new_pids.push((comm.clone(), *pid));
                    }
                    FutexEvent::UnhandledOpcode { .. } => {
                        println!("Futex unhandled opcode. {:?}", event);
                    }
                    FutexEvent::Unexpected { .. } => {
                        println!("Futex unexpected event. {:?}", event);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn take_futex_events(&mut self, tid: usize) -> Result<Vec<FutexEvent>> {
        Ok(self.events.remove(&tid).unwrap_or(Vec::new()))
    }

    pub fn take_new_pid_events(&mut self) -> Result<Vec<(Rc<str>, usize)>> {
        self.poll_events()?;
        Ok(self.new_pids.take().unwrap_or(Vec::new()))
    }
}

impl Drop for FutexProgram {
    fn drop(&mut self) {
        if let Err(why) = self.child.kill() {
            println!("Failed to kill futex {}", why);
        }
    }
}
