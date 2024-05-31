use eyre::Result;
use std::{
    collections::HashMap,
    io::prelude::*,
    process::{Child, Command},
    rc::Rc,
    sync::{
        mpsc::{self, Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    thread,
};

use super::BOOT_EPOCH_NS;
use crate::{execute::BpfReader, metrics::ToCsv};

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
    SampleInstant {
        ns_since_boot: u128,
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
            "SampleInstant" => Self::SampleInstant {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
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
    rx: Receiver<Arc<[u8]>>,
    events: HashMap<usize, Vec<FutexEvent>>,
    new_pids: Option<Vec<(Rc<str>, usize)>>,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
    latest_instant_ns: Option<u128>,
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
        let (mut reader, writer) = super::pipe();
        super::fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let (tx, rx) = mpsc::channel();
        Self::start_bpf_reader(tx, reader, terminate_flag);
        let child = Command::new("bpftrace")
            .args([
                "./metric-collector/src/bpf/futex_wait.bt",
                &format!("{}", pid),
            ])
            .stdout(writer)
            .spawn()?;
        Ok(Self {
            child,
            rx,
            events: HashMap::new(),
            header_lines: 0,
            current_event: None,
            new_pids: None,
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
        thread::spawn(move || loop {
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
        });
    }

    pub fn poll_events(&mut self) -> Result<()> {
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
                let event = FutexEvent::from(event);
                match &event {
                    FutexEvent::Start {
                        tid, ns_since_boot, ..
                    }
                    | FutexEvent::Elapsed {
                        tid, ns_since_boot, ..
                    }
                    | FutexEvent::Wake {
                        tid, ns_since_boot, ..
                    } => {
                        let tid_events = self.events.get_mut(tid);
                        if let None = tid_events {
                            self.events.insert(*tid, Vec::new());
                        }

                        let tid_events = self.events.get_mut(tid).unwrap();
                        self.latest_instant_ns = Some(*ns_since_boot);
                        tid_events.push(event);
                    }
                    FutexEvent::NewProcess { pid, comm } => {
                        if let None = self.new_pids {
                            self.new_pids = Some(Vec::new());
                        }
                        let new_pids = self.new_pids.as_mut().unwrap();
                        new_pids.push((comm.clone(), *pid));
                    }
                    FutexEvent::SampleInstant { ns_since_boot } => {
                        self.latest_instant_ns = Some(*ns_since_boot);
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

    pub fn take_futex_events(&mut self, tid: usize) -> Result<(Vec<FutexEvent>, Option<u128>)> {
        let res = self.poll_events();
        let events = self.events.remove(&tid).unwrap_or(Vec::new());
        match (res, events.len() > 0) {
            (_, true) => Ok((events, self.latest_instant_ns)),
            (Ok(_), false) => Ok((events, self.latest_instant_ns)),
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
        if let Err(why) = self.child.kill() {
            println!("Failed to kill futex {}", why);
        }
    }
}
