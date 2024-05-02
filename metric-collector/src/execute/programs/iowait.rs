use eyre::Result;
use std::os::unix::prelude::*;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::{
    io::prelude::*,
    process::{Child, Command},
    rc::Rc,
    thread,
};

use crate::execute::BpfReader;

#[derive(Debug)]
pub enum IOWaitEvent {
    SubmitBio {
        ns_since_boot: u128,
        device: u32,
        part0: u32,
        sector: u64,
        sector_cnt: usize,
        is_write: bool,
        op: u8,
        status: u32,
        tid: usize,
        comm: Rc<str>,
    },
    BioEndIO {
        ns_since_boot: u128,
        device: u32,
        part0: u32,
        sector: u64,
        sector_cnt: usize,
        is_write: bool,
        op: u8,
        status: u32,
        tid: usize,
        comm: Rc<str>,
    },
    TracepointBioStart {
        ns_since_boot: u128,
        device: u32,
        sector: u64,
        sector_cnt: usize,
        bytes: usize,
        tid: usize,
        comm: Rc<str>,
    },
    TracepointBioDone {
        ns_since_boot: u128,
        device: u32,
        sector: u64,
        sector_cnt: usize,
        bytes: usize,
        tid: usize,
        comm: Rc<str>,
    },
    IOScheduleEnter {
        ns_since_boot: u128,
        tid: usize,
        comm: Rc<str>,
    },
    IOScheduleExit {
        ns_since_boot: u128,
        tid: usize,
        comm: Rc<str>,
    },
    Unexpected {
        data: String,
    },
}

impl From<Vec<u8>> for IOWaitEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        let event_string = event_string.replace(" ", "");
        let mut elements = event_string.split("\t");
        match elements.next().unwrap() {
            "bio_s" => Self::SubmitBio {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                part0: elements.next().unwrap().parse().unwrap(),
                device: elements.next().unwrap().parse().unwrap(),
                sector: elements.next().unwrap().parse().unwrap(),
                sector_cnt: elements.next().unwrap().parse().unwrap(),
                is_write: elements.next().unwrap() == "1",
                op: elements.next().unwrap().parse().unwrap(),
                status: elements.next().unwrap().parse().unwrap(),
                tid: elements.next().unwrap().parse().unwrap(),
                comm: Rc::from(elements.next().unwrap()),
            },
            "bio_e" => Self::BioEndIO {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                part0: elements.next().unwrap().parse().unwrap(),
                device: elements.next().unwrap().parse().unwrap(),
                sector: elements.next().unwrap().parse().unwrap(),
                sector_cnt: elements.next().unwrap().parse().unwrap(),
                is_write: elements.next().unwrap() == "1",
                op: elements.next().unwrap().parse().unwrap(),
                status: elements.next().unwrap().parse().unwrap(),
                tid: elements.next().unwrap().parse().unwrap(),
                comm: Rc::from(elements.next().unwrap()),
            },
            "io_s" => Self::IOScheduleEnter {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                tid: elements.next().unwrap().parse().unwrap(),
                comm: Rc::from(elements.next().unwrap()),
            },
            "io_e" => Self::IOScheduleExit {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                tid: elements.next().unwrap().parse().unwrap(),
                comm: Rc::from(elements.next().unwrap()),
            },
            "t_s" => Self::TracepointBioDone {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                device: elements.next().unwrap().parse().unwrap(),
                sector: elements.next().unwrap().parse().unwrap(),
                sector_cnt: elements.next().unwrap().parse().unwrap(),
                bytes: elements.next().unwrap().parse().unwrap(),
                tid: elements.next().unwrap().parse().unwrap(),
                comm: Rc::from(elements.next().unwrap()),
            },
            "t_e" => Self::TracepointBioStart {
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                device: elements.next().unwrap().parse().unwrap(),
                sector: elements.next().unwrap().parse().unwrap(),
                sector_cnt: elements.next().unwrap().parse().unwrap(),
                bytes: elements.next().unwrap().parse().unwrap(),
                tid: elements.next().unwrap().parse().unwrap(),
                comm: Rc::from(elements.next().unwrap()),
            },
            _ => Self::Unexpected { data: event_string },
        }
    }
}

pub struct IOWaitProgram {
    child: Option<Child>,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
    events: Option<Vec<IOWaitEvent>>,
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
                if let None = self.events {
                    self.events = Some(Vec::new());
                }
                let events = self.events.as_mut().unwrap();
                let event = IOWaitEvent::from(event);
                match event {
                    IOWaitEvent::Unexpected { .. } => {
                        println!("Unexpected iowait event. {:?}", event)
                    }
                    _ => {
                        events.push(event);
                    }
                }
            }
        }
        Ok(self.events.as_ref().map_or(0, |events| events.len()))
    }

    pub fn take_events(&mut self) -> Result<Vec<IOWaitEvent>> {
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
