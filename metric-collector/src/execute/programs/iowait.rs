use eyre::Result;
use std::os::unix::prelude::*;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::{
    fs::File,
    io::{prelude::*, ErrorKind},
    process::{Child, Command},
    rc::Rc,
    thread,
};

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

pub struct IOWaitProgram<R: Read> {
    child: Option<Child>,
    reader: R,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
    events: Option<Vec<IOWaitEvent>>,
}

impl IOWaitProgram<ChannelReader> {
    pub fn new(terminate_flag: Arc<Mutex<bool>>) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = ChannelReader {
            receiver: rx,
            hanging: None,
        };

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
            reader,
            child: Some(child),
            header_lines: 0,
            current_event: None,
            events: None,
        })
    }

    fn start_bpf_reader(
        mut tx: Sender<Arc<[u8]>>,
        mut bpf_pipe_rx: File,
        terminate_flag: Arc<Mutex<bool>>,
    ) {
        thread::spawn(move || loop {
            if *terminate_flag.lock().unwrap() == true {
                break;
            }
            let mut buf: [u8; 1024] = [0; 1024];
            let res = bpf_pipe_rx.read(&mut buf);
            if let Ok(bytes) = res {
                if bytes == 0 {
                    break;
                }

                println!("{}", String::from_utf8(buf[..bytes - 1].into()).unwrap());
                tx.send(Arc::from(&buf[..bytes]));
            }
        });
    }
}

impl<R: Read> IOWaitProgram<R> {
    pub fn custom_reader(reader: R) -> Self {
        Self {
            reader,
            child: None,
            header_lines: 0,
            current_event: None,
            events: None,
        }
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
            let mut buf: [u8; 65536] = [0; 65536];
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
                if let None = self.events {
                    self.events = Some(Vec::new());
                }
                let events = self.events.as_mut().unwrap();
                let event = IOWaitEvent::from(event);
                events.push(event);
            }
        }
        Ok(())
    }

    pub fn take_events(&mut self) -> Result<Vec<IOWaitEvent>> {
        self.poll_events()?;
        Ok(self.events.take().unwrap_or(Vec::new()))
    }
}

impl<R: Read> Drop for IOWaitProgram<R> {
    fn drop(&mut self) {
        if let None = self.child {
            return;
        }

        if let Err(why) = self.child.as_mut().unwrap().kill() {
            println!("Failed to kill futex {}", why);
        }
    }
}

pub struct ChannelReader {
    receiver: Receiver<Arc<[u8]>>,
    hanging: Option<Arc<[u8]>>,
}

impl ChannelReader {
    fn store(&mut self, data: &[u8]) {
        if let None = self.hanging {
            self.hanging = Some(Arc::from(data))
        } else {
            let hanging: Vec<u8> = [self.hanging.as_ref().unwrap(), data].concat();
            self.hanging = Some(Arc::from(&*hanging))
        }
    }

    fn cp(&mut self, data: Arc<[u8]>, buf: &mut [u8], start: usize) -> usize {
        let free = buf.len() - start;
        let cp_size = usize::min(free, data.len());
        buf[start..(start + cp_size)].clone_from_slice(&data[..cp_size]);
        if cp_size == free {
            self.store(&data[cp_size..]);
        }
        free - cp_size
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut free = buf.len();
        if let Some(data) = self.hanging.take() {
            free = self.cp(data, buf, 0);
        }

        loop {
            let data = self.receiver.try_recv();
            if let Err(_) = data {
                return Ok(buf.len() - free);
            }
            if let Ok(data) = data {
                free = self.cp(data, buf, buf.len() - free);
            }
        }
    }
}
