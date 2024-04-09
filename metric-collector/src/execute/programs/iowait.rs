use eyre::Result;
use std::{
    fs::File,
    io::{prelude::*, ErrorKind},
    process::{Child, Command},
    rc::Rc,
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
                device: elements.next().unwrap().parse().unwrap(),
                part0: elements.next().unwrap().parse().unwrap(),
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
                device: elements.next().unwrap().parse().unwrap(),
                part0: elements.next().unwrap().parse().unwrap(),
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

impl IOWaitProgram<File> {
    pub fn new() -> Result<Self> {
        let (mut reader, writer) = super::pipe();
        super::fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let child = Command::new("bpftrace")
            .args(["./metric-collector/src/bpf/io_wait.bt"])
            .stdout(writer)
            .spawn()?;
        Ok(Self {
            reader,
            child: Some(child),
            header_lines: 0,
            current_event: None,
            events: None,
        })
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
