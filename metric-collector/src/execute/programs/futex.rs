use eyre::Result;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::process::{Child, Command};
use std::{fs::File, io::prelude::*};

#[derive(Debug)]
pub enum WaitEvent {
    Start {
        pid: usize,
        tid: usize,
        epoch: u64,
    },
    Elapsed {
        elapsed: u64,
        tid: usize,
        pid: usize,
    },
}

impl From<Vec<u8>> for WaitEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        let event_string = event_string.replace(" ", "");

        let elements: Vec<&str> = event_string.split("\t").collect();
        if elements[0] == "elapsed" {
            Self::Elapsed {
                pid: elements[1].parse().unwrap(),
                tid: elements[2].parse().unwrap(),
                elapsed: elements[3].parse().unwrap(),
            }
        } else {
            Self::Start {
                pid: elements[1].parse().unwrap(),
                tid: elements[2].parse().unwrap(),
                epoch: elements[3].parse().unwrap(),
            }
        }
    }
}

pub struct FutexProgram {
    child: Child,
    reader: File,
    events: HashMap<usize, Vec<WaitEvent>>,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
}

impl FutexProgram {
    pub fn new(pid: usize) -> Result<Self> {
        let (mut reader, writer) = super::pipe();
        super::fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let child = Command::new("bpftrace")
            .args(["./src/bpf/futex_wait.bt", &format!("{}", pid)])
            .stdout(writer)
            .spawn()?;
        Ok(Self {
            child,
            reader,
            events: HashMap::new(),
            header_lines: 0,
            current_event: None,
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

    fn header_read(&self) -> bool {
        self.header_lines == 2
    }

    pub fn poll_events(&mut self, tid: usize) -> Option<Vec<WaitEvent>> {
        loop {
            let mut buf: [u8; 256] = [0; 256];
            let bytes = self.reader.read(&mut buf);

            let bytes = match bytes {
                Err(error) => {
                    let kind = error.kind();
                    if kind == ErrorKind::WouldBlock {
                        break;
                    }

                    return None;
                }
                Ok(bytes) => bytes,
            };

            let mut iterator = buf[..bytes].into_iter();
            if !self.header_read() {
                self.handle_header(&mut iterator);
            }
            while let Some(event) = self.handle_event(&mut iterator) {
                let event = WaitEvent::from(event);
                match &event {
                    WaitEvent::Start { tid, .. } | WaitEvent::Elapsed { tid, .. } => {
                        let tid_events = self.events.get_mut(tid);
                        if let None = tid_events {
                            self.events.insert(*tid, Vec::new());
                        }

                        let tid_events = self.events.get_mut(tid).unwrap();
                        tid_events.push(event);
                    }
                }
            }
        }
        self.events.remove(&tid)
    }
}

impl Drop for FutexProgram {
    fn drop(&mut self) {
        if let Err(why) = self.child.kill() {
            println!("Failed to kill futex {}", why);
        }
    }
}
