use eyre::Result;
use std::io::ErrorKind;
use std::process::{Child, Command};
use std::rc::Rc;
use std::{fs::File, io::prelude::*};

use crate::execute::BpfReader;

pub enum CloneEvent {
    NewThread {
        comm: Rc<str>,
        pid: usize,
        tid: usize,
    },
    NewProcess(Rc<str>, usize),
    RemoveProcess(usize),
    Unexpected {
        data: String,
    },
}

impl From<Vec<u8>> for CloneEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        let mut elements = event_string.split("\t");
        match elements.next().unwrap().trim() {
            "NewThread" => Self::NewThread {
                comm: Rc::from(elements.next().unwrap().trim()),
                pid: elements.next().unwrap().parse().unwrap(),
                tid: elements.next().unwrap().parse().unwrap(),
            },
            "NewProcess" => Self::NewProcess(
                Rc::from(elements.next().unwrap()),
                elements.next().unwrap().parse().unwrap(),
            ),
            "RemoveProcess" => Self::RemoveProcess(elements.next().unwrap().parse().unwrap()),
            _ => Self::Unexpected { data: event_string },
        }
    }
}

pub struct CloneProgram {
    reader: File,
    child: Child,
    header_lines: u8,
    current_event: Option<Vec<u8>>,
}

impl BpfReader for CloneProgram {
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

impl CloneProgram {
    pub fn new(pid: u32) -> Result<Self> {
        let (mut reader, writer) = super::pipe();
        super::fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let child = Command::new("bpftrace")
            .args(["./metric-collector/src/bpf/clone.bt", &format!("{}", pid)])
            .stdout(writer)
            .spawn()?;
        Ok(Self {
            child,
            reader,
            header_lines: 0,
            current_event: None,
        })
    }

    pub fn poll_events(&mut self) -> Result<Vec<CloneEvent>> {
        let mut res = Vec::new();
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
                let event = CloneEvent::from(event);
                res.push(event);
            }
        }
        Ok(res)
    }
}

impl Drop for CloneProgram {
    fn drop(&mut self) {
        if let Err(why) = self.child.kill() {
            println!("Failed to kill futex {}", why);
        }
    }
}
