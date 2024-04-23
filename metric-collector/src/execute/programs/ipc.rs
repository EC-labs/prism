use eyre::Result;
use std::{
    collections::HashMap,
    io::Read,
    process::{Child, Command},
    rc::Rc,
    sync::{
        mpsc::{Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    thread,
};

use crate::execute::BpfReader;

#[derive(Debug)]
pub enum IpcEvent {
    NewProcess {
        comm: Rc<str>,
        pid: usize,
    },
    ReadStart {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        ns_since_boot: u64,
    },
    ReadEnd {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        ns_since_boot: u64,
        ns_elapsed: u64,
    },
    WriteStart {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        ns_since_boot: u64,
    },
    WriteEnd {
        comm: Rc<str>,
        tid: usize,
        fs_type: Rc<str>,
        sb_id: u32,
        inode_id: u64,
        ns_since_boot: u64,
        ns_elapsed: u64,
    },
    Unexpected {
        data: String,
    },
}

impl From<Vec<u8>> for IpcEvent {
    fn from(value: Vec<u8>) -> Self {
        let event_string = String::from_utf8(value).unwrap();
        let event_string = event_string.replace(" ", "");
        let mut elements = event_string.split("\t");
        match elements.next().unwrap() {
            "ReadStart" => Self::ReadStart {
                comm: Rc::from(elements.next().unwrap()),
                tid: elements.next().unwrap().parse().unwrap(),
                fs_type: Rc::from(elements.next().unwrap()),
                sb_id: elements.next().unwrap().parse().unwrap(),
                inode_id: elements.next().unwrap().parse().unwrap(),
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
            },
            "ReadEnd" => Self::ReadEnd {
                comm: Rc::from(elements.next().unwrap()),
                tid: elements.next().unwrap().parse().unwrap(),
                fs_type: Rc::from(elements.next().unwrap()),
                sb_id: elements.next().unwrap().parse().unwrap(),
                inode_id: elements.next().unwrap().parse().unwrap(),
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                ns_elapsed: elements.next().unwrap().parse().unwrap(),
            },
            "WriteStart" => Self::WriteStart {
                comm: Rc::from(elements.next().unwrap()),
                tid: elements.next().unwrap().parse().unwrap(),
                fs_type: Rc::from(elements.next().unwrap()),
                sb_id: elements.next().unwrap().parse().unwrap(),
                inode_id: elements.next().unwrap().parse().unwrap(),
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
            },
            "WriteEnd" => Self::WriteEnd {
                comm: Rc::from(elements.next().unwrap()),
                tid: elements.next().unwrap().parse().unwrap(),
                fs_type: Rc::from(elements.next().unwrap()),
                sb_id: elements.next().unwrap().parse().unwrap(),
                inode_id: elements.next().unwrap().parse().unwrap(),
                ns_since_boot: elements.next().unwrap().parse().unwrap(),
                ns_elapsed: elements.next().unwrap().parse().unwrap(),
            },
            _ => Self::Unexpected { data: event_string },
        }
    }
}

pub struct IpcProgram {
    header_lines: u8,
    current_event: Option<Vec<u8>>,
    child: Option<Child>,
    rx: Receiver<Arc<[u8]>>,
    events: HashMap<usize, Vec<IpcEvent>>,
}

impl IpcProgram {
    pub fn new(terminate_flag: Arc<Mutex<bool>>, pid: u32) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        let (bpf_pipe_rx, bpf_pipe_tx) = super::bpf_pipe(1_048_576);
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
                let event = IpcEvent::from(event);
                match event {
                    IpcEvent::ReadStart { tid, .. }
                    | IpcEvent::ReadEnd { tid, .. }
                    | IpcEvent::WriteStart { tid, .. }
                    | IpcEvent::WriteEnd { tid, .. } => {
                        let events = self.events.entry(tid).or_insert(Vec::new());
                        events.push(event);
                    }
                    _ => {}
                }
            }
        }
        Ok(self.events.len())
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
