use eyre::Result;
use nix::time::{self, ClockId};
use std::ffi::CString;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{cell::RefCell, rc::Rc};

pub mod programs;

use programs::clone::CloneProgram;
use programs::futex::FutexProgram;
use programs::iowait::IOWaitProgram;
use programs::ipc::IpcProgram;
use programs::BOOT_EPOCH_NS;

pub struct Executor {
    pub clone: CloneProgram,
    pub futex: Rc<RefCell<FutexProgram>>,
    pub ipc: Rc<RefCell<IpcProgram>>,
    pub io_wait: Rc<RefCell<IOWaitProgram>>,
}

impl Executor {
    pub fn new(terminate_flag: Arc<Mutex<bool>>) -> Result<Self> {
        if *BOOT_EPOCH_NS.read().unwrap() == 0 {
            let ns_since_boot =
                Duration::from(time::clock_gettime(ClockId::CLOCK_BOOTTIME).unwrap()).as_nanos();
            let start = SystemTime::now();
            let ns_since_epoch = start
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_nanos();
            *BOOT_EPOCH_NS.write().unwrap() = ns_since_epoch - ns_since_boot;
        }

        let pid = std::process::id();
        let mut clone = CloneProgram::new(pid)?;
        let mut futex = FutexProgram::new(pid, terminate_flag.clone())?;
        let mut io_wait = IOWaitProgram::new(terminate_flag.clone())?;
        let mut ipc = IpcProgram::new(terminate_flag, pid)?;

        while (true, true, true, true)
            != (
                clone.header_read(),
                futex.header_read(),
                io_wait.header_read(),
                ipc.header_read(),
            )
        {
            clone.poll_events()?;
            futex.poll_events()?;
            io_wait.poll_events()?;
            ipc.poll_events()?;
            thread::sleep(std::time::Duration::from_millis(1000));
        }

        Ok(Executor {
            clone,
            io_wait: Rc::new(RefCell::new(io_wait)),
            futex: Rc::new(RefCell::new(futex)),
            ipc: Rc::new(RefCell::new(ipc)),
        })
    }
}

impl Executor {
    pub fn monitor(&mut self, pid: usize) {
        println!("Monitoring new process {}", pid);
        let event_id = CString::new("metric-collector-new-pid").unwrap();
        unsafe {
            libc::access(event_id.as_ptr(), pid as i32);
        }
    }
}

pub fn boot_to_epoch(boot_ns: u128) -> u128 {
    *BOOT_EPOCH_NS.read().unwrap() + boot_ns
}

pub trait BpfReader {
    fn header_read(&self) -> bool;
    fn header_lines_get_mut(&mut self) -> &mut u8;

    fn current_event_as_mut(&mut self) -> Option<&mut Vec<u8>>;
    fn set_current_event(&mut self, val: Vec<u8>);
    fn take_current_event(&mut self) -> Option<Vec<u8>>;

    fn handle_header<'a, I: Iterator<Item = &'a u8>>(&mut self, buf: &mut I) {
        while !self.header_read() {
            let newline = buf.find(|&&b| b == b'\n');
            if let Some(_) = newline {
                *self.header_lines_get_mut() += 1;
            } else {
                break;
            }
        }
    }

    fn handle_event<'a, I: Iterator<Item = &'a u8>>(&mut self, buf: &mut I) -> Option<Vec<u8>> {
        if let None = self.current_event_as_mut() {
            self.set_current_event(Vec::new());
        }

        while let Some(byte) = buf.next() {
            if *byte != b'\n' {
                self.current_event_as_mut().map(|curr| curr.push(*byte));
            } else {
                return self.take_current_event();
            }
        }
        return None;
    }
}
