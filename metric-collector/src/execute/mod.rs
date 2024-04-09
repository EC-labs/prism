use eyre::Result;
use nix::time::{self, ClockId};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{cell::RefCell, rc::Rc};

pub mod programs;

use programs::clone::Clone;
use programs::futex::FutexProgram;
use programs::iowait::IOWaitProgram;
use programs::BOOT_EPOCH_NS;

pub struct Executor<R: Read> {
    pub clone: Clone,
    pub futex: Rc<RefCell<FutexProgram>>,
    pub io_wait: Rc<RefCell<IOWaitProgram<R>>>,
}

impl Executor<File> {
    pub fn new() -> Result<Self> {
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
        let mut clone = Clone::new(pid)?;
        let mut futex = FutexProgram::new(pid)?;
        let mut io_wait = IOWaitProgram::new()?;

        while (true, true, true)
            != (
                clone.header_read(),
                futex.header_read(),
                io_wait.header_read(),
            )
        {
            clone.poll_events()?;
            futex.poll_events()?;
            io_wait.poll_events()?;
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }

        Ok(Executor {
            clone,
            io_wait: Rc::new(RefCell::new(io_wait)),
            futex: Rc::new(RefCell::new(futex)),
        })
    }
}

impl<R: Read> Executor<R> {
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
