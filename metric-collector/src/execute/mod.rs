use eyre::Result;
use std::ffi::CString;
use std::{cell::RefCell, rc::Rc};

pub mod programs;

use programs::clone::Clone;
use programs::futex::FutexProgram;

pub struct Executor {
    pub clone: Clone,
    pub futex: Rc<RefCell<FutexProgram>>,
}

impl Executor {
    pub fn new() -> Result<Self> {
        let pid = std::process::id();
        let mut clone = Clone::new(pid)?;
        let mut futex = FutexProgram::new(pid)?;

        while (true, true) != (clone.header_read(), futex.header_read()) {
            clone.poll_events()?;
            futex.poll_events()?;
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }

        Ok(Executor {
            clone,
            futex: Rc::new(RefCell::new(futex)),
        })
    }

    pub fn monitor(&mut self, pid: usize) {
        println!("Monitoring new process {}", pid);
        let event_id = CString::new("metric-collector-new-pid").unwrap();
        unsafe {
            libc::access(event_id.as_ptr(), pid as i32);
        }
    }
}
