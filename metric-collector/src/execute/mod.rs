use eyre::Result;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub mod programs;

use programs::clone::Clone;
use programs::futex::FutexProgram;

pub struct MonitorGroup {
    pub clone: Clone,
    pub futex: Rc<RefCell<FutexProgram>>,
}

impl MonitorGroup {
    fn new(pid: usize) -> Result<Self> {
        Ok(MonitorGroup {
            clone: Clone::new(pid)?,
            futex: Rc::new(RefCell::new(FutexProgram::new(pid)?)),
        })
    }
}

pub struct Executor {
    pub monitor_groups: HashMap<usize, MonitorGroup>,
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            monitor_groups: HashMap::new(),
        }
    }

    pub fn monitor(&mut self, pid: usize) -> Result<()> {
        self.monitor_groups.insert(pid, MonitorGroup::new(pid)?);
        Ok(())
    }
}
