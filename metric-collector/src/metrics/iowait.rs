use eyre::Result;
use std::{
    cell::RefCell,
    collections::HashMap,
    hash::Hash,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::execute::{
    boot_to_epoch,
    programs::iowait::{IOWaitEvent, IOWaitProgram},
};

use super::Collect;

#[derive(Debug)]
struct MinuteRingBuffer {
    buffer: HashMap<u64, u64>,
}

impl MinuteRingBuffer {
    fn new() -> Self {
        Self {
            buffer: HashMap::new(),
        }
    }

    fn account(&mut self, bio: &mut Bio, instant_s: u64) {
        let from = if let Some(from) = bio.last_instant_accounted {
            from
        } else {
            (bio.epoch_ns.unwrap() / 1_000_000_000) + 1
        };

        for key in from..=instant_s as u64 {
            let sectors = self.buffer.entry(key).or_insert(0);
            *sectors += bio.sector_cnt as u64;
        }
        bio.last_instant_accounted = Some(instant_s);
    }
}

#[derive(Debug)]
struct ThreadIOStats {
    device_accounting: HashMap<u32, MinuteRingBuffer>,
}

impl ThreadIOStats {
    fn new() -> Self {
        Self {
            device_accounting: HashMap::new(),
        }
    }

    fn account(&mut self, bio: &mut Bio, instant_s: u64) {
        let buffer = self
            .device_accounting
            .entry(bio.device)
            .or_insert(MinuteRingBuffer::new());
        buffer.account(bio, instant_s);
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct BioKey {
    device: u32,
    sector: u64,
    sector_cnt: usize,
}

impl From<&Bio> for BioKey {
    fn from(value: &Bio) -> Self {
        BioKey {
            device: value.device,
            sector: value.sector,
            sector_cnt: value.sector_cnt,
        }
    }
}

#[derive(Debug)]
struct Bio {
    device: u32,
    sector: u64,
    sector_cnt: usize,
    tid: Option<usize>,
    epoch_ns: Option<u64>,
    last_instant_accounted: Option<u64>,
}

impl PartialEq for Bio {
    fn eq(&self, other: &Self) -> bool {
        (self.device, self.sector, self.sector_cnt)
            == (other.device, other.sector, other.sector_cnt)
    }
}

impl Eq for Bio {}

impl Hash for Bio {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.device.hash(state);
        self.sector.hash(state);
        self.sector_cnt.hash(state);
    }
}

pub struct IOWait {
    iowait_program: Rc<RefCell<IOWaitProgram>>,
    pending_requests: HashMap<u32, HashMap<BioKey, Bio>>,
    thread_accounting: HashMap<usize, ThreadIOStats>,
    current_sample_instant: Option<u64>,
}

impl IOWait {
    pub fn new(iowait_program: Rc<RefCell<IOWaitProgram>>) -> Self {
        Self {
            iowait_program,
            pending_requests: HashMap::new(),
            thread_accounting: HashMap::new(),
            current_sample_instant: None,
        }
    }

    fn account_pending(&mut self) {
        let pending_requests = &mut self.pending_requests;
        for (_, bios) in pending_requests {
            for (_, bio) in bios {
                let thread_acc = self
                    .thread_accounting
                    .entry(bio.tid.unwrap())
                    .or_insert(ThreadIOStats::new());
                thread_acc.account(bio, self.current_sample_instant.unwrap());
            }
        }
    }

    fn process_event(&mut self, event: IOWaitEvent) {
        match event {
            IOWaitEvent::SubmitBio {
                device,
                sector,
                sector_cnt,
                tid,
                ns_since_boot,
                ..
            } => {
                let mut bio = Bio {
                    device,
                    sector,
                    sector_cnt,
                    epoch_ns: Some(boot_to_epoch(ns_since_boot) as u64),
                    tid: Some(tid),
                    last_instant_accounted: None,
                };
                let thread_acc = self
                    .thread_accounting
                    .entry(bio.tid.unwrap())
                    .or_insert(ThreadIOStats::new());
                thread_acc.account(&mut bio, self.current_sample_instant.unwrap());

                let bio_map = self
                    .pending_requests
                    .entry(device)
                    .or_insert(HashMap::new());
                bio_map.insert(BioKey::from(&bio), bio);
            }
            IOWaitEvent::BioEndIO {
                device,
                sector,
                sector_cnt,
                ..
            } => {
                let bios = if let Some(requests) = self.pending_requests.get_mut(&device) {
                    requests
                } else {
                    return;
                };

                let bio = Bio {
                    device,
                    sector,
                    sector_cnt,
                    epoch_ns: None,
                    tid: None,
                    last_instant_accounted: None,
                };
                let bio = bios.remove(&BioKey::from(&bio));
                if let None = bio {
                    return;
                }

                let bio = bio.unwrap();
            }
            _ => {}
        };
    }
}

impl Collect for IOWait {
    fn sample(&mut self) -> Result<()> {
        let events = self.iowait_program.borrow_mut().take_events()?;

        let epoch_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();
        self.current_sample_instant = Some(((epoch_ns as u64) / 1_000_000_000) + 1);

        for event in events {
            self.process_event(event);
        }
        self.account_pending();
        println!("\n{:#?}", self.thread_accounting);

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        Ok(())
    }
}
