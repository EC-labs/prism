use eyre::Result;
use std::{
    cell::RefCell,
    collections::HashMap,
    hash::Hash,
    io::Read,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::execute::{
    boot_to_epoch,
    programs::iowait::{IOWaitEvent, IOWaitProgram},
};

use super::Collect;

#[derive(Debug, PartialEq, Eq)]
struct ThreadDeviceStats {
    buffer: HashMap<u64, u64>,
}

impl ThreadDeviceStats {
    fn new() -> Self {
        Self {
            buffer: HashMap::new(),
        }
    }

    fn account(&mut self, bio: &mut Bio, instant_s: u64) {
        let next = if let Some(last) = bio.last_instant_accounted {
            last + 1
        } else {
            bio.epoch_ns / 1_000_000_000 + 1
        };

        let (contribution, from, to) = if next <= instant_s {
            (bio.sector_cnt as i64, next, instant_s)
        } else {
            (-(bio.sector_cnt as i64), instant_s + 1, next)
        };

        for key in from..=to as u64 {
            let sectors = if let Some(sectors) = self.buffer.get_mut(&key) {
                sectors
            } else if contribution > 0 {
                self.buffer.entry(key).or_insert(0)
            } else {
                continue;
            };
            *sectors = (*sectors as i64 + contribution) as u64;
            if *sectors == 0 {
                self.buffer.remove(&key);
            }
            bio.last_instant_accounted = Some(key);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ThreadIOStats {
    device_map: HashMap<u32, ThreadDeviceStats>,
}

impl ThreadIOStats {
    fn new() -> Self {
        Self {
            device_map: HashMap::new(),
        }
    }

    fn account(&mut self, bio: &mut Bio, instant_s: u64) {
        let buffer = self
            .device_map
            .entry(bio.device)
            .or_insert(ThreadDeviceStats::new());
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
    tid: usize,
    epoch_ns: u64,
    last_instant_accounted: Option<u64>,
}

impl Bio {
    fn first_instant_s(&self) -> u64 {
        self.epoch_ns / 1_000_000_000 + 1
    }
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

pub struct IOWait<R: Read> {
    iowait_program: Rc<RefCell<IOWaitProgram<R>>>,
    pending_requests: HashMap<u32, HashMap<BioKey, Bio>>,
    thread_map: HashMap<usize, ThreadIOStats>,
    current_sample_instant: Option<u64>,
}

impl<R: Read> IOWait<R> {
    pub fn new(iowait_program: Rc<RefCell<IOWaitProgram<R>>>) -> Self {
        Self {
            iowait_program,
            pending_requests: HashMap::new(),
            thread_map: HashMap::new(),
            current_sample_instant: None,
        }
    }

    fn account_pending(&mut self) {
        let pending_requests = &mut self.pending_requests;
        for (_, bios) in pending_requests {
            for (_, mut bio) in bios {
                if bio.first_instant_s() <= self.current_sample_instant.unwrap() {
                    let thread_acc = self
                        .thread_map
                        .entry(bio.tid)
                        .or_insert(ThreadIOStats::new());
                    thread_acc.account(&mut bio, self.current_sample_instant.unwrap());
                }
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
                    epoch_ns: boot_to_epoch(ns_since_boot) as u64,
                    tid: tid,
                    last_instant_accounted: None,
                };

                if bio.first_instant_s() <= self.current_sample_instant.unwrap() {
                    let thread_acc = self
                        .thread_map
                        .entry(bio.tid)
                        .or_insert(ThreadIOStats::new());
                    thread_acc.account(&mut bio, self.current_sample_instant.unwrap());
                }

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
                ns_since_boot,
                ..
            } => {
                let bios = if let Some(requests) = self.pending_requests.get_mut(&device) {
                    requests
                } else {
                    return;
                };

                let key = BioKey {
                    device,
                    sector,
                    sector_cnt,
                };
                let bio = bios.remove(&key);
                if let None = bio {
                    return;
                }
                let mut bio = bio.unwrap();

                let last_instant = (boot_to_epoch(ns_since_boot) / 1_000_000_000 + 1) as u64;
                if last_instant <= self.current_sample_instant.unwrap() {
                    let thread_acc = self
                        .thread_map
                        .entry(bio.tid)
                        .or_insert(ThreadIOStats::new());
                    thread_acc.account(&mut bio, last_instant);
                }
            }
            _ => {}
        };
    }
}

impl<R: Read> Collect for IOWait<R> {
    fn sample(&mut self) -> Result<()> {
        let events = self.iowait_program.borrow_mut().take_events()?;

        let epoch_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();

        if let None = self.current_sample_instant {
            self.current_sample_instant = Some(((epoch_ns as u64) / 1_000_000_000) + 1);
        }

        for event in events {
            self.process_event(event);
        }
        self.account_pending();

        self.current_sample_instant = None;
        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use eyre::{OptionExt, Result};
    use indoc::indoc;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::rc::Rc;

    use crate::execute::programs::iowait::IOWaitProgram;
    use crate::execute::programs::{fcntl_setfd, pipe};
    use crate::metrics::iowait::Bio;
    use crate::metrics::Collect;

    use super::{IOWait, ThreadDeviceStats};

    // Attaching 6 probes...
    // bio_s	772129082664043	264241153	264241153	443675136	8	1	1	0	3	LS Thread
    // bio_s	772129082688258	264241153	264241153	443675144	8	1	1	0	4	LS Thread
    // bio_s	772129082689146	264241152	264241152	443677192	8	1	1	0	4	LS Thread
    // bio_e	772129085774881	264241153	264241153	443675136	8	1	1	0	0	swapper/13
    // bio_e	772129085777546	264241152	264241152	443677192	8	1	1	0	0	swapper/13
    // bio_e	772129085778357	264241153	264241153	443675144	8	1	1	0	0	swapper/13

    #[test]
    fn submit() -> Result<()> {
        let reader = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_s	000001100000000	264241153	264241153	443675144	8	1	1	0	4	LS Thread
        "#};
        let iowait_program = IOWaitProgram::custom_reader(reader.as_bytes());
        let mut iowait = IOWait::new(Rc::new(RefCell::new(iowait_program)));

        iowait.current_sample_instant = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8)]), buffer);

        iowait.current_sample_instant = Some(000002);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(&HashMap::from([(2, 8)]), buffer);

        Ok(())
    }

    #[test]
    fn submit_delayed() -> Result<()> {
        let (mut reader, mut writer) = pipe();
        fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);

        let iowait_program = IOWaitProgram::custom_reader(reader);
        let mut iowait = IOWait::new(Rc::new(RefCell::new(iowait_program)));

        let data = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;
        iowait.current_sample_instant = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8)]), buffer);

        let data = indoc! {r#"
            bio_s	000000110000000	264241153	264241153	443675144	8	1	1	0	3	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;
        iowait.current_sample_instant = Some(000002);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 16), (2, 16)]), buffer);

        Ok(())
    }

    #[test]
    fn sample() -> Result<()> {
        let (mut reader, mut writer) = pipe();
        fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);

        let iowait_program = IOWaitProgram::custom_reader(reader);
        let mut iowait = IOWait::new(Rc::new(RefCell::new(iowait_program)));

        let data = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_s	000001100000000	264241153	264241153	443675144	8	1	1	0	4	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;
        iowait.current_sample_instant = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8)]), buffer);

        iowait.current_sample_instant = Some(000002);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(&HashMap::from([(2, 8)]), buffer);

        iowait.current_sample_instant = Some(000003);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(&HashMap::from([(2, 8), (3, 8)]), buffer);

        let data = indoc! {r#"
            bio_e	000002900000000	264241153	264241153	443675136	8	1	1	0	0	swapper/13
        "#};
        writer.write_all(data.as_bytes())?;
        iowait.current_sample_instant = Some(000004);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(&HashMap::from([(2, 8), (3, 8), (4, 8)]), buffer);

        Ok(())
    }

    #[test]
    fn bioendio() -> Result<()> {
        let (mut reader, mut writer) = pipe();
        fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);

        let iowait_program = IOWaitProgram::custom_reader(reader);
        let mut iowait = IOWait::new(Rc::new(RefCell::new(iowait_program)));

        let data = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_s	000001100000000	264241153	264241153	443675144	8	1	1	0	4	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;
        iowait.current_sample_instant = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8)]), buffer);

        iowait.current_sample_instant = Some(000003);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(&HashMap::from([(2, 8), (3, 8)]), buffer);

        let data = indoc! {r#"
            bio_e	000001900000000	264241153	264241153	443675136	8	1	1	0	0	swapper/13
        "#};
        writer.write_all(data.as_bytes())?;
        iowait.current_sample_instant = Some(000004);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(&HashMap::from([(2, 8), (3, 8), (4, 8)]), buffer);
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8)]), buffer);

        let data = indoc! {r#"
            bio_e	000002900000000	264241153	264241153	443675144	8	1	1	0	0	swapper/13
        "#};
        writer.write_all(data.as_bytes())?;
        iowait.current_sample_instant = Some(000004);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(&HashMap::from([(2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8)]), buffer);

        Ok(())
    }

    fn get_buffer<'a, R: Read>(
        iowait: &'a IOWait<R>,
        thread: &usize,
        device: &u32,
    ) -> Result<&'a HashMap<u64, u64>> {
        let thread_stats = iowait
            .thread_map
            .get(thread)
            .ok_or_eyre("Missing key thread map")?;
        Ok(&thread_stats
            .device_map
            .get(device)
            .ok_or_eyre("Missing key device map")?
            .buffer)
    }

    #[test]
    fn account_add() {
        fn create_bio(millis: u64, sector_cnt: usize) -> Bio {
            Bio {
                sector_cnt,
                epoch_ns: millis * 1_000_000,
                sector: 0,
                last_instant_accounted: None,
                tid: 0,
                device: 1,
            }
        }

        let mut buf = ThreadDeviceStats::new();
        let mut bio = create_bio(0100, 2);
        buf.account(&mut bio, 1);
        assert_eq!(HashMap::from([(1, 2)]), buf.buffer);

        let mut bio = create_bio(1100, 10);
        buf.account(&mut bio, 2);
        assert_eq!(HashMap::from([(1, 2), (2, 10)]), buf.buffer);

        buf.account(&mut bio, 3);
        assert_eq!(HashMap::from([(1, 2), (2, 10), (3, 10)]), buf.buffer);

        let mut bio = create_bio(1100, 4);
        buf.account(&mut bio, 4);
        assert_eq!(
            HashMap::from([(1, 2), (2, 14), (3, 14), (4, 4)]),
            buf.buffer
        );
    }

    #[test]
    fn account_subtract() {
        fn create_bio(millis: u64, sector_cnt: usize) -> Bio {
            Bio {
                sector_cnt,
                epoch_ns: millis * 1_000_000,
                sector: 0,
                last_instant_accounted: None,
                tid: 0,
                device: 1,
            }
        }

        let mut buf = ThreadDeviceStats::new();
        let mut bio = create_bio(1100, 10);
        buf.account(&mut bio, 2);
        buf.account(&mut bio, 3);
        let mut bio = create_bio(1100, 4);
        buf.account(&mut bio, 4);
        assert_eq!(HashMap::from([(2, 14), (3, 14), (4, 4)]), buf.buffer);

        // Subtract
        buf.account(&mut bio, 2);
        assert_eq!(HashMap::from([(2, 14), (3, 10)]), buf.buffer);
    }
}
