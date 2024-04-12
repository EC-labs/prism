use eyre::Result;
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{self, File},
    hash::Hash,
    io::Write,
    path::Path,
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
    device: u32,
    minute_map: HashMap<u64, HashMap<u64, u64>>,
    dir: Rc<str>,
}

impl ThreadDeviceStats {
    fn new(device: u32, parent: Rc<str>) -> Self {
        Self {
            device,
            minute_map: HashMap::new(),
            dir: parent,
        }
    }

    fn store(&mut self, sample_instant_s: u64) -> Result<()> {
        let remove: Vec<u64> = self
            .minute_map
            .iter()
            .map(|(minute, map)| {
                self.store_minute(minute, map);
                *minute
            })
            .filter(|minute| (minute * 60 + 60) < sample_instant_s)
            .collect();

        for minute in remove {
            self.minute_map.remove(&minute);
        }
        Ok(())
    }

    fn store_minute(&self, minute: &u64, map: &HashMap<u64, u64>) -> Result<()> {
        let minute_s = minute * 60;
        let file_path = format!("{}/{:?}/{:?}.csv", self.dir, minute_s, self.device);
        let parent = Path::new(&file_path).parent().unwrap();
        fs::create_dir_all(&parent)?;
        let mut file = File::create(&file_path)?;
        let mut data: Vec<u8> = Vec::with_capacity(1024);
        for second in 0..60 {
            if let Some(sectors) = map.get(&(minute_s + second)) {
                data.extend(format!("{:?},{:?}\n", minute_s + second, sectors).as_bytes());
            } else {
                data.extend(format!("{:?},{:?}\n", minute_s + second, 0).as_bytes());
            }
        }
        file.write_all(&data)?;
        Ok(())
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
            if self.update(key, contribution) {
                bio.last_instant_accounted = Some(key);
            }
        }
    }

    fn update(&mut self, second: u64, value: i64) -> bool {
        let sectors = if let Some(sectors) = self.get_mut_entry(&second) {
            sectors
        } else if value > 0 {
            self.insert_entry(second, 0)
        } else {
            return false;
        };
        *sectors = (*sectors as i64 + value) as u64;
        if *sectors == 0 {
            self.remove_entry(&second);
        }
        return true;
    }

    fn get_mut_entry(&mut self, second: &u64) -> Option<&mut u64> {
        let minute = second / 60;
        if let Some(map) = self.minute_map.get_mut(&minute) {
            map.get_mut(second)
        } else {
            None
        }
    }

    fn insert_entry(&mut self, second: u64, value: u64) -> &mut u64 {
        let minute = second / 60;
        self.minute_map
            .entry(minute)
            .or_insert(HashMap::new())
            .entry(second)
            .or_insert(value)
    }

    fn remove_entry(&mut self, second: &u64) -> Option<u64> {
        let minute = second / 60;
        if let Some(map) = self.minute_map.get_mut(&minute) {
            map.remove(second)
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ThreadIOStats {
    tid: usize,
    device_map: HashMap<u32, ThreadDeviceStats>,
    dir: Rc<str>,
}

impl ThreadIOStats {
    fn new(tid: usize, parent: Rc<str>) -> Self {
        Self {
            tid,
            device_map: HashMap::new(),
            dir: Rc::from(format!("{}/{:?}", parent, tid)),
        }
    }

    fn account(&mut self, bio: &mut Bio, instant_s: u64) {
        let buffer = self
            .device_map
            .entry(bio.device)
            .or_insert(ThreadDeviceStats::new(bio.device, self.dir.clone()));
        buffer.account(bio, instant_s);
    }

    fn store(&mut self, sample_instant_s: u64) -> Result<()> {
        for (_, device_stats) in self.device_map.iter_mut() {
            device_stats.store(sample_instant_s)?;
        }
        Ok(())
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

pub struct IOWait {
    iowait_program: Rc<RefCell<IOWaitProgram>>,
    pending_requests: HashMap<u32, HashMap<BioKey, Bio>>,
    thread_map: HashMap<usize, ThreadIOStats>,
    current_sample_instant_s: Option<u64>,
    last_store_10s: Option<u64>,
    dir: Rc<str>,
}

impl IOWait {
    pub fn new(iowait_program: Rc<RefCell<IOWaitProgram>>, parent: Option<Rc<str>>) -> Self {
        let dir = if let None = parent {
            Rc::from("iowait")
        } else {
            Rc::from(&*format!("{}/iowait", parent.unwrap()))
        };

        Self {
            iowait_program,
            pending_requests: HashMap::new(),
            thread_map: HashMap::new(),
            current_sample_instant_s: None,
            last_store_10s: None,
            dir,
        }
    }

    fn account_pending(&mut self) {
        let pending_requests = &mut self.pending_requests;
        for (_, bios) in pending_requests {
            for (_, mut bio) in bios {
                if bio.first_instant_s() <= self.current_sample_instant_s.unwrap() {
                    let thread_acc = self
                        .thread_map
                        .entry(bio.tid)
                        .or_insert(ThreadIOStats::new(bio.tid, self.dir.clone()));
                    thread_acc.account(&mut bio, self.current_sample_instant_s.unwrap());
                }
            }
        }
    }

    fn process_submit_bio(&mut self, mut bio: Bio) {
        if bio.first_instant_s() <= self.current_sample_instant_s.unwrap() {
            let thread_acc = self
                .thread_map
                .entry(bio.tid)
                .or_insert(ThreadIOStats::new(bio.tid, self.dir.clone()));
            thread_acc.account(&mut bio, self.current_sample_instant_s.unwrap());
        }

        let bio_map = self
            .pending_requests
            .entry(bio.device)
            .or_insert(HashMap::new());
        bio_map.insert(BioKey::from(&bio), bio);
    }

    fn process_bioendio(&mut self, key: BioKey, ns_since_boot: u128) {
        let bios = if let Some(requests) = self.pending_requests.get_mut(&key.device) {
            requests
        } else {
            return;
        };
        let bio = bios.remove(&key);
        if let None = bio {
            return;
        }
        let mut bio = bio.unwrap();

        let last_instant = (boot_to_epoch(ns_since_boot) / 1_000_000_000 + 1) as u64;
        let thread_acc = self
            .thread_map
            .entry(bio.tid)
            .or_insert(ThreadIOStats::new(bio.tid, self.dir.clone()));
        thread_acc.account(&mut bio, last_instant);
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
                let bio = Bio {
                    device,
                    sector,
                    sector_cnt,
                    epoch_ns: boot_to_epoch(ns_since_boot) as u64,
                    tid,
                    last_instant_accounted: None,
                };
                self.process_submit_bio(bio);
            }
            IOWaitEvent::BioEndIO {
                device,
                sector,
                sector_cnt,
                ns_since_boot,
                ..
            } => {
                let key = BioKey {
                    device,
                    sector,
                    sector_cnt,
                };
                self.process_bioendio(key, ns_since_boot);
            }
            _ => {}
        };
    }

    fn set_current_sample_instant(&mut self, value: Option<u64>) {
        if let None = value {
            let epoch_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_nanos();
            self.current_sample_instant_s = Some(((epoch_ns as u64) / 1_000_000_000) + 1);
        } else {
            self.current_sample_instant_s = value;
        }
    }
}

impl Collect for IOWait {
    fn sample(&mut self) -> Result<()> {
        let events = self
            .iowait_program
            .borrow_mut()
            .take_events()
            .unwrap_or(Vec::new());

        if let None = self.current_sample_instant_s {
            self.set_current_sample_instant(None)
        }

        for event in events {
            self.process_event(event);
        }
        self.account_pending();

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        let current_sample_insant_s = self.current_sample_instant_s.unwrap();
        if let Some(last_store) = self.last_store_10s {
            if last_store == (current_sample_insant_s / 10) {
                self.current_sample_instant_s = None;
                return Ok(());
            }
        }

        println!("Store iowait");
        for (_, thread_stats) in self.thread_map.iter_mut() {
            thread_stats.store(current_sample_insant_s)?
        }
        self.current_sample_instant_s = None;
        self.last_store_10s = Some(current_sample_insant_s / 10);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use eyre::{OptionExt, Result};
    use indoc::indoc;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use std::io::Write;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    use crate::execute::programs::iowait::IOWaitProgram;
    use crate::execute::{
        programs::{fcntl_setfd, pipe},
        BpfReader,
    };
    use crate::metrics::iowait::Bio;
    use crate::metrics::Collect;

    use super::{IOWait, ThreadDeviceStats};

    impl ThreadDeviceStats {
        fn get_entries(&self) -> HashMap<u64, u64> {
            self.minute_map
                .iter()
                .map(|(_, map)| map.iter().map(|(k, v)| (*k, *v)))
                .flatten()
                .collect()
        }
    }

    // Attaching 6 probes...
    // bio_s	772129082664043	264241153	264241153	443675136	8	1	1	0	3	LS Thread
    // bio_s	772129082688258	264241153	264241153	443675144	8	1	1	0	4	LS Thread
    // bio_s	772129082689146	264241152	264241152	443677192	8	1	1	0	4	LS Thread
    // bio_e	772129085774881	264241153	264241153	443675136	8	1	1	0	0	swapper/13
    // bio_e	772129085777546	264241152	264241152	443677192	8	1	1	0	0	swapper/13
    // bio_e	772129085778357	264241153	264241153	443675144	8	1	1	0	0	swapper/13

    fn get_buffer<'a>(
        iowait: &'a IOWait,
        thread: &usize,
        device: &u32,
    ) -> Result<HashMap<u64, u64>> {
        let thread_stats = iowait
            .thread_map
            .get(thread)
            .ok_or_eyre("Missing key thread map")?;
        Ok(thread_stats
            .device_map
            .get(device)
            .ok_or_eyre("Missing key device map")?
            .get_entries())
    }

    #[test]
    fn submit() -> Result<()> {
        let reader = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_s	000001100000000	264241153	264241153	443675144	8	1	1	0	4	LS Thread
        "#};
        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader.as_bytes(), terminate_flag);
        while !iowait_program.header_read() {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let _ = iowait_program.poll_events();
        }
        let mut iowait = IOWait::new(Rc::new(RefCell::new(iowait_program)), None);

        iowait.current_sample_instant_s = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8)]), buffer);

        iowait.current_sample_instant_s = Some(000002);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(HashMap::from([(2, 8)]), buffer);

        Ok(())
    }

    #[test]
    fn submit_delayed() -> Result<()> {
        let (mut reader, mut writer) = pipe();
        fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);

        let data = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;

        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader, terminate_flag);
        while !iowait_program.header_read() {
            std::thread::sleep(std::time::Duration::from_millis(10));
            iowait_program.poll_events()?;
        }

        let iowait_program = Rc::new(RefCell::new(iowait_program));
        let mut iowait = IOWait::new(iowait_program.clone(), None);

        iowait.current_sample_instant_s = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8)]), buffer);

        let data = indoc! {r#"
            bio_s	000000110000000	264241153	264241153	443675144	8	1	1	0	3	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;
        drop(writer);
        while let Ok(_) = iowait_program.borrow_mut().poll_events() {}
        iowait.current_sample_instant_s = Some(000002);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 16), (2, 16)]), buffer);

        Ok(())
    }

    #[test]
    fn sample() -> Result<()> {
        let (mut reader, mut writer) = pipe();
        fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let data = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_s	000001100000000	264241153	264241153	443675144	8	1	1	0	4	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;

        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader, terminate_flag);
        while !iowait_program.header_read() {
            let _ = iowait_program.poll_events();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let iowait_program = Rc::new(RefCell::new(iowait_program));
        let mut iowait = IOWait::new(iowait_program.clone(), None);

        iowait.current_sample_instant_s = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8)]), buffer);

        iowait.current_sample_instant_s = Some(000002);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(HashMap::from([(2, 8)]), buffer);

        iowait.current_sample_instant_s = Some(000003);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(HashMap::from([(2, 8), (3, 8)]), buffer);

        let data = indoc! {r#"
            bio_e	000002900000000	264241153	264241153	443675136	8	1	1	0	0	swapper/13
        "#};
        writer.write_all(data.as_bytes())?;
        while iowait_program.borrow_mut().poll_events().unwrap() == 0 {}
        iowait.current_sample_instant_s = Some(000004);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(HashMap::from([(2, 8), (3, 8), (4, 8)]), buffer);

        Ok(())
    }

    #[test]
    fn bioendio() -> Result<()> {
        let (mut reader, mut writer) = pipe();
        fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let data = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_s	000001100000000	264241153	264241153	443675144	8	1	1	0	4	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;

        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader, terminate_flag);
        while !iowait_program.header_read() {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let _ = iowait_program.poll_events();
        }
        let iowait_program = Rc::new(RefCell::new(iowait_program));
        let mut iowait = IOWait::new(iowait_program.clone(), None);

        iowait.current_sample_instant_s = Some(000001);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8)]), buffer);

        iowait.current_sample_instant_s = Some(000003);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(HashMap::from([(2, 8), (3, 8)]), buffer);

        let data = indoc! {r#"
            bio_e	000001900000000	264241153	264241153	443675136	8	1	1	0	0	swapper/13
        "#};
        writer.write_all(data.as_bytes())?;
        while iowait_program.borrow_mut().poll_events().unwrap() == 0 {}
        iowait.current_sample_instant_s = Some(000004);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(HashMap::from([(2, 8), (3, 8), (4, 8)]), buffer);
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);

        let data = indoc! {r#"
            bio_e	000002900000000	264241153	264241153	443675144	8	1	1	0	0	swapper/13
        "#};
        writer.write_all(data.as_bytes())?;
        while iowait_program.borrow_mut().poll_events().unwrap() == 0 {}
        iowait.current_sample_instant_s = Some(000004);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &4, &264241153)?;
        assert_eq!(HashMap::from([(2, 8), (3, 8)]), buffer);
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);

        Ok(())
    }

    #[test]
    fn bioendio_within_interval() -> Result<()> {
        let (mut reader, mut writer) = pipe();
        fcntl_setfd(&mut reader, libc::O_RDONLY | libc::O_NONBLOCK);
        let data = indoc! {r#"
            Attaching 6 probes...
            bio_s	000001100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_e	000001200000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
        "#};
        writer.write_all(data.as_bytes())?;

        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader, terminate_flag);
        while !iowait_program.header_read() {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let _ = iowait_program.poll_events();
        }
        let mut iowait = IOWait::new(Rc::new(RefCell::new(iowait_program)), None);

        iowait.current_sample_instant_s = Some(2);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(2, 8)]), buffer);

        Ok(())
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

        let mut buf = ThreadDeviceStats::new(1, Rc::from("iowait"));
        let mut bio = create_bio(0100, 2);
        buf.account(&mut bio, 1);
        assert_eq!(HashMap::from([(1, 2)]), buf.get_entries());

        let mut bio = create_bio(1100, 10);
        buf.account(&mut bio, 2);
        assert_eq!(HashMap::from([(1, 2), (2, 10)]), buf.get_entries());

        buf.account(&mut bio, 3);
        assert_eq!(HashMap::from([(1, 2), (2, 10), (3, 10)]), buf.get_entries());

        let mut bio = create_bio(1100, 4);
        buf.account(&mut bio, 4);
        assert_eq!(
            HashMap::from([(1, 2), (2, 14), (3, 14), (4, 4)]),
            buf.get_entries()
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

        let mut buf = ThreadDeviceStats::new(1, Rc::from("iowait"));
        let mut bio = create_bio(1100, 10);
        buf.account(&mut bio, 2);
        buf.account(&mut bio, 3);
        let mut bio = create_bio(1100, 4);
        buf.account(&mut bio, 4);
        assert_eq!(HashMap::from([(2, 14), (3, 14), (4, 4)]), buf.get_entries());

        // Subtract
        buf.account(&mut bio, 2);
        assert_eq!(HashMap::from([(2, 14), (3, 10)]), buf.get_entries());
    }

    #[test]
    fn minute_maps() -> Result<()> {
        let reader = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_e	000001100000000	264241153	264241153	443675136	8	1	1	0	0	swapper/13
            bio_s	000000100000000	264241153	264241154	443675148	8	1	1	0	4	LS Thread
            bio_e	000001100000000	264241153	264241154	443675148	8	1	1	0	0	swapper/13
            bio_s	000061000000000	264241153	264241154	443675144	8	1	1	0	4	LS Thread
            bio_e	000062000000000	264241153	264241154	443675144	8	1	1	0	0	swapper/13
        "#};
        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader.as_bytes(), terminate_flag);
        while !iowait_program.header_read() {
            let _ = iowait_program.poll_events();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut iowait = IOWait::new(Rc::new(RefCell::new(iowait_program)), None);

        iowait.current_sample_instant_s = Some(1);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);

        iowait.current_sample_instant_s = Some(70);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241154)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8), (62, 8), (63, 8)]), buffer);

        let minute = iowait
            .thread_map
            .get(&4)
            .ok_or_eyre("Missing thread")?
            .device_map
            .get(&264241154)
            .ok_or_eyre("Missing device")?;
        let map = minute.minute_map.get(&0).ok_or_eyre("Missing minute")?;
        assert_eq!(&HashMap::from([(1, 8), (2, 8)]), map);
        let map = minute.minute_map.get(&1).ok_or_eyre("Missing minute")?;
        assert_eq!(&HashMap::from([(62, 8), (63, 8)]), map);

        Ok(())
    }

    use tempdir::TempDir;

    #[test]
    fn store() -> Result<()> {
        let reader = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_e	000001100000000	264241153	264241153	443675136	8	1	1	0	0	swapper/13
            bio_s	000061000000000	264241153	264241154	443675144	8	1	1	0	4	LS Thread
            bio_e	000062000000000	264241153	264241154	443675144	8	1	1	0	0	swapper/13
        "#};
        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader.as_bytes(), terminate_flag);
        while !iowait_program.header_read() {
            let _ = iowait_program.poll_events();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let tmp_dir = TempDir::new("test_store")?;
        let mut iowait = IOWait::new(
            Rc::new(RefCell::new(iowait_program)),
            Some(Rc::from(tmp_dir.path().to_str().unwrap())),
        );

        iowait.current_sample_instant_s = Some(1);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241154)?;
        assert_eq!(HashMap::from([(62, 8), (63, 8)]), buffer);

        iowait.store()?;
        let file_path = format!(
            "{}/iowait/3/0/264241153.csv",
            tmp_dir.path().to_str().unwrap()
        );
        let content = fs::read_to_string(file_path)?;
        for line in content.lines() {
            let mut elements = line.split(',');
            let second = elements.next().unwrap();
            if second == "1" || second == "2" {
                assert_eq!(elements.next().unwrap(), "8");
            } else {
                assert_eq!(elements.next().unwrap(), "0");
            }
        }

        let file_path = format!(
            "{}/iowait/4/60/264241154.csv",
            tmp_dir.path().to_str().unwrap()
        );
        let content = fs::read_to_string(file_path)?;
        let mut line_count = 0;
        for line in content.lines() {
            let mut elements = line.split(',');
            let second = elements.next().unwrap();
            if second == "62" || second == "63" {
                assert_eq!(elements.next().unwrap(), "8");
            } else {
                assert_eq!(elements.next().unwrap(), "0");
            }
            line_count += 1;
        }
        assert_eq!(line_count, 60);
        Ok(())
    }

    #[test]
    fn store_remove() -> Result<()> {
        let reader = indoc! {r#"
            Attaching 6 probes...
            bio_s	000000100000000	264241153	264241153	443675136	8	1	1	0	3	LS Thread
            bio_e	000001100000000	264241153	264241153	443675136	8	1	1	0	0	swapper/13
            bio_s	000008000000000	264241153	264241154	443675144	8	1	1	0	4	LS Thread
            bio_e	000009000000000	264241153	264241154	443675144	8	1	1	0	0	swapper/13
        "#};
        let terminate_flag = Arc::new(Mutex::new(false));
        let mut iowait_program = IOWaitProgram::custom_reader(reader.as_bytes(), terminate_flag);
        while !iowait_program.header_read() {
            let _ = iowait_program.poll_events();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let tmp_dir = TempDir::new("test_store")?;
        let mut iowait = IOWait::new(
            Rc::new(RefCell::new(iowait_program)),
            Some(Rc::from(tmp_dir.path().to_str().unwrap())),
        );

        iowait.current_sample_instant_s = Some(70);
        iowait.sample().unwrap();
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(HashMap::from([(1, 8), (2, 8)]), buffer);
        let buffer = get_buffer(&iowait, &4, &264241154)?;
        assert_eq!(HashMap::from([(9, 8), (10, 8)]), buffer);

        iowait.store()?;
        let buffer = get_buffer(&iowait, &3, &264241153)?;
        assert_eq!(buffer.len(), 0);
        let buffer = get_buffer(&iowait, &4, &264241154)?;
        assert_eq!(buffer.len(), 0);

        Ok(())
    }
}
