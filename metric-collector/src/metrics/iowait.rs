use eyre::Result;
use lru_time_cache::LruCache;
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{self, File},
    io::Write,
    mem,
    path::Path,
    rc::Rc,
    time::Duration,
};

use crate::execute::{
    self,
    programs::iowait::{IOWaitProgram, IowaitEvent},
};

use super::Collect;

struct ThreadDeviceStats {
    device: u32,
    minute_map: LruCache<u64, HashMap<u64, usize>>,
    dir: Rc<str>,
    data_files: LruCache<String, File>,
}

impl ThreadDeviceStats {
    fn new(device: u32, parent: Rc<str>) -> Self {
        Self {
            device,
            minute_map: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
            dir: parent,
            data_files: LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
        }
    }

    fn get_or_create_file<'a>(
        data_files: &'a mut LruCache<String, File>,
        filepath: &Path,
        headers: &str,
    ) -> Result<&'a File> {
        let file = data_files.get(filepath.to_str().unwrap());
        if let None = file {
            let file = File::options().append(true).open(filepath);
            let file = match file {
                Err(_) => {
                    fs::create_dir_all(filepath.parent().unwrap())?;
                    let mut file = File::options().append(true).create(true).open(filepath)?;
                    file.write_all(headers.as_bytes())?;
                    file
                }
                Ok(file) => file,
            };
            data_files.insert(filepath.to_str().unwrap().into(), file);
        }

        let file = data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }

    fn store(&mut self) -> Result<()> {
        if self.minute_map.len() == 0 {
            return Ok(());
        }

        let mut minute_map = mem::replace(
            &mut self.minute_map,
            LruCache::with_expiry_duration(Duration::from_millis(1000 * 120)),
        );
        minute_map
            .iter()
            .map(|(minute, map)| {
                Self::store_minute(
                    &mut self.data_files,
                    self.dir.clone(),
                    self.device,
                    minute,
                    map,
                )
            })
            .collect()
    }

    fn store_minute(
        data_files: &mut LruCache<String, File>,
        dir: Rc<str>,
        device: u32,
        minute: &u64,
        map: &HashMap<u64, usize>,
    ) -> Result<()> {
        let minute_s = minute * 60;
        let file_path = format!("{}/{:?}/{:?}.csv", dir, minute_s, device);
        let mut file = Self::get_or_create_file(
            data_files,
            &Path::new(file_path.as_str()),
            "epoch_s,sector_cnt\n",
        )?;
        let mut data: Vec<u8> = Vec::with_capacity(1024);

        let mut sorted = map.iter().collect::<Vec<(&u64, &usize)>>();
        sorted.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());
        for (second, sectors) in sorted {
            if *sectors == 0 {
                continue;
            }
            data.extend(format!("{:?},{:?}\n", second, sectors).as_bytes());
        }

        file.write_all(&data)?;
        Ok(())
    }

    fn process(&mut self, event: IowaitEvent) {
        let IowaitEvent::Requests {
            ns_since_boot,
            sector_cnt,
            ..
        } = event;
        let instant_s = (execute::boot_to_epoch(ns_since_boot as u128) / 10u128.pow(9)) as u64;
        if sector_cnt == 0 {
            return;
        }
        self.insert_entry(instant_s, sector_cnt);
    }

    fn insert_entry(&mut self, second: u64, value: usize) -> &mut usize {
        let minute = second / 60;
        self.minute_map
            .entry(minute)
            .or_insert(HashMap::new())
            .entry(second)
            .or_insert(value)
    }
}

struct ThreadIOStats {
    tid: usize,
    device_map: HashMap<u32, ThreadDeviceStats>,
    dir: Rc<str>,
}

impl ThreadIOStats {
    fn new(tid: usize, pid: usize, parent: Rc<str>) -> Self {
        Self {
            tid,
            device_map: HashMap::new(),
            dir: Rc::from(format!("{}/{}/{:?}", parent, pid, tid)),
        }
    }

    fn process(&mut self, event: IowaitEvent) {
        let IowaitEvent::Requests { ref device, .. } = event;
        let thread_device = self
            .device_map
            .entry(*device)
            .or_insert(ThreadDeviceStats::new(*device, self.dir.clone()));
        thread_device.process(event);
    }

    fn store(&mut self) -> Result<()> {
        for (_, device_stats) in self.device_map.iter_mut() {
            device_stats.store()?;
        }
        Ok(())
    }
}

pub struct IOWait {
    iowait_program: Rc<RefCell<IOWaitProgram>>,
    thread_map: HashMap<usize, ThreadIOStats>,
    dir: Rc<str>,
}

impl IOWait {
    pub fn new(iowait_program: Rc<RefCell<IOWaitProgram>>, parent: Option<Rc<str>>) -> Self {
        let dir = if let None = parent {
            Rc::from("iowait")
        } else {
            Rc::from(&*format!("{}/global/iowait", parent.unwrap()))
        };

        Self {
            iowait_program,
            thread_map: HashMap::new(),
            dir,
        }
    }

    fn process_event(&mut self, event: IowaitEvent) {
        let IowaitEvent::Requests {
            ref tid, ref pid, ..
        } = event;
        let thread_acc =
            self.thread_map
                .entry(*tid)
                .or_insert(ThreadIOStats::new(*tid, *pid, self.dir.clone()));
        thread_acc.process(event);
    }
}

impl Collect for IOWait {
    fn sample(&mut self) -> Result<()> {
        let events = self
            .iowait_program
            .borrow_mut()
            .take_events()
            .unwrap_or(Vec::new());

        for event in events {
            self.process_event(event);
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        for (_, thread_stats) in self.thread_map.iter_mut() {
            thread_stats.store()?
        }

        Ok(())
    }
}
