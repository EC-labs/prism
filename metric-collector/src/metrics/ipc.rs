use eyre::{OptionExt, Result};
use lru_time_cache::LruCache;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::prelude::*,
    mem,
    path::Path,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::execute::programs::{
    ipc::{IpcEvent, IpcProgram},
    BOOT_EPOCH_NS,
};

use super::Collect;
use super::ToCsv;

type KFile = (u32, u64);

pub struct Ipc {
    ipc_program: Rc<RefCell<IpcProgram>>,
    file_map: HashMap<KFile, u64>,
    sum_file_wait_time_ns: u64,
    pending: HashMap<KFile, u64>,
    last_updated: HashSet<KFile>,
    tid: usize,
    data_files: LruCache<String, File>,
    sample_instant_ns: Option<u128>,
    target_subdirectory: String,
}

impl Ipc {
    pub fn new(
        ipc_program: Rc<RefCell<IpcProgram>>,
        tid: usize,
        root_directory: Rc<str>,
        target_subdirectory: &str,
    ) -> Self {
        Self {
            ipc_program,
            tid,
            file_map: HashMap::new(),
            sum_file_wait_time_ns: 0,
            pending: HashMap::new(),
            last_updated: HashSet::new(),
            data_files: LruCache::with_expiry_duration(Duration::from_millis(120)),
            sample_instant_ns: None,
            target_subdirectory: format!("{}/{}/ipc", root_directory, target_subdirectory),
        }
    }

    fn process_event(&mut self, event: IpcEvent) {
        println!("{:?}", event);
        match event {
            IpcEvent::ReadStart {
                sb_id,
                inode_id,
                ns_since_boot,
                ..
            }
            | IpcEvent::WriteStart {
                sb_id,
                inode_id,
                ns_since_boot,
                ..
            } => {
                self.pending.insert((sb_id, inode_id), ns_since_boot);
                self.last_updated.insert((sb_id, inode_id));
            }
            IpcEvent::ReadEnd {
                sb_id,
                inode_id,
                ns_elapsed,
                ..
            }
            | IpcEvent::WriteEnd {
                sb_id,
                inode_id,
                ns_elapsed,
                ..
            } => {
                let entry = self.file_map.entry((sb_id, inode_id)).or_insert(0);
                self.last_updated.insert((sb_id, inode_id));
                *entry += ns_elapsed;
                self.sum_file_wait_time_ns += ns_elapsed;
            }
            _ => {
                println!("{:?}", event);
            }
        }
    }

    fn get_or_create_file(&mut self, filepath: &Path, headers: &str) -> Result<&File> {
        let file = self.data_files.get(filepath.to_str().unwrap());
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
            self.data_files
                .insert(filepath.to_str().unwrap().into(), file);
        }

        let file = self.data_files.get(filepath.to_str().unwrap());
        Ok(file.unwrap())
    }
}

impl Collect for Ipc {
    fn sample(&mut self) -> Result<()> {
        let events = self.ipc_program.borrow_mut().take_tid_events(self.tid)?;

        let sample_instant = SystemTime::now();
        self.sample_instant_ns = Some(
            sample_instant
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_nanos(),
        );

        for event in events {
            self.process_event(event);
        }

        Ok(())
    }

    fn store(&mut self) -> Result<()> {
        if self.last_updated.len() == 0 {
            return Ok(());
        }

        let epoch_ns = self
            .sample_instant_ns
            .take()
            .ok_or_eyre("Missing sample instant")?;
        let epoch_ms = epoch_ns / 1_000_000;

        let last_updated = mem::replace(&mut self.last_updated, HashSet::new());
        for kfile in last_updated {
            let pending = if let Some(ns_since_boot) = self.pending.get(&kfile) {
                epoch_ns - (*BOOT_EPOCH_NS.read().unwrap() + *ns_since_boot as u128)
            } else {
                0
            };
            let cached_wait = *self.file_map.get(&kfile).unwrap_or(&0);
            let cumulative_wait = pending as u64 + cached_wait;

            let sample = IpcFileSample {
                epoch_ms,
                cumulative_wait,
            };

            let file_path = format!(
                "{}/streams/{:?}/{:?}_{:?}.csv",
                self.target_subdirectory,
                (epoch_ms / (1000 * 60)) * 60,
                kfile.0,
                kfile.1,
            );
            let mut file = self.get_or_create_file(Path::new(&file_path), sample.csv_headers())?;
            file.write_all(sample.to_csv_row().as_bytes())?;
        }
        Ok(())
    }
}

struct IpcFileSample {
    epoch_ms: u128,
    cumulative_wait: u64,
}

impl ToCsv for IpcFileSample {
    fn to_csv_row(&self) -> String {
        format!("{},{}\n", self.epoch_ms, self.cumulative_wait)
    }

    fn csv_headers(&self) -> &'static str {
        "epoch_ms,stream_wait\n"
    }
}
