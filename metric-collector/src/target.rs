use anyhow::Result;
use duckdb::Connection;
use libbpf_rs::MapHandle;
use log::info;
use regex::Regex;
use std::{
    cell::RefCell,
    collections::HashMap,
    error::Error,
    fmt::{self, Display},
    fs,
    rc::Rc,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

pub fn search_targets_regex(name: &str, kthread: bool) -> Result<Vec<usize>> {
    let mut targets = Vec::new();
    let tasks = fs::read_dir(format!("/proc"))?;
    for task in tasks {
        let file_path = task?.path();
        let stem = file_path.file_stem().unwrap().to_str().unwrap();
        let re = Regex::new(r"\d+").unwrap();
        let captures = re.captures(stem);
        if let None = captures {
            continue;
        }

        let proc_stat = fs::read_to_string(format!("{}/stat", file_path.to_str().unwrap()));
        if let Err(_) = proc_stat {
            continue;
        }
        let proc_stat = proc_stat.unwrap();
        let mut proc_stat = proc_stat.split(" ");
        let (comm, flags) = (proc_stat.nth(1).unwrap(), proc_stat.nth(6).unwrap());
        let re = Regex::new(r"[\(\)]")?;
        let comm = re.replace_all(&comm, "");
        let flags = flags.parse::<i64>()?;

        let is_kthread = (flags & 0x00200000) != 0;
        if is_kthread != kthread {
            continue;
        }

        let re = Regex::new(name)?;
        let re_match = re.captures(&comm);
        if let None = re_match {
            continue;
        }
        let pid: usize = stem.parse()?;

        targets.push(pid);
    }

    return Ok(targets);
}
