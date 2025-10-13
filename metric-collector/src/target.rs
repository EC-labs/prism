use anyhow::Result;
use regex::Regex;
use std::fs;
use lazy_static::lazy_static;

lazy_static! {
    static ref RE_UINT: Regex = Regex::new(r"\d+").unwrap();
    static ref PARENTHESIS: Regex = Regex::new(r"[\(\)]").unwrap();

}


pub fn search_targets_regex(name: &str, kthread: bool) -> Result<Vec<usize>> {
    let mut targets = Vec::new();
    let tasks = fs::read_dir("/proc")?;
    for task in tasks {
        let file_path = task?.path();
        let stem = file_path.file_stem().unwrap().to_str().unwrap();
        let captures = RE_UINT.captures(stem);
        if captures.is_none() {
            continue;
        }

        let proc_stat = fs::read_to_string(format!("{}/stat", file_path.to_str().unwrap()));
        if proc_stat.is_err() {
            continue;
        }
        let proc_stat = proc_stat.unwrap();
        let mut proc_stat = proc_stat.split(" ");
        let (comm, flags) = (proc_stat.nth(1).unwrap(), proc_stat.nth(6).unwrap());
        let comm = PARENTHESIS.replace_all(comm, "");
        let flags = flags.parse::<i64>()?;

        let is_kthread = (flags & 0x00200000) != 0;
        if is_kthread != kthread {
            continue;
        }

        let re = Regex::new(name)?;
        let re_match = re.captures(&comm);
        if re_match.is_none() {
            continue;
        }
        let pid: usize = stem.parse()?;

        targets.push(pid);
    }

    Ok(targets)
}
