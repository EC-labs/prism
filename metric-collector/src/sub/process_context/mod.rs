use anyhow::Result;
use bus::BusReader;
use duckdb::Connection;
use std::{ffi::CStr, fs::{self, File}, io::Read, path::{Path, PathBuf}, sync::{Arc, Mutex}, thread, time::Duration};

struct Pid(u32);

#[derive(Debug)]
pub struct ProcessContext {
    cgroup: String, 
    argv: Vec<String>,
    exe: PathBuf,
}

impl TryFrom<Pid> for ProcessContext {
    type Error = anyhow::Error;

    fn try_from(value: Pid) -> Result<Self> {
        let pid_proc = format!("/proc/{}", value.0);
        let pid_proc_path = Path::new(pid_proc.as_str());

        let cgroup_path = pid_proc_path.join("cgroup");
        let cgroup = fs::read_to_string(cgroup_path)?;
        
        let cmdline_path = pid_proc_path.join("cmdline");
        let mut cmdline_file = File::open(cmdline_path)?;
        let mut cmdline_content = Vec::new();
        cmdline_file.read_to_end(&mut cmdline_content);
        let cmdline_null_bytes = cmdline_content.iter().enumerate().fold(Vec::new(), |mut acc, (pos, x)| {
            if pos == 0 {
                acc.push(pos);
            }

            if *x == 0 {
                acc.push(pos + 1);
            }
            acc
        });

        let mut argv = Vec::new();
        for pair in cmdline_null_bytes.windows(2) {
            match CStr::from_bytes_with_nul(&cmdline_content[pair[0]..pair[1]])?.to_str() {
                Ok(arg) => { 
                    argv.push(String::from(arg));
                }
                Err(e) => {
                    argv.push(String::from("InvalidUtf8"))
                }
            }

        }

        let exe_file = pid_proc_path.join("exe");
        let exe = fs::read_link(exe_file)?;

        Ok(Self { cgroup, argv, exe })
    }
}

pub fn init_thread(terminate_flag: Arc<Mutex<bool>>, conn: &Connection, mut pid_rx: BusReader<u32>) -> Result<()> {
    let conn = conn.try_clone()?;
    thread::spawn(move || {
        loop {
            let Ok(terminate) = terminate_flag.lock() else { break };
            if *terminate == true {
                break;
            }
            drop(terminate);

            let pid = match pid_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(pid) => Pid(pid),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => { continue }
                Err(e) => { break }
            };
            let context = ProcessContext::try_from(pid);
            println!("process context {:?}", context);

        }
        Ok(()) as Result<()>
    });
    Ok(())
}
