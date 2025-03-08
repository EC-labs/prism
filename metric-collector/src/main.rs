use anyhow::Result;
use std::time::Duration;
use std::{env, mem::MaybeUninit};

use collector::cmdline;
use collector::configure::Config;
use collector::extract::Extractor;
use collector::sub;
use collector::sub::vfs::Vfs;
use duckdb::Connection;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use libc::{geteuid, getuid, seteuid};

fn create_pid_map() -> Result<MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    Ok(MapHandle::create(
        MapType::Hash,
        Some("pids"),
        size_of::<u32>() as u32,
        size_of::<u8>() as u32,
        8192,
        &opts,
    )?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let mut command = cmdline::register_args();
    let help = command.render_help();
    let config = match Config::try_from(command.get_matches()) {
        Err(e) => {
            eprintln!("{help}");
            return Err(e);
        }
        Ok(config) => config,
    };

    let euid = unsafe { geteuid() };
    let uid = env::var("SUDO_UID")?.parse::<u32>()?;
    unsafe { seteuid(uid) };
    let path = "./data/prism-db.db3";
    let conn = Connection::open(&path)?;
    unsafe { seteuid(euid) };

    let mut iowait_open_object = MaybeUninit::uninit();
    let mut iowait = sub::iowait::IOWait::new(&mut iowait_open_object, &conn).unwrap();

    let pid_map = create_pid_map()?;
    for pid in config.pids.unwrap() {
        pid_map.update(
            &(pid as u32).to_ne_bytes(),
            &1u8.to_ne_bytes(),
            MapFlags::ANY,
        )?;
    }
    let mut vfs_open_object = MaybeUninit::uninit();
    let mut vfs = Vfs::new(&mut vfs_open_object, &conn, pid_map).unwrap();

    for _ in 0..20 {
        iowait.sample()?;
        vfs.sample()?;
        std::thread::sleep(Duration::from_millis(1000));
    }
    // let extractor = Extractor::new(config);
    // extractor.run()?;

    Ok(())
}
