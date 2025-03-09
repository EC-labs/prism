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

    let extractor = Extractor::new(config);
    extractor.run()?;

    Ok(())
}
