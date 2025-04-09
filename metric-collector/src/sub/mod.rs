use anyhow::{bail, Result};

pub mod futex;
pub mod iowait;
pub mod muxio;
pub mod net;
pub mod taskstats;
pub mod vfs;

mod consts {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(clippy::const_static_lifetime)]
    #![allow(clippy::unreadable_literal)]
    #![allow(clippy::cyclomatic_complexity)]
    #![allow(clippy::useless_transmute)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/include/consts.bindings.rs"
    ));
}

pub const SAMPLES: u64 = consts::SAMPLES as u64;
pub const MAX_ENTRIES: u64 = consts::MAX_ENTRIES as u64;
pub const BATCH_SIZE: usize = 8192;

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
