use anyhow::Result;
use std::time::Duration;
use std::{env, mem::MaybeUninit};

pub mod cmdline;
pub mod configure;
pub mod execute;
pub mod extract;
pub mod metrics;
pub mod sub;
mod target;

use crate::configure::Config;
use crate::extract::Extractor;

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
