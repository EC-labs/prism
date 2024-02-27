use ctrlc;
use eyre::Result;
use std::{
    fs,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::configure::Config;
use crate::metrics::{
    scheduler::{Sched, SchedStat},
    Collect,
};
use crate::target::Target;

pub struct Extractor {
    terminate_flag: Arc<Mutex<bool>>,
    config: Config,
}

impl Extractor {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            terminate_flag: Arc::new(Mutex::new(false)),
        }
    }

    fn register_sighandler(&self) {
        let terminate_flag = self.terminate_flag.clone();
        ctrlc::set_handler(move || {
            let mut terminate_flag = terminate_flag.lock().unwrap();
            *terminate_flag = true;
        })
        .expect("Error setting Ctrl-C handler");
    }

    pub fn run(self) -> Result<()> {
        self.register_sighandler();

        let mut targets = Target::search_targets_regex("jbd2", true, &self.config.data_directory)?;
        targets.extend(Target::search_targets_regex(
            "example-app",
            false,
            &self.config.data_directory,
        )?);

        loop {
            if *self.terminate_flag.lock().unwrap() == true {
                break;
            }

            targets
                .iter_mut()
                .map(|target| target.sample())
                .collect::<Result<()>>()?;

            thread::sleep(Duration::from_millis(self.config.period));
        }

        Ok(())
    }
}
