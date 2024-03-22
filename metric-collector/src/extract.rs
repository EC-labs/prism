use ctrlc;
use eyre::Result;
use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::configure::Config;
use crate::execute::Executor;
use crate::target::Target;

pub struct Extractor {
    terminate_flag: Arc<Mutex<bool>>,
    config: Config,
    targets: Vec<Target>,
}

impl Extractor {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            terminate_flag: Arc::new(Mutex::new(false)),
            targets: Vec::new(),
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

    fn register_new_targets(&mut self, executor: &mut Executor) {
        executor
            .monitor_groups
            .iter_mut()
            .for_each(|(pid, monitor_group)| {
                let new_targets = monitor_group.clone.poll_events().unwrap();
                for target in new_targets {
                    self.targets.push(Target::new(
                        target,
                        monitor_group.futex.clone(),
                        &self.config.data_directory,
                    ));
                }
            });
    }

    fn sample_targets(&mut self) -> Result<()> {
        self.targets
            .iter_mut()
            .map(|target| target.sample())
            .collect::<Result<()>>()
    }

    pub fn run(mut self) -> Result<()> {
        self.register_sighandler();
        let mut executor = Executor::new();

        self.targets =
            Target::search_targets_regex("jbd2", true, &self.config.data_directory, &mut executor)?;
        self.targets.extend(Target::search_targets_regex(
            "thread-sync",
            false,
            &self.config.data_directory,
            &mut executor,
        )?);

        loop {
            if *self.terminate_flag.lock().unwrap() == true {
                break;
            }

            self.sample_targets()?;
            self.register_new_targets(&mut executor);
            thread::sleep(Duration::from_millis(self.config.period));
        }

        Ok(())
    }
}
