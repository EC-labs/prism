use ctrlc;
use eyre::Result;
use std::{
    collections::HashMap,
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
    targets: HashMap<usize, Target>,
}

impl Extractor {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            terminate_flag: Arc::new(Mutex::new(false)),
            targets: HashMap::new(),
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
            .for_each(|(_, monitor_group)| {
                let new_targets = monitor_group.clone.poll_events().unwrap();
                for target in new_targets {
                    self.targets.insert(
                        target,
                        Target::new(
                            target,
                            monitor_group.futex.clone(),
                            &self.config.data_directory,
                        ),
                    );
                }
            });
    }

    fn sample_targets(&mut self) {
        let mut targets_remove = Vec::new();
        self.targets.iter_mut().for_each(|(tid, target)| {
            if let Err(_) = target.sample() {
                targets_remove.push(*tid)
            }
        });

        for tid in targets_remove {
            self.targets.remove(&tid);
        }
    }

    pub fn run(mut self) -> Result<()> {
        self.register_sighandler();
        let mut executor = Executor::new();

        Target::search_targets_regex("jbd2", true, &self.config.data_directory, &mut executor)?
            .into_iter()
            .for_each(|target| {
                self.targets.insert(target.tid, target);
            });

        let targets = Target::search_targets_regex(
            "example-app",
            false,
            &self.config.data_directory,
            &mut executor,
        )?;
        targets.into_iter().for_each(|target| {
            self.targets.insert(target.tid, target);
        });

        loop {
            if *self.terminate_flag.lock().unwrap() == true {
                break;
            }

            self.sample_targets();
            self.register_new_targets(&mut executor);
            thread::sleep(Duration::from_millis(self.config.period));
        }

        Ok(())
    }
}
