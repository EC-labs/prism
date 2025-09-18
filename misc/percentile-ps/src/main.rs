use eyre::Result;

mod cli;
mod config;
mod program;

use config::Config;
use program::{response_time::PercentileResponseTime, throughput_ops::ThroughputOps};

fn main() -> Result<()> {
    let cmd = cli::register_args();
    let config = Config::try_from(cmd.get_matches())?;
    match config {
        Config::ResponseTimePercentile {
            percentile,
            time_factor,
        } => {
            PercentileResponseTime::run(time_factor, percentile);
        }
        Config::ThroughputOps { time_factor } => {
            ThroughputOps::run(time_factor);
        }
    }

    Ok(())
}
