mod cmdline;
mod configure;
mod execute;
mod extract;
mod metrics;
mod target;

use configure::Config;
use extract::Extractor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = cmdline::register_args();
    let config = Config::from(command.get_matches());

    let extractor = Extractor::new(config);
    extractor.run()?;

    Ok(())
}
