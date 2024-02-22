mod cmdline;
mod configure;
mod extract;
mod metrics;

use configure::Config;
use extract::Extractor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = cmdline::register_args();
    let config = Config::from(command.get_matches());

    let extractor = Extractor::new(config);
    extractor.run()?;

    Ok(())
}
