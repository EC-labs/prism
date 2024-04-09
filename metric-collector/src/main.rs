use collector::cmdline;
use collector::configure::Config;
use collector::extract::Extractor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = cmdline::register_args();
    let config = Config::from(command.get_matches());

    let extractor = Extractor::new(config);
    extractor.run()?;

    Ok(())
}
