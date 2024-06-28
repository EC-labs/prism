use collector::cmdline;
use collector::configure::Config;
use collector::extract::Extractor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
