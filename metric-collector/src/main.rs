use std::mem::MaybeUninit;
use std::time::Duration;

use collector::cmdline;
use collector::configure::Config;
use collector::extract::Extractor;
use collector::sub;

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

    let mut iowait_open_object = MaybeUninit::uninit();
    let mut iowait = sub::iowait::IOWait::new(&mut iowait_open_object).unwrap();
    for i in 0..20 {
        iowait.sample();
        std::thread::sleep(Duration::from_millis(1000));
    }
    // sub::iowait::IOWait::new(&mut open_object);

    // sub::iowait::run();
    // let extractor = Extractor::new(config);
    // extractor.run()?;

    Ok(())
}
