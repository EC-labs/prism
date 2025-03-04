use std::mem::MaybeUninit;
use std::time::Duration;

use collector::cmdline;
use collector::configure::Config;
use collector::extract::Extractor;
use collector::sub;
use duckdb::Connection;

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

    let path = "./data/prism-db.db3";
    let conn = Connection::open(&path)?;

    let mut iowait_open_object = MaybeUninit::uninit();
    let mut iowait = sub::iowait::IOWait::new(&mut iowait_open_object, conn.try_clone()?).unwrap();
    for i in 0..20 {
        iowait.sample()?;
        std::thread::sleep(Duration::from_millis(1000));
    }
    // let extractor = Extractor::new(config);
    // extractor.run()?;

    Ok(())
}
