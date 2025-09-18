use hdrhistogram::Histogram;
use std::{collections::BTreeMap, io};

pub struct PercentileResponseTime {}

impl PercentileResponseTime {
    pub fn run(time_factor: u64, percentile: f64) {
        let mut start_map = BTreeMap::new();
        let mut end_map = BTreeMap::new();
        let time_factor = time_factor;
        let mut buf = String::new();

        println!("Reading input");
        for (i, line) in io::stdin().lines().enumerate() {
            let line = match line {
                Ok(c) => {
                    if c.len() == 0 {
                        break;
                    } else {
                        c
                    }
                }
                Err(_) => break,
            };

            if i % 500_000 == 0 {
                println!("Read {:?} lines", i)
            }

            let line = line.trim();
            let mut elements = line.split(",");

            let start: u64 = elements.next().unwrap().parse().unwrap();
            let end: u64 = elements.next().unwrap().parse().unwrap();
            let delay: u64 = elements.next().unwrap().parse().unwrap();

            start_map.insert(start, (start, end, delay));
            end_map.insert(end, (start, end, delay));

            buf.truncate(0);
        }

        let (start_epoch, end_epoch) = (
            start_map.first_key_value().unwrap().0,
            end_map.last_key_value().unwrap().0,
        );

        for current_epoch in (*start_epoch..=*end_epoch).step_by(time_factor as usize) {
            let combined_set = start_map
                .range(..=current_epoch)
                .map(|(_, v)| v)
                .filter(|v| v.1 > current_epoch - time_factor);

            let mut hist = Histogram::<u64>::new_with_bounds(1, 1000 * 1000 * 60, 2).unwrap();
            for (_, _, rt) in combined_set {
                hist.record(*rt).unwrap();
            }

            let qv = hist.value_at_quantile(percentile);
            println!("{:?},{:?}", current_epoch / time_factor, qv);
        }
    }
}
