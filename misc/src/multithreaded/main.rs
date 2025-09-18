use std::time::{Duration, SystemTime};

fn main() {
    let mut handles = Vec::new();
    for i in 0..20 {
        handles.push(std::thread::spawn(move || {
            println!("thread {}", i);
            let start = SystemTime::now();
            for j in 0..5 {
                println!("thread {} iter {}", i, j);
                std::thread::sleep(Duration::from_secs(1));
            }
            println!(
                "thread[{i}] elapsed[{}]",
                start.elapsed().unwrap().as_millis()
            );
        }));
        std::thread::sleep(Duration::from_secs(1));
    }

    for handle in handles {
        handle.join();
    }
}
