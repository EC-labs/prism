use std::time::Duration;

fn main() {
    let mut handles = Vec::new();
    for i in 0..20 {
        handles.push(std::thread::spawn(move || {
            println!("thread {}", i);
            for j in 0..5 {
                println!("thread {} iter {}", i, j);
                std::thread::sleep(Duration::from_secs(5));
            }
        }));
        std::thread::sleep(Duration::from_secs(5));
    }

    for handle in handles {
        handle.join();
    }
}
