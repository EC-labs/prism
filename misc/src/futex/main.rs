use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

fn main() {
    let counter = Arc::new(Mutex::new(0));
    let mut handlers = Vec::new();
    for thread_id in 0..2 {
        let counter = counter.clone();
        handlers.push(thread::spawn(move || {
            println!("Starting thread {:?}", thread_id);
            for _ in 0..20 {
                let mut counter = counter.lock().unwrap();
                *counter += 1;
                thread::sleep(Duration::from_millis(500));
                println!("Thread_id: {:?}\tCounter: {:?}", thread_id, counter);
                drop(counter);
                thread::sleep(Duration::from_millis(10));
            }
        }));
    }
    handlers.into_iter().for_each(|handler| {
        handler.join();
    });

    let mut handlers = Vec::new();
    for thread_id in 0..2 {
        let counter = counter.clone();
        handlers.push(thread::spawn(move || {
            println!("Starting thread {:?}", thread_id);
            for _ in 0..1000 {
                let mut counter = counter.lock().unwrap();
                *counter += 1;
                thread::sleep(Duration::from_millis(500));
                println!("Thread_id: {:?}\tCounter: {:?}", thread_id, counter);
                drop(counter);
                thread::sleep(Duration::from_millis(10));
            }
        }));
    }
    handlers.into_iter().for_each(|handler| {
        handler.join();
    });
}
