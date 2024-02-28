use std::io::{prelude::*, SeekFrom};
use std::thread;
use std::time::Duration;
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

fn main() {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .custom_flags(libc::O_SYNC)
        .open("test")
        .expect("Can't open file");

    for i in 0..10_000_000 {
        file.write_all(format!("This is write {i}\n").as_bytes())
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        // thread::sleep(Duration::from_millis(10))
    }
}
