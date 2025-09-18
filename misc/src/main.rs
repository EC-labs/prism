use std::fs::File;
use std::io::Read;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

struct IOWaitProgram<R: Read> {
    reader: R,
}

impl IOWaitProgram<File> {
    pub fn new() -> Self {
        let f = File::create("/tmp/test").unwrap();
        Self { reader: f }
    }
}

impl<R: Read> IOWaitProgram<R> {
    pub fn custom_reader(reader: R) -> Self {
        Self { reader }
    }
}

fn main() {
    let reader = "testing";
    let mut p1 = IOWaitProgram::custom_reader(reader.as_bytes());
    let p2 = IOWaitProgram::new();
    let mut buffer: [u8; 5] = [0; 5];
    loop {
        let bytes = p1.reader.read(&mut buffer);
        println!("{:?}", bytes);
        if let Ok(0) = bytes {
            break;
        }
    }
}
