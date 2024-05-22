use libc::{self, c_int};
use std::fs::File;
use std::io::{self, prelude::*, ErrorKind};
use std::os::unix::prelude::*;
use std::process::{self, Command};
use std::thread;
use std::time::Duration;

use tokio::io::AsyncReadExt;

fn pipe() -> (File, File) {
    let mut fds: [c_int; 2] = [0; 2];
    let res = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if res != 0 {
        process::exit(1);
    }
    let reader = unsafe { File::from_raw_fd(fds[0]) };
    let writer = unsafe { File::from_raw_fd(fds[1]) };
    (reader, writer)
}

fn fcntl_setfd(file: &mut File, flags: c_int) {
    let res = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags) };
    println!("fcntl result {:?}", res);
    if res != 0 {
        println!("res {:?}", res);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, writer) = pipe();
    fcntl_setfd(&mut reader, libc::O_NONBLOCK | libc::O_RDONLY);

    let mut child = Command::new("bpftrace")
        .args(["../thread-sync/bpf/futex_wait.bt", "1"])
        .stdout(writer)
        .spawn()?;

    let mut buf: [u8; 256] = [0; 256];
    loop {
        let bytes = reader.read(&mut buf);
        if let Err(error) = bytes {
            let kind = error.kind();
            if kind == ErrorKind::WouldBlock {
                println!("Would Block");
                std::thread::sleep(Duration::from_millis(1000));
                continue;
            }
            break;
        }

        let bytes = bytes.unwrap();
        if bytes == 0 {
            break;
        }

        let data = String::from_utf8(buf[..bytes].into()).unwrap();
        println!("{:?}", data);
    }

    child.kill()?;
    Ok(())
}
