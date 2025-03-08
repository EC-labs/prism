use libc::{self, c_int};
use nix::unistd::ForkResult;
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::prelude::*;
use std::process;
use std::time::Duration;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, mut writer) = pipe();
    let mut buf: [u8; 256] = [0; 256];
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Child) => {
            println!("child: {}", unsafe { libc::getpid() });

            for i in 0..200 {
                writer.write(format!("hello {i}").as_bytes()).unwrap();
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
        Ok(ForkResult::Parent { .. }) => {
            println!("parent: {}", unsafe { libc::getpid() });
            drop(writer);

            loop {
                let Ok(bytes) = reader.read(&mut buf) else {
                    println!("Error");
                    break;
                };

                if bytes == 0 {
                    println!("No bytes");
                    break;
                }

                let data = String::from_utf8(buf[..bytes].into()).unwrap();
                println!("{}", data);
            }
        }
        _ => {}
    }

    Ok(())
}
