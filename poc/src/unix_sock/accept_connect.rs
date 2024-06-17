use nix::{
    sys::wait,
    unistd::{fork, ForkResult},
};
use std::io::prelude::*;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sock_path = "./unix.sock";
    let listener = UnixListener::bind(sock_path)?;
    let iters = 2;

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // child sends data
            println!("{} - In child", std::process::id());
            let mut input = String::new();
            loop {
                input.clear();
                std::io::stdin().read_line(&mut input)?;
                if input == "exit\n" {
                    let mut sock = UnixStream::connect(sock_path)?;
                    let _ = sock.write("exit".as_bytes());
                    std::process::exit(0);
                }
                let mut sock = UnixStream::connect(sock_path)?;
                for i in 0..iters {
                    thread::sleep(Duration::from_millis(1000));
                    let _ = sock.write(format!("Iteration {}", i).as_bytes());
                }
            }
        }
        Ok(ForkResult::Parent { child }) => {
            // parent receives data
            println!("{} - In parent {}", std::process::id(), child);
            let (mut sock, _) = listener.accept()?;
            let mut buf: [u8; 256] = [0; 256];
            loop {
                if let Ok(bytes) = sock.read(&mut buf) {
                    if bytes == 0 {
                        sock = listener.accept()?.0;
                        continue;
                    }
                    let contents = String::from_utf8(buf[..bytes].into()).unwrap();
                    if contents == "exit" {
                        break;
                    } else {
                        println!("{}", contents);
                    }
                } else {
                    sock = listener.accept()?.0;
                }
            }
            wait::waitpid(child, None)?;
        }
        _ => {}
    }
    std::fs::remove_file(sock_path).unwrap();
    Ok(())
}
