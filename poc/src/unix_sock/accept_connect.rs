use nix::{
    sys::wait,
    unistd::{fork, ForkResult},
};
use std::io::prelude::*;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

const MAX_CONNECTIONS: usize = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sock_path = "./unix.sock";

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // child sends data
            println!("{} - In child", std::process::id());
            let mut input = String::new();

            for _ in 0..MAX_CONNECTIONS {
                std::thread::sleep(Duration::from_millis(1500));
                let mut sock = UnixStream::connect(sock_path)?;
                loop {
                    input.truncate(0);
                    std::io::stdin().read_line(&mut input)?;
                    sock.write(input.trim().as_bytes()).unwrap();

                    if input == "exit\n" {
                        break;
                    }
                }
            }
        }
        Ok(ForkResult::Parent { child }) => {
            // parent receives data
            println!("{} - In parent {}", std::process::id(), child);
            let listener = UnixListener::bind(sock_path)?;
            let mut buf: [u8; 256] = [0; 256];
            for i in 0..MAX_CONNECTIONS {
                println!("Server conn {i}");
                let (mut sock, _) = listener.accept()?;
                loop {
                    if let Ok(bytes) = sock.read(&mut buf) {
                        if bytes == 0 {
                            continue;
                        }
                        let contents = String::from_utf8(buf[..bytes].into()).unwrap();
                        if contents == "exit" {
                            break;
                        } else {
                            println!("received: {}", contents);
                        }
                    } else {
                        sock = listener.accept()?.0;
                    }
                }
            }
            wait::waitpid(child, None)?;
            std::fs::remove_file(sock_path).unwrap();
        }
        _ => {}
    }
    Ok(())
}
