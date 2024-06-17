use std::io::prelude::*;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sock1, sock2) = match UnixStream::pair() {
        Ok((sock1, sock2)) => (sock1, sock2),
        Err(e) => {
            println!("Couldn't create a pair of sockets: {e:?}");
            return Err(e.into());
        }
    };
    let iters = 50;

    let mut handles = Vec::new();
    handles.push(thread::spawn(move || {
        let mut sock = sock1;
        for _ in 0..iters {
            thread::sleep(Duration::from_millis(1000));
            let _ = sock.write("What is your name?".as_bytes());
        }
    }));
    handles.push(thread::spawn(move || {
        let mut sock = sock2;
        for _ in 0..iters {
            thread::sleep(Duration::from_millis(1000));
            let mut buf: [u8; 256] = [0; 256];
            let _ = sock.read(&mut buf);
            println!("{}", String::from_utf8(buf.into()).unwrap())
        }
    }));

    handles.into_iter().for_each(|handle| {
        handle.join().unwrap();
    });

    Ok(())
}
