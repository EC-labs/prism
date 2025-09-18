use rand::Rng;
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

fn main() {
    let mut conn = TcpStream::connect("::1:8080").unwrap();
    let mut read_buf: [u8; 16] = [0; 16];
    loop {
        conn.write("request".as_bytes()).unwrap();
        let Ok(len) = conn.read(&mut read_buf) else {
            break;
        };
        println!("{}", String::from_utf8(read_buf[..len].into()).unwrap());
        let millis = rand::thread_rng().gen_range(0..5000);
        println!("{:?}", millis);
        std::thread::sleep(Duration::from_millis(millis));
    }
}
