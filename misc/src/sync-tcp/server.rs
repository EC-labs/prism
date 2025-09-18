use std::{
    io::{Read, Write},
    net::TcpListener,
};

fn main() {
    let server = TcpListener::bind("::1:8080").unwrap();
    print!("press [enter] key to accept connections");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut String::new()).unwrap();
    println!("accepting connections");
    let (mut conn, addr) = server.accept().unwrap();
    let mut read_buf: [u8; 16] = [0; 16];
    loop {
        let Ok(len) = conn.read(&mut read_buf) else {
            break;
        };
        println!("{}", String::from_utf8(read_buf[..len].into()).unwrap());
        conn.write("response".as_bytes()).unwrap();
    }
    println!("{:?}", addr);
}
