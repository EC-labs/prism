use std::io::Read;

fn main() {
    let mut stdin = std::io::stdin();
    let mut buf = [0; 256];
    let bytes = stdin.read(&mut buf).unwrap();
    let res = String::from_utf8(buf[..bytes].into()).unwrap();
    println!("{:?}", res);
}
