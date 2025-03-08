use std::io::Read;

fn main() {
    println!("{}", std::process::id());
    let mut stdin = std::io::stdin();
    let mut buf = [0; 256];
    loop {
        let bytes = stdin.read(&mut buf).unwrap();
        let res = String::from_utf8(buf[..bytes].into()).unwrap();
        if res == "\n" {
            break;
        }
        println!("{:?}", res);
    }
}
