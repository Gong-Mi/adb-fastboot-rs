
use std::fs;
use adb_protocol::crypto::key::{load_private_key_from_pem, AdbAuth};

fn main() {
    let pem = fs::read_to_string("/data/data/com.termux/files/home/.android/adbkey").unwrap();
    let private_key = load_private_key_from_pem(&pem).unwrap();
    let auth = AdbAuth::new(private_key, "u0_a717@localhost");
    let payload = auth.build_rsakey_payload().unwrap();
    let payload_str = String::from_utf8_lossy(&payload);
    println!("OUR KEY:");
    println!("{}", payload_str);
    println!("END");
    println!("Length: {}", payload_str.len());
}
