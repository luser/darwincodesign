extern crate darwincodesign;
extern crate env_logger;

use std::env;

fn main() {
    env_logger::init().unwrap();
    let path = env::args_os().nth(1).expect("Missing path!");
    darwincodesign::dump_signature(path).unwrap();
}
