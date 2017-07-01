extern crate clap;
extern crate darwincodesign;
extern crate env_logger;

use clap::{Arg, App, SubCommand};
use darwincodesign::SignatureValidity;

fn main() {
    env_logger::init().unwrap();
        let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand(SubCommand::with_name("print")
                    .about("print signature information")
                    .arg(Arg::with_name("INPUT")
                         .help("The input file to parse")
                         .required(true)
                         .index(1)))
        .subcommand(SubCommand::with_name("extract")
                    .about("extract PKCS#7 signature to OUTPUT")
                    .arg(Arg::with_name("INPUT")
                         .help("The input file to parse")
                         .required(true))
                    .arg(Arg::with_name("OUTPUT")
                         .help("Where to write signature data")
                         .required(true)))
        .subcommand(SubCommand::with_name("verify")
                    .about("Verify signature in INPUT")
                    .arg(Arg::with_name("INPUT")
                         .help("The input file to parse")
                         .required(true)))
        .get_matches();
    if let Some(matches) = matches.subcommand_matches("print") {
        let input_path = matches.value_of_os("INPUT").unwrap();
        darwincodesign::dump_signature(input_path).unwrap();
    }
    if let Some(matches) = matches.subcommand_matches("extract") {
        let input_path = matches.value_of_os("INPUT").expect("Missing INPUT");
        let output_path = matches.value_of_os("OUTPUT").expect("Missing OUTPUT");
        darwincodesign::extract_signature(input_path, output_path).unwrap();
    }
    if let Some(matches) = matches.subcommand_matches("verify") {
        let input_path = matches.value_of_os("INPUT").unwrap();
        println!("Signature is {}", match darwincodesign::verify_signature(input_path).unwrap() {
            SignatureValidity::Valid => "valid",
            SignatureValidity::Invalid => "not valid",
        });
    }
}
