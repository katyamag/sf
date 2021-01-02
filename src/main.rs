mod aes;
mod error;

use structopt::StructOpt;
use std::path::PathBuf;
use aes::{OpenSSLAesCommand, AES};

#[derive(StructOpt)]
struct Opt {
    /// Action
    action: String,

    /// Key
    key: String,

    /// Input dir
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// Output dir
    #[structopt(short, long, parse(from_os_str))]
    output: PathBuf,
}

fn main() {
    let opt = Opt::from_args();

    let cryptographic: OpenSSLAesCommand = AES::new(
        &opt.key,
        &opt.input,
        &opt.output,
        0,
    );

    match cryptographic.encrypt() {
        Ok(()) => println!("Done"),
        Err(e) => println!("Error: {}", e.message),
    }
}
