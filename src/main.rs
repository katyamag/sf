mod aes;
mod error;

use structopt::StructOpt;
use std::path::PathBuf;
use aes::{OpenSSLAesCommand, AES};
use error::{SfResult, SfError};

#[derive(StructOpt)]
struct Opt {
    /// Action
    action: String,

    /// Key
    key: String,

    /// The number of thread
    threads: i32,

    /// Input dir
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// Output dir
    #[structopt(short, long, parse(from_os_str), required_if("out", "dir"))]
    output: PathBuf,
}

fn main() -> SfResult {
    let opt = Opt::from_args();

    if !opt.input.is_dir() || !opt.output.is_dir() {
        return Err(SfError::new("input or output is not directory".to_string()))
    }

    if opt.key == "" {
        return Err(SfError::new("key is empty".to_string()))
    }

    let cryptographic: OpenSSLAesCommand = AES::new(
        &opt.key,
        &opt.input,
        &opt.output,
        opt.threads,
    );

    match opt.action.as_str() {
        "encrypt" => cryptographic.encrypt()?,
        "decrypt" => cryptographic.decrypt()?,
        _ => return Err(SfError::new(format!("Not defined action: {}", opt.action)))
    }

    Ok(())
}
