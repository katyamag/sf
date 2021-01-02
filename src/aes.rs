use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::{self, Write};

use super::error::{SfError, SfResult};

pub struct OpenSSLAesCommand<'a> {
    key: &'a str,
    input: &'a PathBuf,
    output: &'a PathBuf,
    threads: i32,
}

pub trait AES<'a> {
    fn new(key: &'a str, input: &'a PathBuf, output: &'a PathBuf, threads: i32) -> Self;
    fn encrypt(&self) -> SfResult;
    fn decrypt(&self) -> SfResult;
}

impl<'a> AES<'a> for OpenSSLAesCommand<'a> {
    fn new(key: &'a str, input: &'a PathBuf, output: &'a PathBuf, threads: i32) -> OpenSSLAesCommand<'a> {
        OpenSSLAesCommand {
            key: key,
            input: input,
            output: output,
            threads: threads,
        }
    }

    fn encrypt(&self) -> SfResult {
        let output = Command::new("openssl")
            .args(&[
                  "aes-256-cbc",
                  "-a",
                  "-salt",
                  "-pbkdf2",
                  "-in",
                  &self.input.display().to_string(),
                  "-out",
                  &self.output.display().to_string(),
                  "-k",
                  &self.key,
                  // &format!("-in {}", self.input.display().to_string()),
                  // &format!("-out {}", self.output.display().to_string()),
                  // &format!("-k {}", self.key),
            ])
        .output()?;

        if output.status.success() {
            io::stdout().write_all(&output.stdout)?;
            Ok(())
        } else {
            io::stderr().write_all(&output.stderr)?;
            Err(SfError::new("failed to encrypt".to_string()))
        }
    }

    fn decrypt(&self) -> SfResult {
        let output = Command::new("openssl")
            .args(&[
                  "aes-256-cbc",
                  "-d",
                  "-a",
                  "-pbkdf2",
                  &self.input.display().to_string(),
                  "-out",
                  &self.output.display().to_string(),
                  "-k",
                  &self.key,
                  // &format!("-in {}", self.input.display().to_string()),
                  // &format!("-out {}", self.output.display().to_string()),
                  // &format!("-k {}", self.key),
            ])
        .output()?;

        if output.status.success() {
            io::stdout().write_all(&output.stdout)?;
            Ok(())
        } else {
            io::stderr().write_all(&output.stderr)?;
            Err(SfError::new("failed to decrypt".to_string()))
        }
    }
}
