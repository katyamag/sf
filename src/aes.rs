use std::path::{PathBuf, Path};
use std::process::Command;
use std::io::{self, Write};
use std::thread;
use std::sync::{Mutex, Arc};

use uuid::Uuid;
use pbr::ProgressBar;
use regex::Regex;

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

fn get_file_list(input_dir: &PathBuf, output_dir: &PathBuf, file_type: &str) -> Result<Vec<std::string::String>, SfError> {
    let list = std::fs::read_dir(input_dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|e| e.display().to_string().contains(file_type))
        .map(|f| f.file_name().expect("failed to get filename")
            .to_str().expect("failed to convert to str")
            .split(".")
            .collect::<Vec<&str>>()[0]
            .to_string())
        .collect::<Vec<_>>();

    println!("{:?}", list);

    // TODO
    // for f in &list {
    //     let filename = f.file_name().expect("failed to get filename")
    //         .to_str().expect("failed to convert to str")
    //         .split(".")
    //         .collect::<Vec<&str>>()[0]
    //         .to_string();

    //     let check_file_type = match file_type {
    //         ".enc" => ".mp4",
    //         ".mp4" => ".enc"
    //     };

    //     if Path::new(&format!("{}/{}{}", output_dir.display(), filename, check_file_type)).exists() {
    //         continue
    //     }

    //     println!("{}", filename);
    // }

    Ok(list)
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
        let file_list = get_file_list(self.input, self.output, ".mp4").expect("failed to get file list");

        let mut pb = Arc::new(Mutex::new(ProgressBar::new(file_list.len() as u64)));
        let mfile_list = Arc::new(Mutex::new(file_list));

        let mut thread_handlers = vec![];

        for _ in 0..self.threads {
            let file_list = Arc::clone(&mfile_list);
            let tpb = Arc::clone(&mut pb);

            let input_dir = self.input.clone();
            let output_dir = self.output.clone();
            let key = self.key.to_owned();

            thread_handlers.push(thread::spawn(move || -> SfResult {
                loop {
                    if let Ok(mut list) = file_list.lock() {
                        if list.len() == 0 {
                            return Ok(())
                        }

                        if let Some(target_file) = list.pop() {
                            drop(list);

                            let re = Regex::new(
                                r"[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}")?;

                            let mut output_filename = String::new();

                            if re.is_match(&target_file) {
                                output_filename = target_file.clone();
                            } else {
                                loop {
                                    let uuid = Uuid::new_v4();
                                    output_filename = uuid.to_hyphenated().to_string();
                                    if !Path::new(&output_filename).exists() {
                                        break
                                    }
                                }
                            }

                            let cmd_result = Command::new("openssl")
                                .args(&[
                                      "aes-256-cbc",
                                      "-a",
                                      "-salt",
                                      "-pbkdf2",
                                      "-in",
                                      &format!("{}/{}.mp4", input_dir.display(), target_file),
                                      "-out",
                                      &format!("{}/{}.enc", output_dir.display(), output_filename),
                                      "-k",
                                      &key,
                                ])
                                .output()?;

                            if cmd_result.status.success() {
                                tpb.lock().expect("failed to get progress bar").inc();
                                tpb.lock().expect("failed to get progress bar").tick();
                            } else {
                                // TODO: collect error
                                println!("failed to encrypt {}/{}", input_dir.display(), target_file);
                                io::stderr().write_all(&cmd_result.stderr)?;
                                println!("");
                            }
                        }
                    }
                }
            }));
        }

        for handler in thread_handlers {
            // TODO
            handler.join().unwrap()?;
        }

        pb.lock().expect("failed to get progress bar").finish_println("done");

        Ok(())
    }

    fn decrypt(&self) -> SfResult {
        let file_list = get_file_list(self.input, self.output, ".enc").expect("failed to get file list");
        let mut pb = Arc::new(Mutex::new(ProgressBar::new(file_list.len() as u64)));
        let mfile_list = Arc::new(Mutex::new(file_list));
        let mut thread_handlers = vec![];

        for _ in 0..self.threads {
            let file_list = Arc::clone(&mfile_list);
            let tpb = Arc::clone(&mut pb);

            let input_dir = self.input.clone();
            let output_dir = self.output.clone();
            let key = self.key.to_owned();

            thread_handlers.push(thread::spawn(move || -> SfResult {
                loop {
                    if let Ok(mut list) = file_list.lock() {
                        if list.len() == 0 {
                            return Ok(())
                        }

                        if let Some(target_file) = list.pop() {
                            drop(list);

                            let cmd_result = Command::new("openssl")
                                .args(&[
                                      "aes-256-cbc",
                                      "-d",
                                      "-a",
                                      "-pbkdf2",
                                      "-in",
                                      &format!("{}/{}.enc", input_dir.display(), target_file),
                                      "-out",
                                      &format!("{}/{}.mp4", output_dir.display(), target_file),
                                      "-k",
                                      &key,
                                ])
                                .output()?;

                            if cmd_result.status.success() {
                                tpb.lock().expect("failed to get progress bar").inc();
                                tpb.lock().expect("failed to get progress bar").tick();
                            } else {
                                // TODO: collect error
                                println!("failed to encrypt {}/{}.enc", input_dir.display(), target_file);
                                io::stderr().write_all(&cmd_result.stderr)?;
                                println!("");
                            }
                        }
                    }
                }
            }));
        }

        for handler in thread_handlers {
            // TODO
            handler.join().unwrap()?;
        }

        Ok(())
    }
}
