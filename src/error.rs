use std::fmt::{Debug, Formatter};
use std::fmt::Error as FmtError;
use std::io::Error as IoError;
use regex::Error as RegexError;

// #[derive(PartialEq)]
pub struct SfError {
    pub message: String,
    pub stderr: Option<String>,
    pub stdout: Option<String>,
}

pub type SfResult = Result<(), SfError>;

impl SfError {
    pub fn new(message: String) -> SfError {
        SfError {
            message: message,
            stderr: None,
            stdout: None,
        }
    }
}

impl Debug for SfError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{:?}", self.message)
    }
}

impl From<IoError> for SfError {
    fn from(err: IoError) -> Self {
        SfError::new(format!("{}", err))
    }
}

impl From<RegexError> for SfError {
    fn from(err: RegexError) -> Self {
        SfError::new(format!("{}", err))
    }
}
