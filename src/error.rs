use libc::c_int;
use std::error::Error;
use std::fmt;

use ffi::nfq_errno;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ErrorReason {
    OpenHandle,
    Bind,
    Unbind,
    CreateQueue,
    SetQueueMode,
    SetQueueMaxlen,
    SetVerdict,
    Unknown
}

pub struct NFQError {
    reason: ErrorReason,
    description: String,
    cause: Option<Box<Error>>,
}

impl fmt::Debug for NFQError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = format!("{:?}: {:?} (cause: {:?})",
                          self.reason, self.description, self.cause);
        formatter.write_str(msg.as_ref())
    }
}

impl fmt::Display for NFQError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = format!("{:?} ({:?})", self.reason, self.description);
        formatter.write_str(msg.as_ref())
    }
}

impl Error for NFQError {
    fn description(&self) -> &str {
        self.description.as_ref()
    }
    fn cause(&self) -> Option<&Error> {
        self.cause.as_ref().map(|c| &**c)
    }
}

pub fn error(reason: ErrorReason, msg: &str, res: Option<c_int>) -> NFQError {
    let errno = nfq_errno;
    let desc = match res {
        Some(r) => format!("{} (errno: {}, res: {})", msg, errno, r),
        None => format!("{}, (errno: {})", msg, errno)
    };
    NFQError {
        reason: reason,
        description: desc,
        cause: None,
    }
}
