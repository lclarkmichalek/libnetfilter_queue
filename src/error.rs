use libc::c_int;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ErrorReason {
    OpenHandle,
    Bind,
    Unbind,
    CreateQueue,
    SetQueueMode,
    SetQueueMaxlen,
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

impl<E: Error + 'static> From<E> for NFQError {
    fn from(err: E) -> NFQError {
        NFQError {
            reason: ErrorReason::Unknown,
            description: err.description().to_string(),
            cause: Some(Box::new(err)),
        }
    }
}

pub fn error(reason: ErrorReason, msg: &str, res: Option<c_int>) -> NFQError {
    let errno = unsafe { nfq_errno };
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

#[link(name="netfilter_queue")]
extern {
    static mut nfq_errno: c_int;
}
