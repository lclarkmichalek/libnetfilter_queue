pub use libc::*;
use std::sync::{StaticMutex, MUTEX_INIT};
use std::error::Error;

pub static NFQ_LOCK: StaticMutex = MUTEX_INIT;

pub struct NFQError(pub String);

impl<E: Error> From<E> for NFQError {
    fn from(err: E) -> NFQError {
        NFQError(err.description().to_string())
    }
}

pub fn error(msg: &str) -> NFQError {
    let errno = unsafe { nfq_errno };
    NFQError(format!("{} (errno: {})", msg, errno))
}

#[link(name="netfilter_queue")]
extern {
    static mut nfq_errno: c_int;
}
