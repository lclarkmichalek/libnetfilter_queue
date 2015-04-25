//! Bindings for [netfilter_queue](http://netfilter.org/projects/libnetfilter_queue/doxygen/index.html)
//!
//! These bindings allow you to have access to the `NFQUEUE`, set in `iptables`,
//! and write your own userspace programs to process these queues.
//#![deny(missing_docs)]

extern crate libc;
#[macro_use]
extern crate lazy_static;

mod ffi;

mod error;
mod util;
mod lock;

pub mod message;
pub mod queue;
pub mod handle;
pub mod verdict;

#[cfg(test)]
mod test;

pub use ffi::nfq_q_handle;
