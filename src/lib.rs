#![feature(std_misc)]
#![feature(core)]

extern crate libc;

mod raw;

mod error;
mod lock;

pub mod handle;
pub mod queue;

#[cfg(test)]
mod test_handle;
