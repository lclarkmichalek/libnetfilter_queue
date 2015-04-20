extern crate libc;
#[macro_use]
extern crate lazy_static;

mod ffi;

mod error;
mod lock;

pub mod handle;
//pub mod queue;

#[cfg(test)]
mod test;
