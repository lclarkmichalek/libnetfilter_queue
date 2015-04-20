//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use ffi::*;

pub struct Message {
    pub raw: *mut nfgenmsg,
    pub ptr: *mut nfq_data
}

impl Drop for Message {
    fn drop(&mut self) {}
}

/*
impl Message {
    pub fn header(&self) -> {
*/
