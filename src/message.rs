//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use util::*;
use ffi::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;

pub struct Message {
    pub raw: *mut nfgenmsg,
    pub ptr: *mut nfq_data
}

impl Drop for Message {
    fn drop(&mut self) {}
}

impl Message {
    pub fn header(&mut self) -> &Header {
        unsafe {
            let ptr = nf_get_msg_packet_hdr(self.ptr);
            as_ref(&ptr).unwrap()
        }
    }
}
