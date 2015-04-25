//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use util::*;
use ffi::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;

pub struct Message {
    pub raw: *mut nfgenmsg,
    pub ptr: *mut nfq_data,
}

impl Message {
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Message {
        Message {
            raw: raw,
            ptr: ptr,
        }
    }

    pub fn header(&self) -> &Header {
        unsafe {
            let ptr = nfq_get_msg_packet_hdr(self.ptr);
            as_ref(&ptr).unwrap()
        }
    }
}
