//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use error::*;
use util::*;
use ffi::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;

pub struct Message<'a> {
    pub raw: *mut nfgenmsg,
    pub ptr: *mut nfq_data,
    pub header: Result<&'a Header, Error>
}

impl<'a> Drop for Message<'a> {
    fn drop(&mut self) {}
}

impl<'a> Message<'a> {
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Message<'a> {
        let header = unsafe {
            let ptr = nfq_get_msg_packet_hdr(ptr);
            if ptr.is_null() {
                Err(error(Reason::GetHeader, "Failed to get header", None))
            } else {
                Ok(as_ref(&ptr).unwrap())
            }
        };
        Message {
            raw: raw,
            ptr: ptr,
            header: header
        }
    }
}
