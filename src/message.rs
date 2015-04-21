//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use util::*;
use ffi::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;

pub struct Message<'a> {
    pub raw: *mut nfgenmsg,
    pub ptr: *mut nfq_data,
    pub header: &'a Header
}

impl<'a> Drop for Message<'a> {
    fn drop(&mut self) {}
}

impl<'a> Message<'a> {
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Message<'a> {
        let header = unsafe {
            let ptr = nfq_get_msg_packet_hdr(ptr);
            as_ref(&ptr).unwrap()
        };
        Message {
            raw: raw,
            ptr: ptr,
            header: header
        }
    }
}

pub mod verdict {
    use libc::*;
    use ffi::*;

    pub enum Verdict {
        Drop,
        Accept,
        Stolen,
        Queue,
        Repeat,
        Stop
    }

    impl Verdict {

        pub fn set_verdict(qh: *mut nfq_q_handle, packet_id: u32, verdict: Verdict, data_len: u32, buffer: *const c_uchar) -> Result<c_int, ()> {
            let c_verdict = match verdict {
                Verdict::Drop => NF_DROP,
                Verdict::Accept => NF_ACCEPT,
                Verdict::Stolen => NF_STOLEN,
                Verdict::Queue => NF_QUEUE,
                Verdict::Repeat => NF_REPEAT,
                Verdict::Stop => NF_STOP
            };

            match unsafe { nfq_set_verdict(qh, packet_id as uint32_t, c_verdict as uint32_t, data_len as uint32_t, buffer) } {
                -1 => Err(()),
                r @ _ => Ok(r)
            }
        }
    }
}
