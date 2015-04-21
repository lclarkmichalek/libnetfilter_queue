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
            let ptr = nfq_get_msg_packet_hdr(self.ptr);
            as_ref(&ptr).unwrap()
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

    pub fn set_verdict(qh: *mut nfq_q_handle, packet_id: uint32_t, verdict: Verdict, data_len: uint32_t, buffer: *mut c_uchar) -> Result<(),()> {
        let c_verdict = match verdict {
            Verdict::Drop => NF_DROP,
            Verdict::Accept => NF_ACCEPT,
            Verdict::Stolen => NF_STOLEN,
            Verdict::Queue => NF_QUEUE,
            Verdict::Repeat => NF_REPEAT,
            Verdict::Stop => NF_STOP
        };

        match unsafe { nfq_set_verdict(qh, packet_id, c_verdict as uint32_t, data_len, buffer) } {
            -1 => Err(()),
            _ => Ok(())
        }
    }
}
