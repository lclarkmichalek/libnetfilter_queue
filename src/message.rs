//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use std::num::Int;
use util::*;
use ffi::*;

pub struct Message {
    pub raw: *mut nfgenmsg,
    pub ptr: *mut nfq_data,
    pub header: Header
}

pub struct Header {
    pub id: u32,
    pub protocol: u16,
    pub hook: u8
}

impl Drop for Message {
    fn drop(&mut self) {}
}

impl Message {
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Message {
        let header = unsafe {
            let ptr = nfq_get_msg_packet_hdr(ptr);
            as_ref(&ptr).unwrap()
        };
        Message {
            raw: raw,
            ptr: ptr,
            header: Header {
                id: Int::from_be(header.packet_id),
                protocol: Int::from_be(header.hw_protocol),
                hook: Int::from_be(header.hook)
            }
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
