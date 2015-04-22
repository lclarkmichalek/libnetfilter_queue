use error::*;
use libc::*;
use std::ptr::null;

use ffi::*;
pub use ffi::nfq_q_handle as QueueHandle;
use message::Message;

pub enum Verdict {
    Drop,
    Accept,
    Stolen,
    Queue,
    Repeat,
    Stop
}

impl Verdict {
    pub fn set_verdict(qh: *mut QueueHandle, packet_id: u32, verdict: Verdict, data_len: u32, buffer: *const c_uchar) -> Result<c_int, Error> {
        let c_verdict = match verdict {
            Verdict::Drop => NF_DROP,
            Verdict::Accept => NF_ACCEPT,
            Verdict::Stolen => NF_STOLEN,
            Verdict::Queue => NF_QUEUE,
            Verdict::Repeat => NF_REPEAT,
            Verdict::Stop => NF_STOP
        };

        match unsafe { nfq_set_verdict(qh, packet_id as uint32_t, c_verdict as uint32_t, data_len as uint32_t, buffer) } {
            -1 => Err(error(Reason::Verdict, "Failed to set verdict", None)),
            r @ _ => Ok(r)
        }
    }
}

pub trait PacketHandler<A> {
    fn handle(&self, hq: *mut QueueHandle, message: Result<&Message, &Error>, data: &mut A) -> i32;
}

pub trait VerdictHandler<A> {
    fn decide(&self, message: &Message, data: &mut A) -> Verdict;
}

#[allow(non_snake_case)]
impl<A, V> PacketHandler<A> for V where V: VerdictHandler<A> {
    fn handle(&self, hq: *mut QueueHandle, message: Result<&Message, &Error>, data: &mut A) -> i32 {
        let NULL: *const c_uchar = null();
        match message {
            Ok(m) => {
                let verdict = self.decide(m, data);
                let _ = Verdict::set_verdict(hq, m.header.id(), verdict, 0, NULL);
            },
            Err(_) => ()
        }
        0
    }
}
