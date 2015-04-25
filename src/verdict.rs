use libc::*;
use ffi::*;

use error::*;

pub enum Verdict {
    Drop,
    Accept,
    Stolen,
    Queue(u16),
    Repeat,
    Stop
}

impl Verdict {
    // Encodes the enum into a u32 suitible for use by nfq_set_verdict
    fn nfq_verdict(&self) -> u32 {
        match *self {
            Verdict::Drop => NF_DROP,
            Verdict::Accept => NF_ACCEPT,
            Verdict::Stolen => NF_STOLEN,
            Verdict::Queue(t) => NF_QUEUE | (t as u32) << 16,
            Verdict::Repeat => NF_REPEAT,
            Verdict::Stop => NF_STOP,
        }
    }

    pub fn set_verdict(qh: *mut nfq_q_handle,
                       packet_id: u32,
                       verdict: Verdict,
                       data_len: u32,
                       buffer: *const c_uchar) -> Result<c_int, NFQError> {
        let res = unsafe {
            nfq_set_verdict(qh,
                            packet_id as uint32_t,
                            verdict.nfq_verdict() as uint32_t,
                            data_len as uint32_t,
                            buffer)
        };

        if res != 0 {
            Err(error(ErrorReason::SetVerdict, "Failed to set verdict", Some(res)))
        } else {
            Ok(res)
        }
    }
}
