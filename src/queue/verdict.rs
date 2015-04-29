//! Verdict and packet handling for NFQueue packets.
use libc::*;
use error::*;
use ffi::*;
use ffi::nfq_q_handle as QueueHandle;

/// Packet verdict used to notify netfilter of a packet's destiny
pub enum Verdict {
    /// Drop the packet and release it's memory
    Drop,
    /// Accept the packet from this chain
    Accept,
    /// Drop the packet but do not release it's memory
    ///
    /// This is used when userspace (this program) will finish handling the packet.
    Stolen,
    /// Queue the packet into the given queue_number
    Queue(u16),
    /// Call this hook again for this packet
    ///
    /// The hook is stored in the packet header.
    Repeat,
    /// Similar to Accept
    Stop
}

impl Verdict {
    // Encodes the enum into a u32 suitible for use by nfq_set_verdict
    fn as_u32(&self) -> u32 {
        match *self {
            Verdict::Drop => NF_DROP,
            Verdict::Accept => NF_ACCEPT,
            Verdict::Stolen => NF_STOLEN,
            Verdict::Queue(t) => NF_QUEUE | (t as u32) << 16,
            Verdict::Repeat => NF_REPEAT,
            Verdict::Stop => NF_STOP,
        }
    }

    /// Set the verdict for a packet
    ///
    /// The `packet_id` must be used to identify a packet, fetched from `packet.header.id()`.
    /// For simpler cases, pass `data_len = 0` and `buffer = std::ptr::null()`.
    pub fn set_verdict(qh: *mut QueueHandle, packet_id: u32, verdict: Verdict, data_len: u32, buffer: *const c_uchar) -> Result<c_int, Error> {
	let c_verdict = verdict.as_u32() as uint32_t;

        match unsafe { nfq_set_verdict(qh, packet_id as uint32_t, c_verdict as uint32_t, data_len as uint32_t, buffer) } {
            -1 => Err(error(Reason::SetVerdict, "Failed to set verdict", None)),
            r @ _ => Ok(r)
        }
    }
}
