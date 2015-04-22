//! Verdict and packet handling for NFQueue packets.
use error::*;
use libc::*;
use std::ptr::null;

use ffi::*;
pub use ffi::nfq_q_handle as QueueHandle;
use message::Message;

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
    /// Queue the packet
    Queue,
    /// Call this hook again for this packet
    ///
    /// The hook is stored in the packet header.
    Repeat,
    /// Similar to Accept
    Stop
}

impl Verdict {
    /// Set the verdict for a packet
    ///
    /// The `packet_id` must be used to identify a packet, fetched from `packet.header.id()`.
    /// For simpler cases, pass `data_len = 0` and `buffer = std::ptr::null()`.
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

/// Invoked to handle packets from the queue
pub trait PacketHandler<A> {
    /// Handle a packet from the queue
    ///
    /// `Verdict`s must be set using the `set_verdict` fn.
    fn handle(&self, hq: *mut QueueHandle, message: Result<&Message, &Error>, data: &mut A) -> i32;
}

/// An abstraction over `PacketHandler` for simple handling that need only a `Verdict`
pub trait VerdictHandler<A> {
    /// Handle a packet from the queue
    ///
    /// Only properly formed `Message`s will be passed to the `decide` fn.
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
