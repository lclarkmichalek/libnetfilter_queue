//! Queue handling
//!
//! The queue handle and callback,
//! analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html>

use libc::*;
use std::mem;
use std::ptr::null;

use error::*;
use util::*;
use message::Message;
use verdict::Verdict;
use lock::NFQ_LOCK as LOCK;

use ffi::*;

enum NFQCopyMode {
    NONE = 0,
    META = 1,
    PACKET = 2
}

pub enum CopyMode {
    None,
    Metadata,
    Packet(u16)
}

pub trait PacketHandler {
    fn handle(&mut self, hq: *mut nfq_q_handle, message: &mut Message) -> i32;
}

pub trait VerdictHandler {
    fn decide(&mut self, message: &mut Message) -> Verdict;
}

impl<V> PacketHandler for V where V: VerdictHandler {
    fn handle(&mut self, hq: *mut nfq_q_handle, message: &mut Message) -> i32 {
        let NULL: *const c_uchar = null();
        let verdict = self.decide(message);
        Verdict::set_verdict(hq, message.header.id(), verdict, 0, NULL);
        0
    }
}

extern fn queue_callback<F: PacketHandler>(qh: *mut nfq_q_handle,
                               nfmsg: *mut nfgenmsg,
                               nfad: *mut nfq_data,
                               cdata: *mut c_void) -> c_int {

    let queue_ptr: *mut Queue<F> = unsafe { mem::transmute(cdata) };
    let queue: &mut Queue<F> = unsafe { as_mut(&queue_ptr).unwrap() };
    let mut message = Message::new(nfmsg, nfad);

    queue.callback.handle(qh, &mut message) as c_int
}

pub struct Queue<F: PacketHandler> {
    ptr: *mut nfq_q_handle,
    callback: F
}

impl<F: PacketHandler> Drop for Queue<F> {
    fn drop(&mut self) {
        let ret = unsafe { nfq_destroy_queue(self.ptr) };
        if ret != 0 {
            panic!("Failed to destroy nfq queue");
        }
    }
}

impl<F: PacketHandler> Queue<F> {
    pub fn new(handle: *mut nfq_handle,
           queue_number: u16,
           packet_handler: F) -> Result<Box<Queue<F>>, NFQError> {
        let _lock = LOCK.lock().unwrap();

        let nfq_ptr: *const nfq_q_handle = null();
        let mut queue: Box<Queue<F>> = Box::new(Queue {
            ptr: nfq_ptr as *mut nfq_q_handle, // set after nfq_create_queue
            callback: packet_handler,
        });
        let queue_ptr: *mut Queue<F> = &mut *queue;

        let ptr = unsafe {
            nfq_create_queue(handle,
                             queue_number,
                             queue_callback::<F>,
                             mem::transmute(queue_ptr))
        };

        if ptr.is_null() {
            Err(error(ErrorReason::CreateQueue, "Failed to create Queue", None))
        } else {
            queue.ptr = ptr;
            Ok(queue)
        }
    }

    pub fn mode(&mut self, mode: CopyMode) -> Result<(), NFQError> {
        let copy_mode = match mode {
            CopyMode::None => NFQCopyMode::NONE,
            CopyMode::Metadata => NFQCopyMode::META,
            CopyMode::Packet(_) => NFQCopyMode::PACKET
        } as uint8_t;
        let range = match mode {
            CopyMode::Packet(r) => r,
            _ => 0
        } as uint16_t as uint32_t;

        let res = unsafe { nfq_set_mode(self.ptr, copy_mode, range) };
        if res != 0 {
            Err(error(ErrorReason::SetQueueMode, "Failed to set queue mode", Some(res)))
        } else {
            Ok(())
        }
    }

    pub fn maxlen(&mut self, len: u32) -> Result<(), NFQError> {
        let res = unsafe { nfq_set_queue_maxlen(self.ptr, len) };
        if res != 0 {
            Err(error(ErrorReason::SetQueueMaxlen, "Failed to set queue maxlen", Some(res)))
        } else {
            Ok(())
        }
    }
}
