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
use message::verdict::Verdict;
use lock::NFQ_LOCK as LOCK;

use ffi::{nfq_handle, nfgenmsg, nfq_data, nfq_destroy_queue, nfq_create_queue, nfq_set_queue_maxlen, nfq_set_mode};
pub use ffi::nfq_q_handle;

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

pub trait PacketHandler<A> {
    fn handle(&self, hq: *mut nfq_q_handle, message: &Message, data: &mut A) -> i32;
}

pub trait VerdictHandler<A> {
    fn decide(&self, message: &Message, data: &mut A) -> Verdict;
}

#[allow(non_snake_case)]
impl<A, V> PacketHandler<A> for V where V: VerdictHandler<A> {
    fn handle(&self, hq: *mut nfq_q_handle, message: &Message, data: &mut A) -> i32 {
        let NULL: *const c_uchar = null();
        let verdict = self.decide(message, data);
        match message.header {
            Ok(header) => { let _ = Verdict::set_verdict(hq, header.id(), verdict, 0, NULL); },
            Err(_) => (),
        };
        0
    }
}

extern fn queue_callback<A, F: PacketHandler<A>>(qh: *mut nfq_q_handle,
                               nfmsg: *mut nfgenmsg,
                               nfad: *mut nfq_data,
                               cdata: *mut c_void) -> c_int {

    let queue_ptr: *mut Queue<A, F> = unsafe { mem::transmute(cdata) };
    let queue: &mut Queue<A, F> = unsafe { as_mut(&queue_ptr).unwrap() };
    let message = Message::new(nfmsg, nfad);

    queue.callback.handle(qh, &message, &mut queue.data) as c_int
}

pub struct Queue<A, F: PacketHandler<A>> {
    ptr: *mut nfq_q_handle,
    data: A,
    callback: F
}

impl<A, F: PacketHandler<A>> Drop for Queue<A, F> {
    fn drop(&mut self) {
        let ret = unsafe { nfq_destroy_queue(self.ptr) };
        if ret != 0 {
            panic!("Failed to destroy nfq queue");
        }
    }
}

impl<A, F: PacketHandler<A>> Queue<A, F> {
    fn new(handle: *mut nfq_handle,
           queue_number: u16,
           data: A,
           packet_handler: F) -> Result<Box<Queue<A, F>>, Error> {
        let _lock = LOCK.lock().unwrap();

        let nfq_ptr: *const nfq_q_handle = null();
        let mut queue: Box<Queue<A, F>> = Box::new(Queue {
            ptr: nfq_ptr as *mut nfq_q_handle, // set after nfq_create_queue
            data: data,
            callback: packet_handler,
        });
        let queue_ptr: *mut Queue<A, F> = &mut *queue;

        let ptr = unsafe {
            nfq_create_queue(handle,
                             queue_number,
                             queue_callback::<A, F>,
                             mem::transmute(queue_ptr))
        };

        if ptr.is_null() {
            Err(error(Reason::CreateQueue, "Failed to create queue", None))
        } else {
            queue.ptr = ptr;
            Ok(queue)
        }
    }

    pub fn mode(&mut self, mode: CopyMode) -> Result<(), Error> {
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
            Err(error(Reason::SetQueueMode, "Failed to set queue mode", Some(res)))
        } else {
            Ok(())
        }
    }

    pub fn maxlen(&mut self, len: u32) -> Result<(), Error> {
        let res = unsafe { nfq_set_queue_maxlen(self.ptr, len) };
        if res != 0 {
            Err(error(Reason::SetQueueMaxlen, "Failed to set queue maxlen", Some(res)))
        } else {
            Ok(())
        }
    }
}

pub struct QueueBuilder<A> {
    ptr: *mut nfq_handle,
    queue_number: uint16_t,
    data: A
}

impl<A> QueueBuilder<A> {
    pub fn new(ptr: *mut nfq_handle, data: A) -> QueueBuilder<A> {
        QueueBuilder {
            ptr: ptr,
            queue_number: 0,
            data: data
        }
    }

    pub fn queue_number(&mut self, queue_number: u16) -> &mut QueueBuilder<A> {
        self.queue_number = queue_number;
        self
    }

    pub fn callback_and_finalize<F: PacketHandler<A>>(self, callback: F)
            -> Result<Box<Queue<A, F>>, Error> {
        Queue::new(self.ptr, self.queue_number, self.data, callback)
    }

    pub fn decider_and_finalize<F: PacketHandler<A> + VerdictHandler<A>>(self, decider: F)
            -> Result<Box<Queue<A, F>>, Error> {
        Queue::new(self.ptr, self.queue_number, self.data, decider)
    }
}

