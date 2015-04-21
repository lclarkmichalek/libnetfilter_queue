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

pub struct Queue<A> {
    ptr: *mut nfq_q_handle,
    callback: fn(handle: *mut nfq_q_handle, message: Message, data: &mut A) -> i32,
    data: A
}

extern fn queue_callback<A>(qh: *mut nfq_q_handle,
                            nfmsg: *mut nfgenmsg,
                            nfad: *mut nfq_data,
                            cdata: *mut c_void) -> c_int {

    let queue_ptr: *mut Queue<A> = unsafe { mem::transmute(cdata) };
    let queue: &mut Queue<A> = unsafe { as_mut(&queue_ptr).unwrap() };
    let message = Message::new(nfmsg, nfad);

    (queue.callback)(qh, message, &mut queue.data) as c_int
}

impl<A> Drop for Queue<A> {
    fn drop(&mut self) {
        let ret = unsafe { nfq_destroy_queue(self.ptr) };
        if ret != 0 {
            panic!("Failed to destroy nfq queue");
        }
    }
}

pub fn new_queue<A>(handle: *mut nfq_handle,
                 queue_number: u16,
                 // TODO: Add a layer of abstraction (struct Packet) to hide the nfq_q_handle
                 packet_handler: fn(qh: *mut nfq_q_handle,
                                 message: Message,
                                 data: &mut A) -> i32,
                 mut data: A) -> Result<Box<Queue<A>>, NFQError> {
    let _lock = LOCK.lock().unwrap();

    let nfq_ptr: *const nfq_q_handle = null();
    let mut queue: Box<Queue<A>> = Box::new(Queue {
        ptr: nfq_ptr as *mut nfq_q_handle, // set after nfq_create_queue
        data: data,
        callback: packet_handler,
    });
    let queue_ptr: *mut Queue<A> = &mut *queue;

    let ptr = unsafe {
        nfq_create_queue(handle,
                         queue_number,
                         queue_callback::<A>,
                         mem::transmute(queue_ptr))
    };

    if ptr.is_null() {
        Err(error(ErrorReason::CreateQueue, "Failed to create Queue", None))
    } else {
        queue.ptr = ptr;
        Ok(queue)
    }
}

impl<A> Queue<A> {
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
