#![allow(non_camel_case_types)]

use libc::*;
use std::sync::{StaticMutex, MUTEX_INIT};
use std::error::Error;
use std::mem;
use std::ptr::null;

static NFQ_LOCK: StaticMutex = MUTEX_INIT;

pub struct NFQError(pub String);

impl<E: Error> From<E> for NFQError {
    fn from(err: E) -> NFQError {
        NFQError(err.description().to_string())
    }
}

fn error(msg: &str) -> NFQError {
    let errno = unsafe { nfq_errno };
    NFQError(format!("{} (errno: {})", msg, errno))
}

#[link(name="netfilter_queue")]
extern {
    static mut nfq_errno: c_int;
}

// NFQ Handle

#[repr(C)]
struct nfq_handle;

#[repr(C)]
pub enum ProtoFamily {
    INET = 2,
    INET6 = 10,
}

#[link(name="netfilter_queue")]
extern {
    fn nfq_open() -> *mut nfq_handle;
    fn nfq_close(handle: *mut nfq_handle) -> c_int;

    fn nfq_bind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;
    fn nfq_unbind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;
}

pub struct NFQHandle {
    ptr: *mut nfq_handle,
}

impl Drop for NFQHandle {
    fn drop(&mut self) {
        let ret = unsafe { nfq_close(self.ptr) };
        if ret != 0 {
            panic!("Failed to close nfq handle");
        }
    }
}

impl NFQHandle {
    pub fn new() -> Result<NFQHandle, NFQError> {
        let _g = NFQ_LOCK.lock().unwrap();

        let ptr = unsafe { nfq_open() };
        if ptr.is_null() {
            Err(error("Failed to allocate NFQHandle"))
        } else {
            Ok(NFQHandle{ ptr: ptr })
        }
    }

    pub fn bind(&mut self, proto: ProtoFamily) -> Result<(), NFQError> {
        let _g = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_bind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error("Failed to bind packet filter"))
        } else {
            Ok(())
        }
    }

    pub fn unbind(&mut self, proto: ProtoFamily) -> Result<(), NFQError> {
        let _g = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_unbind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error("Failed to unbind packet filter"))
        } else {
            Ok(())
        }
    }

}

// NFQ Queue
#[repr(C)]
struct nfq_q_handle;

#[repr(C)]
struct nfgenmsg;

#[repr(C)]
struct nfq_data;

pub struct NFGenMsg {
    ptr: *mut nfgenmsg
}
pub struct NFQData {
    ptr: *mut nfq_data
}

#[repr(C)]
struct CallbackData<A> {
    ctx: *mut A,
    func: fn(ctx: &mut A, msg: &NFGenMsg, ad: &NFQData) -> c_int
}

#[link(name="netfilter_queue")]
extern {
    fn nfq_create_queue(handle: *mut nfq_handle,
                        num: uint16_t,
                        cb: extern "C" fn(h: *mut nfq_q_handle,
                                          nfmsg: *mut nfgenmsg,
                                          nfad: *mut nfq_data,
                                          data: *mut c_void) -> c_int,
                        data: *mut c_void) -> *mut nfq_q_handle;
    fn nfq_destroy_queue(handle: *mut nfq_q_handle) -> c_int;
}

pub struct NFQQueue<A> {
    ptr: *mut nfq_q_handle,
    cb_data: CallbackData<A>,
    ctx: A
}

extern fn queue_callback<A>(h: *mut nfq_q_handle,
                            nfmsg: *mut nfgenmsg,
                            nfad: *mut nfq_data,
                            cdata: *mut c_void) -> c_int {
    let data: &CallbackData<A> = unsafe { mem::transmute(cdata) };
    let msg = NFGenMsg { ptr: nfmsg };
    let ad = NFQData { ptr: nfad };
    let mut ctx = match unsafe { data.ctx.as_mut() } {
        Some(c) => c,
        None => panic!("Could not deref ctx pointer")
    };
    (data.func)(ctx, &msg, &ad) as c_int
}

impl<A> NFQQueue<A> {
    pub fn new(h: &NFQHandle,
               num: u16,
               ctx: A,
               cb: fn(ctx: &mut A,
                      msg: &NFGenMsg,
                      ad: &NFQData) -> c_int
               ) -> Result<NFQQueue<A>, NFQError> {
        let _g = NFQ_LOCK.lock().unwrap();




        let fpointer: *const nfq_q_handle = null();
        let apointer: *const A = null();
        // So we initialise the queue obj as empty apart from the ctx
        // This is so we can take references to the mem inside
        let mut queue = NFQQueue {
            ctx: ctx,
            // Will be set after nfq_create_queue
            ptr: fpointer as *mut nfq_q_handle,
            cb_data: CallbackData{
                // Will be set to reference to queue.ctx
                ctx: apointer as *mut A,
                func: cb
            }
        };

        let ctxp: *mut A = &mut queue.ctx;
        queue.cb_data.ctx = ctxp;

        let ptr = unsafe { nfq_create_queue(h.ptr,
                                            num,
                                            queue_callback::<A>,
                                            mem::transmute(&queue.cb_data)) };
        if ptr.is_null() {
            Err(error("Failed to create queue"))
        } else {
            queue.ptr = ptr;
            Ok(queue)
        }
    }
}

impl<A> Drop for NFQQueue<A> {
    fn drop(&mut self) {
        let ret = unsafe { nfq_destroy_queue(self.ptr) };
        if ret != 0 {
            panic!("Failed to destroy nfq queue");
        }
    }
}
