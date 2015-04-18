use libc::*;
use std::mem;
use std::ptr::null;

use error::*;
use lock::*;

use raw::*;

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

pub struct NFGenMsg {
    ptr: *mut nfgenmsg
}
pub struct NFQData {
    ptr: *mut nfq_data
}

struct CallbackData<A> {
    ctx: *mut A,
    func: fn(ctx: &mut A, msg: &NFGenMsg, ad: &NFQData) -> i32
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


pub fn new_queue<A>(h: *mut nfq_handle,
                    num: u16,
                    ctx: A,
                    cb: fn(ctx: &mut A,
                           msg: &NFGenMsg,
                           ad: &NFQData) -> i32
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

    let ptr = unsafe { nfq_create_queue(h,
                                        num,
                                        queue_callback::<A>,
                                        mem::transmute(&queue.cb_data)) };
    if ptr.is_null() {
        Err(error(ErrorReason::CreateQueue, "Failed to create queue", None))
    } else {
        queue.ptr = ptr;
        Ok(queue)
    }
}

impl<A> NFQQueue<A> {
    pub fn mode(&mut self, mode: CopyMode) -> Result<(), NFQError> {
        let cmode = match mode {
            CopyMode::None => NFQCopyMode::NONE,
            CopyMode::Metadata => NFQCopyMode::META,
            CopyMode::Packet(_) => NFQCopyMode::PACKET
        } as uint8_t;
        let range = match mode {
            CopyMode::Packet(r) => r,
            _ => 0
        } as uint16_t as uint32_t;

        let res = unsafe { nfq_set_mode(self.ptr, cmode, range) };
        if res != 0 {
            Err(error(ErrorReason::SetQueueMode, "Failed to set queue mode", Some(res)))
        } else {
            Ok(())
        }
    }

    pub fn queue_maxlen(&mut self, len: u32) -> Result<(), NFQError> {
        let res = unsafe { nfq_set_queue_maxlen(self.ptr, len as uint32_t) };
        if res != 0 {
            Err(error(ErrorReason::SetQueueMaxlen, "Failed to set queue maxlen", Some(res)))
        } else {
            Ok(())
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
