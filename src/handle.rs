use libc::*;
use std::mem;
use std::ptr::null;

use error::*;
use lock::NFQ_LOCK;

use raw::*;
use queue;

pub enum ProtoFamily {
    INET = 2,
    INET6 = 10,
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
            Err(error(ErrorReason::OpenHandle, "Failed to allocate NFQHandle", None))
        } else {
            Ok(NFQHandle{ ptr: ptr })
        }
    }

    pub fn bind(&mut self, proto: ProtoFamily) -> Result<(), NFQError> {
        let _g = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_bind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(ErrorReason::Bind, "Failed to bind packet filter", Some(res)))
        } else {
            Ok(())
        }
    }

    pub fn unbind(&mut self, proto: ProtoFamily) -> Result<(), NFQError> {
        let _g = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_unbind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(ErrorReason::Unbind, "Failed to unbind packet filter", Some(res)))
        } else {
            Ok(())
        }
    }

    pub fn queue<A>(&self,
                    num: u16,
                    ctx: A,
                    cb: fn(ctx: &mut A,
                           msg: &queue::NFGenMsg,
                           ad: &queue::NFQData) -> c_int
                    ) -> Result<queue::NFQQueue<A>, NFQError> {
        queue::new_queue::<A>(self.ptr, num, ctx, cb)
    }

}
