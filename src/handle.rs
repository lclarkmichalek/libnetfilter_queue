use libc::*;
use std::mem;
use std::ptr::null;

use error::*;
use lock::NFQ_LOCK;

use ffi::*;
// use queue;

pub enum ProtoFamily {
    INET = AF_INET as isize,
    INET6 = AF_INET6 as isize
}

pub struct Handle {
    ptr: *mut nfq_handle,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let ret = unsafe { nfq_close(self.ptr) };
        if ret != 0 {
            panic!("Failed to close NFQHandle");
        }
    }
}

impl Handle {
    pub fn new() -> Result<Handle, NFQError> {
        let _lock = NFQ_LOCK.lock().unwrap();

        let ptr = unsafe { nfq_open() };
        if ptr.is_null() {
            Err(error(ErrorReason::OpenHandle, "Failed to allocate NFQ Handle", None))
        } else {
            Ok(Handle{ ptr: ptr })
        }
    }

    pub fn bind(&self, proto: ProtoFamily) -> Result<(), NFQError> {
        let _lock = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_bind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(ErrorReason::Bind, "Failed to bind NFQ Handle", Some(res)))
        } else {
            Ok(())
        }
    }

    pub fn unbind(&self, proto: ProtoFamily) -> Result<(), NFQError> {
        let _lock = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_unbind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(ErrorReason::Unbind, "Failed to unbind NFQ Handle", Some(res)))
        } else {
            Ok(())
        }
    }
}
