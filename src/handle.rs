#![allow(non_camel_case_types)]

use nfq::*;

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
