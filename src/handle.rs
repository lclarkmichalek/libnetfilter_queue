//! The handle into NFQueue, necessary for library setup.

use libc::*;
use std::mem;
use std::ptr::null;

use error::*;
use lock::NFQ_LOCK;

use ffi::*;

/// Protocol Family
///
/// NFQueue will only deal with IP, so only those families are made available.
pub enum ProtocolFamily {
    /// IPv4 Address Family
    INET = AF_INET as isize,
    /// IPv4 Address Family
    INET6 = AF_INET6 as isize
}

/// A handle into NFQueue
///
/// This is needed for library setup.
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
    /// Open a new handle to NFQueue
    ///
    /// This tells the kernel that userspace queuing will be handled for the selected protocol.
    pub fn new() -> Result<Handle, NFQError> {
        let _lock = NFQ_LOCK.lock().unwrap();

        let ptr = unsafe { nfq_open() };
        if ptr.is_null() {
            Err(error(ErrorReason::OpenHandle, "Failed to allocate NFQ Handle", None))
        } else {
            Ok(Handle{ ptr: ptr })
        }
    }

    /// Bind the handle to a `Protocol Family`
    pub fn bind(&self, proto: ProtocolFamily) -> Result<(), NFQError> {
        let _lock = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_bind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(ErrorReason::Bind, "Failed to bind NFQ Handle", Some(res)))
        } else {
            Ok(())
        }
    }

    /// Unbind the handle from a `Protocol Family`
    ///
    /// This should usually be avoided, as it may attach other programs from the `Protocol Family`.
    pub fn unbind(&self, proto: ProtocolFamily) -> Result<(), NFQError> {
        let _lock = NFQ_LOCK.lock().unwrap();

        let res = unsafe { nfq_unbind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(ErrorReason::Unbind, "Failed to unbind NFQ Handle", Some(res)))
        } else {
            Ok(())
        }
    }
}
