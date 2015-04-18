#![allow(non_camel_case_types)]

use libc::*;

#[repr(C)]
pub struct nfq_handle;

#[repr(C)]
pub struct nfq_q_handle;

#[repr(C)]
pub struct nfgenmsg;

#[repr(C)]
pub struct nfq_data;

#[link(name="netfilter_queue")]
extern {
    pub static nfq_errno: c_int;

    pub fn nfq_open() -> *mut nfq_handle;
    pub fn nfq_close(handle: *mut nfq_handle) -> c_int;

    pub fn nfq_bind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;
    pub fn nfq_unbind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;

    pub fn nfq_create_queue(handle: *mut nfq_handle,
                        num: uint16_t,
                        cb: extern "C" fn(h: *mut nfq_q_handle,
                                          nfmsg: *mut nfgenmsg,
                                          nfad: *mut nfq_data,
                                          data: *mut c_void) -> c_int,
                        data: *mut c_void) -> *mut nfq_q_handle;
    pub fn nfq_destroy_queue(handle: *mut nfq_q_handle) -> c_int;

    pub fn nfq_fd(handle: *mut nfq_handle) -> c_int;
    pub fn nfq_handle_packet(handle: *mut nfq_handle,
                         buf: *mut u8,
                         len: c_int) -> c_int;

    pub fn nfq_set_mode(handle: *mut nfq_q_handle,
                    mode: uint8_t,
                    range: uint32_t) -> c_int;
    pub fn nfq_set_queue_maxlen(handle: *mut nfq_q_handle,
                            queuelen: uint32_t) -> c_int;
    pub fn nfq_set_verdict(handle: *mut nfq_q_handle,
                       id: uint32_t,
                       verdict: uint32_t,
                       data_len: uint32_t,
                       buf: *const u8) -> c_int;
}
