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

#[repr(C)]
#[packed]
pub struct nfqnl_msg_packet_hdr {
    pub packet_id: uint32_t,
    pub hw_protocol: uint16_t,
    pub hook: uint8_t
}

#[link(name="netfilter_queue")]
extern {
    pub static nfq_errno: c_int;

    // Library setup
    pub fn nfq_open() -> *mut nfq_handle;
    pub fn nfq_close(handle: *mut nfq_handle) -> c_int;
    pub fn nfq_bind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;
    pub fn nfq_unbind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;

    // Queue handling
    pub fn nfq_create_queue(handle: *mut nfq_handle,
                            num: uint16_t,
                            cb: extern "C" fn(h: *mut nfq_q_handle,
                                              nfmsg: *mut nfgenmsg,
                                              nfad: *mut nfq_data,
                                              data: *mut c_void) -> c_int,
                            data: *mut c_void) -> *mut nfq_q_handle;
    pub fn nfq_destroy_queue(handle: *mut nfq_q_handle) -> c_int;
    pub fn nfq_set_mode(handle: *mut nfq_q_handle,
                        mode: uint8_t,
                        range: uint32_t) -> c_int;
    pub fn nfq_set_queue_maxlen(handle: *mut nfq_q_handle,
                                queuelen: uint32_t) -> c_int;

    // Iterating through a queue
    pub fn nfq_fd(handle: *mut nfq_handle) -> c_int;
    pub fn nfq_handle_packet(handle: *mut nfq_handle,
                             buf: *mut c_char,
                             len: c_int) -> c_int;

    // Deciding on a verdict
    pub fn nfq_set_verdict(handle: *mut nfq_q_handle,
                           id: uint32_t,
                           verdict: uint32_t,
                           data_len: uint32_t,
                           buf: *const c_uchar) -> c_int;

    // Parsing the message
    pub fn nf_get_msg_packet_hdr(nfad: *mut nfq_data) -> *const nfqnl_msg_packet_hdr;
}
