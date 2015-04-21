#![allow(non_camel_case_types)]

use std::num::Int;
use libc::*;

#[link(name="linux/netfilter")]
pub const NF_DROP: c_int = 0;
pub const NF_ACCEPT: c_int = 1;
pub const NF_STOLEN: c_int = 2;
pub const NF_QUEUE: c_int = 3;
pub const NF_REPEAT: c_int = 4;
pub const NF_STOP: c_int = 5;

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

impl nfqnl_msg_packet_hdr {
    pub fn id(&self) -> u32 { Int::from_be(self.packet_id) }
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
    pub fn nfq_get_msg_packet_hdr(nfad: *mut nfq_data) -> *const nfqnl_msg_packet_hdr;
}
