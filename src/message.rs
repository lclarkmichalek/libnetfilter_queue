//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use libc::*;
use std::mem;
use std::ptr::null;
use std::net::Ipv4Addr;
use num::traits::PrimInt;

use error::*;
use util::*;
use ffi::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;

pub trait Payload {}

pub const IPHEADER_SIZE: u16 = 160;

#[allow(dead_code)]
pub struct IPHeader {
    pub version_and_header_raw: u8,
    pub dscp_raw: u8,
    pub total_length_raw: u16,
    pub id_raw: u16,
    pub flags_and_offset_raw: u16,
    pub ttl_raw: u8,
    pub protocol_raw: u8,
    pub checksum_raw: u16,
    pub saddr_raw: u32,
    pub daddr_raw: u32
}

impl IPHeader {
    pub fn new() -> IPHeader {
        IPHeader {
            version_and_header_raw: 0,
            dscp_raw: 0,
            total_length_raw: 0,
            id_raw: 0,
            flags_and_offset_raw: 0,
            ttl_raw: 0,
            protocol_raw: 0,
            checksum_raw: 0,
            saddr_raw: 0,
            daddr_raw: 0,
        }
    }

    pub fn saddr(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.saddr_raw)
    }

    pub fn daddr(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.daddr_raw)
    }
}

#[inline]
fn addr_to_ipv4(src: &u32) -> Ipv4Addr {
    let octets: [u8; 4] = unsafe { mem::transmute(*src) };
    Ipv4Addr::new(u8::from_be(octets[0]),
                  u8::from_be(octets[1]),
                  u8::from_be(octets[2]),
                  u8::from_be(octets[3]))
}

impl Payload for IPHeader {}

pub struct Message<'a> {
    pub raw: *mut nfgenmsg,
    pub ptr: *mut nfq_data,
    pub header: Result<&'a Header, Error>
}

impl<'a> Drop for Message<'a> {
    fn drop(&mut self) {}
}

impl<'a> Message<'a> {
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Message<'a> {
        let header = unsafe {
            let ptr = nfq_get_msg_packet_hdr(ptr);
            if ptr.is_null() {
                Err(error(Reason::GetHeader, "Failed to get header", None))
            } else {
                Ok(as_ref(&ptr).unwrap())
            }
        };
        Message {
            raw: raw,
            ptr: ptr,
            header: header
        }
    }

    pub unsafe fn ip_header(&self) -> Result<&IPHeader, Error> {
        self.payload::<IPHeader>()
    }

    pub unsafe fn payload<A: Payload>(&self) -> Result<&A, Error> {
        let data: *const A = null();
        let ptr: *mut *mut A = &mut (data as *mut A);
        let _ = match nfq_get_payload(self.ptr, ptr as *mut *mut c_uchar) {
            -1 => return Err(error(Reason::GetPayload, "Failed to get payload", Some(-1))),
            _ => ()
        };
        match as_ref(&data) {
            Some(payload) => Ok(payload),
            None => Err(error(Reason::GetPayload, "Failed to get payload", None))
        }
    }
}
