extern crate libc;
extern crate libnetfilter_queue as nfq;

use libc::*;
use std::ptr::null;
use std::mem;
use nfq::nfq_q_handle;
use nfq::handle::{Handle, ProtocolFamily};
use nfq::queue::{Queue, CopyMode};
use nfq::message::Message;
use nfq::message::verdict::{set_verdict, Verdict};

fn main() {
    let mut void = Void;
    let mut handle = Handle::new().ok().unwrap();
    println!("Obtained a handle");

    handle.bind(ProtocolFamily::INET);
    println!("Bound to INET");

    let mut queue = handle.queue::<Void>(0, packet_handler, void).ok().unwrap();
    println!("Registered a packet handler to the queue");

    queue.mode(CopyMode::Packet(4096)).ok().unwrap();
    println!("Set copy mode");

    println!("Beginning to listen...");
    handle.start(4096);

    println!("Finished...");
}

fn packet_handler(qh: *mut nfq_q_handle, mut message: Message, data: &mut Void) -> i32 {
    let header = &message.header;
    println!("Packet ID: {}, Protocol: {}, Hook: {}", header.id, header.protocol, header.hook);

    let NULL: *const c_uchar = null();
    match set_verdict(qh, header.id, Verdict::Accept, 0, NULL) {
        Ok(r) => { println!("Verdict set: {}", r); r },
        Err(_) => -1
    }
}

struct Void;
