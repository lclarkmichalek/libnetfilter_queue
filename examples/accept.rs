extern crate libc;
extern crate libnetfilter_queue;

use libc::*;
use libnetfilter_queue::nfq_q_handle;
use libnetfilter_queue::handle::{Handle, ProtocolFamily};
use libnetfilter_queue::message::Message;
use libnetfilter_queue::message::verdict::{set_verdict, Verdict};

fn main() {
    let mut void = Void;
    let mut handle = Handle::new().ok().unwrap();

    handle.bind(ProtocolFamily::INET);
    handle.queue::<Void>(0, packet_handler, void);
    handle.start(4096);
}

fn packet_handler(qh: *mut nfq_q_handle, mut message: Message, data: &mut Void) -> i32 {
    let id = message.header().packet_id.clone();

    set_verdict(qh, id, Verdict::Accept, 4096, message.raw as *mut c_uchar);
    0
}

struct Void;
