extern crate libc;
extern crate libnetfilter_queue as nfq;

use libc::*;
use std::ptr::null;
use std::mem;
use nfq::nfq_q_handle;
use nfq::handle::{Handle, ProtocolFamily};
use nfq::queue::{CopyMode, VerdictHandler};
use nfq::message::Message;
use nfq::message::verdict::Verdict;

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    let mut queue = handle.queue_builder()
        .decider_and_finalize(Decider)
        .ok().unwrap();

    handle.bind(ProtocolFamily::INET);
    queue.mode(CopyMode::Packet(4096)).ok();

    println!("Listen for packets...");
    handle.start(4096);

    println!("Finished...");
}

struct Decider;

impl VerdictHandler for Decider {
    fn decide(&mut self, message: &mut Message) -> Verdict {
        let id = message.header.id();
        println!("Handline packet (ID: {})", id);

        Verdict::Accept
    }
}
