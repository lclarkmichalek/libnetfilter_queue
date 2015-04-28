extern crate libnfqueue as nfq;

use nfq::handle::{Handle, ProtocolFamily};
use nfq::queue::{Verdict, VerdictHandler};
use nfq::message::Message;

fn main() {
    println!("Opening handle.");
    let mut handle = Handle::new().ok().unwrap();

    println!("Getting queue.");
    let _queue = handle.queue(0, Decider).unwrap();

    println!("Binding to INET.");
    let _ = handle.bind(ProtocolFamily::INET);

    println!("Listening for packets...");
    handle.start(4096);

    println!("...finished.");
}

struct Decider;

impl VerdictHandler for Decider {
    fn decide(&mut self, message: &Message) -> Verdict {
        let id = message.header.id();
        println!("Handling packet (ID: {})", id);

        Verdict::Accept
    }
}
