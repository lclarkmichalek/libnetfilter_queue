extern crate libnfqueue as nfq;

use nfq::{Handle, ProtocolFamily, CopyMode, VerdictHandler, Message, Verdict};

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    let mut queue = handle.queue(0, Decider).unwrap();

    handle.bind(ProtocolFamily::INET);
    queue.mode(CopyMode::Packet(4096)).ok();

    println!("Listen for packets...");
    handle.start(4096);

    println!("Finished...");
}

struct Decider;

impl VerdictHandler for Decider {
    fn decide(&mut self, message: &mut Message) -> Verdict {
        let id = message.header().id();
        println!("Handling packet (ID: {})", id);

        Verdict::Accept
    }
}
