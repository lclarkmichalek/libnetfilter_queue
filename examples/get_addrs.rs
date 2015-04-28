extern crate libnfqueue as nfq;

use nfq::handle::{Handle, ProtocolFamily};
use nfq::queue::{Verdict, VerdictHandler};
use nfq::message::{Message, IPHeader};

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    handle.bind(ProtocolFamily::INET).ok().unwrap();

    let mut queue = handle.queue(0, Decider).ok().unwrap();
    queue.set_mode_sized::<IPHeader>().ok().unwrap();

    println!("Listening for packets...");
    handle.start_sized::<IPHeader>();

    println!("...finished.");
}

struct Decider;

impl VerdictHandler for Decider {
    fn decide(&mut self, message: &Message) -> Verdict {
        println!("Handling packet (ID: {})", message.header.id());
        // Note that the queue was set and handle was started with `_sized`
        match unsafe { message.ip_header() } {
            Ok(ip_header) => println!("saddr: {}, daddr: {}", ip_header.saddr(), ip_header.daddr()),
            Err(_) => ()
        };

        Verdict::Accept
    }
}
