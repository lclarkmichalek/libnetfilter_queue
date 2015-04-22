extern crate libc;
extern crate libnetfilter_queue as nfq;

use nfq::verdict::{Verdict, VerdictHandler};
use nfq::message::Message;
use nfq::queue::CopyMode;
use nfq::handle::{Handle, ProtocolFamily};

fn main() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let mut queue = handle.queue_builder(void)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET);
    let _ = queue.mode(CopyMode::Packet(4096)).ok();

    println!("Listen for packets...");
    handle.start(4096);

    println!("Finished...");
}

struct Void;
struct Decider;

impl VerdictHandler<Void> for Decider {
    fn decide(&self, message: &Message, _: &mut Void) -> Verdict {
        match message.header {
            Ok(header) => println!("Handling packet (ID: {})", header.id()),
            Err(_) => ()
        };

        Verdict::Accept
    }
}
