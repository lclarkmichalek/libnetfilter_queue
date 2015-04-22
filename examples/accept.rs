extern crate libc;
extern crate netfilter_queue as nfq;

use nfq::verdict::{Verdict, VerdictHandler};
use nfq::message::Message;
use nfq::queue::CopyMode;
use nfq::handle::{Handle, ProtocolFamily};

fn main() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode(CopyMode::None)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET);

    println!("Listening for packets...");
    handle.start(4096);

    println!("...finished.");
}

struct Void;
struct Decider;

impl VerdictHandler<Void> for Decider {
    fn decide(&self, message: &Message, _: &mut Void) -> Verdict {
        println!("Handling packet (ID: {})", message.header.id());
        Verdict::Accept
    }
}
