extern crate libc;
extern crate netfilter_queue as nfq;

use nfq::verdict::{Verdict, VerdictHandler};
use nfq::message::{Message, IPHEADER_SIZE};
use nfq::queue::CopyMode;
use nfq::handle::{Handle, ProtocolFamily};

fn main() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let mut queue = handle.queue_builder(void)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET);
    let _ = queue.set_mode(CopyMode::Packet(IPHEADER_SIZE)).ok();

    println!("Listening for packets...");
    handle.start(IPHEADER_SIZE);

    println!("...finished.");
}

struct Void;
struct Decider;

impl VerdictHandler<Void> for Decider {
    fn decide(&self, message: &Message, _: &mut Void) -> Verdict {
        match unsafe { message.ip_header() } { // Note that the handle was started with IPHEADER_SIZE
            Ok(ip_header) => println!("saddr: {}, daddr: {}", ip_header.saddr(), ip_header.daddr()),
            Err(_) => ()
        };

        Verdict::Accept
    }
}
