extern crate libc;
extern crate libnetfilter_queue as nfq;

use nfq::verdict::{Verdict, VerdictHandler};
use nfq::message::{Message, IPHEADER_SIZE};
use nfq::queue::CopyMode;
use nfq::handle::{Handle, ProtocolFamily};

fn main() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let mut queue = handle.queue_builder::<Void>(void)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET);
    let _ = queue.mode(CopyMode::Packet(IPHEADER_SIZE)).ok();

    println!("Listen for packets...");
    handle.start(IPHEADER_SIZE as u64);

    println!("Finished...");
}

struct Void;
struct Decider;

impl VerdictHandler<Void> for Decider {
    fn decide(&self, message: &Message, _: &mut Void) -> Verdict {
        match message.header {
            Ok(packet_header) => println!("Handling packet (ID: {})", packet_header.id()),
            Err(_) => ()
        };

        match unsafe { message.ip_header() } {
            Ok(ip_header) => println!("saddr: {}, daddr: {}", ip_header.saddr(), ip_header.daddr()),
            Err(_) => ()
        };

        Verdict::Accept
    }
}
