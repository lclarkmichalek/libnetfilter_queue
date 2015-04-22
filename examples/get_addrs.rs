extern crate libc;
extern crate netfilter_queue as nfq;

use nfq::verdict::{Verdict, VerdictHandler};
use nfq::message::{Message, IPHeader};
use nfq::handle::{Handle, ProtocolFamily};

fn main() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode_sized_to_payload::<IPHeader>()
        .decider_and_finalize(Decider)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET);

    println!("Listening for packets...");
    handle.start_sized_to_payload::<IPHeader>();

    println!("...finished.");
}

struct Void;
struct Decider;

impl VerdictHandler<Void> for Decider {
    fn decide(&self, message: &Message, _: &mut Void) -> Verdict {
        // Note that the queue was set and handle was started with `_sized_to_payload`
        match unsafe { message.ip_header() } {
            Ok(ip_header) => println!("saddr: {}, daddr: {}", ip_header.saddr(), ip_header.daddr()),
            Err(_) => ()
        };

        Verdict::Accept
    }
}
