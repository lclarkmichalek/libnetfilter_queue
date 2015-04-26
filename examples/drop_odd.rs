extern crate libnfqueue as nfq;

use nfq::{Handle, ProtocolFamily, CopyMode, VerdictHandler, Message, Verdict};

fn main() {
    let mut handle = Handle::new().ok().unwrap();

    let mut count = 0;

    let mut queue = handle.queue(0, move |message: &mut Message| {
        let id = message.header().id();

        count += 1;

        if count % 2 == 0 {
            println!("{} accepting packet", id);
            Verdict::Accept
        } else {
            println!("{} dropping packet", id);
            Verdict::Drop
        }
    }).unwrap();

    handle.bind(ProtocolFamily::INET).ok();
    queue.mode(CopyMode::Packet(4096)).ok();

    println!("Listening for packets...");
    handle.start(4096);

    println!("Finished...");
}
