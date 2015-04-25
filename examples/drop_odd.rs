extern crate libnfqueue as nfq;

use nfq::{Handle, ProtocolFamily, CopyMode, VerdictHandler, Message, Verdict};

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    let mut queue = handle.queue(0, Decider{count: 0}).unwrap();

    handle.bind(ProtocolFamily::INET).ok();
    queue.mode(CopyMode::Packet(4096)).ok();

    println!("Listening for packets...");
    handle.start(4096);

    println!("Finished...");
}

struct Decider {
    count: i32
}

impl VerdictHandler for Decider {
    fn decide(&mut self, message: &mut Message) -> Verdict {
        let id = message.header.id();

        self.count += 1;
        if self.count % 2 == 0 {
            println!("Accepting packet {}", id);
            Verdict::Accept
        } else {
            println!("Dropping packet {}", id);
            Verdict::Drop
        }
    }
}
