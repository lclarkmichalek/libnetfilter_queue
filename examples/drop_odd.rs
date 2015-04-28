extern crate libnfqueue as nfq;

use nfq::handle::{Handle, ProtocolFamily};
use nfq::queue::{CopyMode, Verdict, VerdictHandler};
use nfq::message::Message;

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    handle.bind(ProtocolFamily::INET).ok().unwrap();

    let counter = Counter(0);
    let mut queue = handle.queue(0, counter).ok().unwrap();
    queue.set_mode(CopyMode::Metadata).ok().unwrap();

    println!("Listening for packets...");
    handle.start(4096);

    println!("Finished...");
}

struct Counter(u64);

impl VerdictHandler for Counter {
    fn decide(&mut self, message: &Message) -> Verdict {
        println!("Handling packet (ID: {})", message.header.id());

        let count = self.0 + 1;
        self.0 = count;
        match count {
            c if c % 2 == 0 => {
                println!("Accepting even packet: {}", c);
                Verdict::Accept
            },
            c @ _ => {
                println!("Dropping odd packet: {}", c);
                Verdict::Drop
            }
        }
    }
}
