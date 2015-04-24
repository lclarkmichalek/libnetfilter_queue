use handle::*;
use queue::*;
use message::*;
use message::verdict::*;
use error::*;

struct CallbackCtx {
    count: u64
}

impl VerdictHandler for CallbackCtx {
    fn decide(&mut self, msg: &mut Message) -> Verdict {
        self.count += 1;
        Verdict::Accept
    }
}

#[test]
fn create_queue() {
    let mut h = Handle::new().unwrap();
    h.bind(ProtocolFamily::INET).unwrap();
    let queue = h.queue(1, CallbackCtx{count: 0}).unwrap();
}

#[test]
fn set_mode() {
    let mut h = Handle::new().unwrap();
    h.bind(ProtocolFamily::INET).unwrap();
    let mut queue = h.queue(1, CallbackCtx{count: 0}).unwrap();
    queue.mode(CopyMode::Packet(1024)).unwrap();
}

#[test]
fn set_maxlen() {
    let mut h = Handle::new().unwrap();
    h.bind(ProtocolFamily::INET).unwrap();
    let mut queue = h.queue(1, CallbackCtx{count: 0}).unwrap();
    queue.maxlen(1024).unwrap();
}
