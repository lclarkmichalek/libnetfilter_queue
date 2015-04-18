use handle::*;
use queue::*;
use error::*;

struct CallbackCtx {
    count: u64
}

fn callback(ctx: &mut CallbackCtx, msg: &NFGenMsg, ad: &NFQData) -> i32 {
    ctx.count += 1;
    0
}

#[test]
fn create_queue() {
    let mut h = NFQHandle::new().unwrap();
    h.bind(ProtoFamily::INET).unwrap();
    let queue = h.queue(1, CallbackCtx{count: 0}, callback).unwrap();
}

#[test]
fn set_mode() {
    let mut h = NFQHandle::new().unwrap();
    h.bind(ProtoFamily::INET).unwrap();
    let mut queue = h.queue(1, CallbackCtx{count: 0}, callback).unwrap();
    queue.mode(CopyMode::Packet(1024)).unwrap();
}

#[test]
fn set_maxlen() {
    let mut h = NFQHandle::new().unwrap();
    h.bind(ProtoFamily::INET).unwrap();
    let mut queue = h.queue(1, CallbackCtx{count: 0}, callback).unwrap();
    queue.queue_maxlen(1024).unwrap();
}
