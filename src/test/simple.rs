use super::super::verdict::{Verdict, VerdictHandler};
use super::super::message::Message;
use super::super::queue::CopyMode;
use super::super::handle::{Handle, ProtocolFamily};

struct Void;
struct Callback;
struct Decider;

impl PacketHandler<Void> for Callback {
    fn callback(&self, hq: *mut QueueHandle, message: Result<&Message, &Error>, _: &mut Void) -> i32 { -1 }
}

impl VerdictHandler<Void> for Decider {
    fn decide(&self, message: &Message, _: &mut Void) -> Verdict { panic!(); Verdict::Accept }
}

#[test]
fn bind() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode(CopyMode::None)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    handle.bind(ProtocolFamily::INET).ok().unwrap();
}

#[test]
#[should_panic]
fn decider() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode(CopyMode::None)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    handle.bind(ProtocolFamily::INET).ok().unwrap();
    handle.start(4096);
}

#[test]
fn callback() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode(CopyMode::None)
        .callback_and_finalize(Callback)
        .ok().unwrap();

    handle.bind(ProtocolFamily::INET).ok().unwrap();
    handle.start(4096);
}
