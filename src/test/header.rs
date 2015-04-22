use super::super::verdict::{Verdict, VerdictHandler};
use super::super::message::{Message, IPHeader};
use super::super::handle::{Handle, ProtocolFamily};

struct Void;
struct Callback;
struct Decider;

impl PacketHandler<Void> for Callback {
    fn callback(&self, hq: *mut QueueHandle, message: Result<&Message, &Error>, _: &mut Void) -> i32 {
        unsafe { Message.header.ip_header().ok().unwrap(); }
        -1
    }
}

impl VerdictHandler<Void> for Decider {
    fn decide(&self, message: &Message, _: &mut Void) -> Verdict {
        unsafe { Message.header.ip_header().ok().unwrap(); }
        panic!();
        Verdict::Accept
    }
}

#[test]
fn bind() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode_sized_to_payload::<IPHeader>()
        .decider_and_finalize(Decider)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET).ok().unwrap();
}

#[test]
#[should_panic]
fn decide() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode_sized_to_payload::<IPHeader>()
        .decider_and_finalize(Decider)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET).ok().unwrap();
    handle.start_sized_to_payload::<IPHeader>();
}

#[test]
fn callback() {
    let void = Void;
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(void)
        .copy_mode_sized_to_payload::<IPHeader>()
        .callback_and_finalize(Callback)
        .ok().unwrap();

    let _ = handle.bind(ProtocolFamily::INET6).ok().unwrap();
    handle.start_sized_to_payload::<IPHeader>();
}
