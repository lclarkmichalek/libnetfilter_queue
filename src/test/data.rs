use super::super::verdict::{Verdict, VerdictHandler};
use super::super::message::Message;
use super::super::queue::CopyMode;
use super::super::handle::{Handle, ProtocolFamily};

struct Data(u32);
struct Callback;
struct Decider;

impl PacketHandler<Data> for Callback {
    fn callback(&self, hq: *mut QueueHandle, message: Result<&Message, &Error>, data: &mut Data) -> i32 {
        match data {
            Data(42) => -1,
            _ => panic!()
        }
    }
}

impl VerdictHandler<Data> for Decider {
    fn decide(&self, message: &Message, data: &mut Data) -> Verdict {
        match data {
            Data(42) => panic!(),
            Verdict::Accept
        }
    }
}

#[test]
fn bind() {
    let data = Data(42);
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(data)
        .copy_mode(CopyMode::None)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    handle.bind(ProtocolFamily::INET).ok().unwrap();
}

#[test]
#[should_panic]
fn decider() {
    let data = Data(42);
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(data)
        .copy_mode(CopyMode::None)
        .decider_and_finalize(Decider)
        .ok().unwrap();

    handle.bind(ProtocolFamily::INET).ok().unwrap();
    handle.start(4096);
}

#[test]
fn callback() {
    let data = Data(42);
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.queue_builder(data)
        .copy_mode(CopyMode::None)
        .callback_and_finalize(Callback)
        .ok().unwrap();

    handle.bind(ProtocolFamily::INET).ok().unwrap();
    handle.start(4096);
}
