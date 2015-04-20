use handle::*;
use error::*;

#[test]
fn create_handle() {
    let _h = NFQHandle::new().unwrap();
}

#[test]
fn bind_unbind() {
    let mut h = NFQHandle::new().unwrap();
    h.bind(ProtoFamily::INET).unwrap();
    h.unbind(ProtoFamily::INET).unwrap();
}
