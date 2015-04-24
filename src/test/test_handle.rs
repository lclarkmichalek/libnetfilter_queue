use handle::*;
use error::*;

#[test]
fn create_handle() {
    let _h = Handle::new().unwrap();
}

#[test]
fn bind_unbind() {
    let mut h = Handle::new().unwrap();
    h.bind(ProtocolFamily::INET).unwrap();
    h.unbind(ProtocolFamily::INET).unwrap();
}
