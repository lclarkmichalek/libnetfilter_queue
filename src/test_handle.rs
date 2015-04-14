use nfq::*;

#[test]
fn create_handle() {
    match NFQHandle::new() {
        Err(NFQError(err)) => panic!("{}", err),
        _ => ()
    }
}

#[test]
fn bind_unbind() {
    let mut h = match NFQHandle::new() {
        Err(NFQError(err)) => panic!("{}", err),
        Ok(h) => h
    };
    match h.bind(ProtoFamily::INET) {
        Err(NFQError(err)) => panic!("{}", err),
        _ => ()
    };
    match h.unbind(ProtoFamily::INET) {
        Err(NFQError(err)) => panic!("{}", err),
        _ => ()
    }
}
