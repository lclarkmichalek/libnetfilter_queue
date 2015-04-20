use std::sync::Mutex;

lazy_static! { pub static ref NFQ_LOCK: Mutex<()> = Mutex::new(()); }
