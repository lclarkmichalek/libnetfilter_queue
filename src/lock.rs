use std::sync::{StaticMutex, MUTEX_INIT};

pub static NFQ_LOCK: StaticMutex = MUTEX_INIT;
