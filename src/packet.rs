//! Packet handling

use libc::*;
use error::*;
use message::Message;

use ffi::*;

struct Packet {

