//! The controlled test agent. NOT_PRODUCTION_CAPABILITY.
//!
//! Usage:
//!   ghost-demo-agent <host:port>   connect over TCP, say hello, then block
//!                                  on stdin until the parent closes it
//!   ghost-demo-agent --idle        block on stdin without connecting
//!
//! It holds no key, signs nothing and reports nothing about itself. The only
//! thing it does is (optionally) open one TCP connection and stay alive so an
//! independent observer can look at it.

use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let _held = if arg == "--idle" {
        None
    } else {
        let mut s = TcpStream::connect(&arg).expect("connect");
        s.write_all(b"ghost-demo-agent connected\n").expect("hello");
        Some(s)
    };
    // Block until the parent closes our stdin (or kills us).
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}
