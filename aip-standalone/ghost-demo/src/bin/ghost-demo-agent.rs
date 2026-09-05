//! The controlled test agent. NOT_PRODUCTION_CAPABILITY.
//!
//! Usage:
//!   ghost-demo-agent <host:port>                 connect over TCP, say hello,
//!                                                then block on stdin until the
//!                                                parent closes it
//!   ghost-demo-agent --connect-close <host:port> connect, say hello, close the
//!                                                connection at once, then block
//!                                                on stdin (the connection is
//!                                                gone before anyone can poll it)
//!   ghost-demo-agent --idle                      block on stdin without connecting
//!
//! It holds no key, signs nothing and reports nothing about itself. The only
//! thing it does is (optionally) open one TCP connection and stay alive so an
//! independent observer can look at it.

use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let _held = match args.first().map(String::as_str) {
        Some("--idle") => None,
        Some("--connect-close") => {
            let mut s = TcpStream::connect(&args[1]).expect("connect");
            s.write_all(b"ghost-demo-agent connected\n").expect("hello");
            drop(s);
            None
        }
        Some(addr) => {
            let mut s = TcpStream::connect(addr).expect("connect");
            s.write_all(b"ghost-demo-agent connected\n").expect("hello");
            Some(s)
        }
        None => None,
    };
    // Block until the parent closes our stdin (or kills us).
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}
