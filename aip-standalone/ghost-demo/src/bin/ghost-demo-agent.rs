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
//!   ghost-demo-agent --spawn <path> [args...]    spawn a child process running
//!                                                <path>, print "spawned <pid>",
//!                                                block on stdin, then kill it
//!   ghost-demo-agent --idle                      block on stdin without connecting
//!   ghost-demo-agent --write <path>              write one line to <path>, close
//!                                                it, print "wrote <path>", block
//!                                                on stdin
//!
//! It holds no key, signs nothing and reports nothing about itself. The only
//! thing it does is (optionally) open one TCP connection and stay alive so an
//! independent observer can look at it.

use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--spawn") {
        let mut child = std::process::Command::new(&args[1])
            .args(&args[2..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn child");
        println!("spawned {}", child.id());
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    if args.first().map(String::as_str) == Some("--write") {
        // Write one line to the path, close it (a completed write), report,
        // then stay alive so an observer can bind the instance.
        std::fs::write(&args[1], b"ghost-demo-agent wrote\n").expect("write");
        println!("wrote {}", args[1]);
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        return;
    }
    let _held = match args.first().map(String::as_str) {
        Some("--idle") => {
            // Synchronization only: the parent independently measures every
            // identity field through procfs after this message. It is never
            // signed evidence or an identity assertion.
            println!("ghost-demo-agent idle");
            std::io::stdout().flush().expect("idle readiness");
            None
        }
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
