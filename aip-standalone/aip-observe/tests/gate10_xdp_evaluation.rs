//! Gate 10 — XDP, evaluated against this host. **No library code in this
//! repository loads a BPF program**; everything below lives in this test
//! and exists to answer one question with measurement instead of
//! assertion:
//!
//! > Would this kernel accept and execute an XDP program that parses a
//! > frame the way the observation model would need, and what would that
//! > add to the evidence the `AF_PACKET` tap of Gate 2 already produces?
//!
//! # What this does
//!
//! It hand-assembles a 27-instruction XDP program that bounds-checks the
//! frame, matches IPv4/TCP, tests the SYN flag and increments a counter in
//! an array map, always returning `XDP_PASS`. It loads it with the `bpf`
//! syscall — so the in-kernel verifier is the judge, not a claim in a
//! document — and executes it with `BPF_PROG_TEST_RUN` against synthetic
//! frames, reading the map back to see what it observed.
//!
//! # What this deliberately does not do
//!
//! It never attaches the program to an interface. `BPF_PROG_TEST_RUN`
//! executes the program in the kernel against a supplied buffer and copies
//! the verdict back; nothing is in the path of any real packet, so no
//! frame can be delayed or dropped by this test. The only route out of
//! this host is `eth0`; attaching to a live NIC with no out-of-band path
//! is the kind of irreversible act the mandate's "dry-run first" exists to
//! prevent, and a dry run is what is warranted at this gate.
//!
//! A host without `CONFIG_BPF_SYSCALL`, without the privilege to load, or
//! with the syscall blocked reports that and returns: an unavailable
//! mechanism is recorded, never inferred away.

#![cfg(target_os = "linux")]

use std::io::Error;

// ─── bpf(2) ───

const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_PROG_LOAD: i32 = 5;
const BPF_PROG_TEST_RUN: i32 = 10;

const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_PROG_TYPE_XDP: u32 = 6;

/// `union bpf_attr` is a union, so every command's fields start at offset
/// 0. A zeroed buffer plus explicit writes avoids depending on a binding
/// crate for a layout the kernel documents.
#[repr(C, align(8))]
struct Attr([u8; 144]);

impl Attr {
    fn new() -> Self {
        Attr([0u8; 144])
    }
    fn u32_at(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn u64_at(&mut self, off: usize, v: u64) {
        self.0[off..off + 8].copy_from_slice(&v.to_ne_bytes());
    }
    fn read_u32(&self, off: usize) -> u32 {
        u32::from_ne_bytes(self.0[off..off + 4].try_into().unwrap())
    }
    fn call(&mut self, cmd: i32) -> Result<i64, Error> {
        // SAFETY: `bpf` takes a command, a pointer to a bpf_attr and its
        // size; the buffer is owned, aligned and large enough.
        let r = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                cmd as libc::c_long,
                self.0.as_mut_ptr() as *mut libc::c_void,
                self.0.len() as libc::c_ulong,
            )
        };
        if r < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(r)
        }
    }
}

struct Fd(i32);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from bpf(2) and is owned here.
        unsafe {
            libc::close(self.0);
        }
    }
}

// ─── instruction encoding ───

#[derive(Clone, Copy)]
#[repr(C)]
struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        regs: (src << 4) | (dst & 0x0f),
        off,
        imm,
    }
}

// Opcodes used below (linux/bpf_common.h, linux/bpf.h).
const MOV64_REG: u8 = 0xbf; // BPF_ALU64|BPF_MOV|BPF_X
const MOV64_IMM: u8 = 0xb7; // BPF_ALU64|BPF_MOV|BPF_K
const ADD64_IMM: u8 = 0x07; // BPF_ALU64|BPF_ADD|BPF_K
const AND64_IMM: u8 = 0x57; // BPF_ALU64|BPF_AND|BPF_K
const LDX_W: u8 = 0x61; // BPF_LDX|BPF_MEM|BPF_W
const LDX_H: u8 = 0x69;
const LDX_B: u8 = 0x71;
const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b; // BPF_STX|BPF_MEM|BPF_DW
const ST_W: u8 = 0x62; // BPF_ST|BPF_MEM|BPF_W
const JGT_REG: u8 = 0x2d; // BPF_JMP|BPF_JGT|BPF_X
const JNE_IMM: u8 = 0x55;
const JEQ_IMM: u8 = 0x15;
const CALL: u8 = 0x85;
const EXIT: u8 = 0x95;
const LD_IMM64: u8 = 0x18; // BPF_LD|BPF_DW|BPF_IMM (two slots)
const PSEUDO_MAP_FD: u8 = 1;

const XDP_PASS: u32 = 2;

/// The program. `r1` is `struct xdp_md*`: `data` at 0, `data_end` at 4.
/// Index 25 is the common `XDP_PASS` exit; every jump targets it, so no
/// path can return `XDP_DROP` even if this program were ever attached.
fn program(map_fd: i32) -> Vec<Insn> {
    let pass: i16 = 25;
    let to = |i: i16| pass - i - 1;
    vec![
        insn(MOV64_REG, 6, 1, 0, 0),                 // 0  r6 = ctx
        insn(LDX_W, 2, 6, 0, 0),                     // 1  r2 = data
        insn(LDX_W, 3, 6, 4, 0),                     // 2  r3 = data_end
        insn(MOV64_REG, 4, 2, 0, 0),                 // 3  r4 = data
        insn(ADD64_IMM, 4, 0, 0, 54),                // 4  r4 += eth+ip+tcp
        insn(JGT_REG, 4, 3, to(5), 0),               // 5  short frame → pass
        insn(LDX_H, 5, 2, 12, 0),                    // 6  eth proto
        insn(JNE_IMM, 5, 0, to(7), 8),               // 7  not IPv4 (0x0800 BE) → pass
        insn(LDX_B, 5, 2, 14, 0),                    // 8  version/ihl
        insn(JNE_IMM, 5, 0, to(9), 0x45),            // 9  not IPv4 ihl=5 → pass
        insn(LDX_B, 5, 2, 23, 0),                    // 10 protocol
        insn(JNE_IMM, 5, 0, to(11), 6),              // 11 not TCP → pass
        insn(LDX_B, 5, 2, 47, 0),                    // 12 tcp flags
        insn(AND64_IMM, 5, 0, 0, 2),                 // 13 SYN
        insn(JEQ_IMM, 5, 0, to(14), 0),              // 14 not SYN → pass
        insn(ST_W, 10, 0, -4, 0),                    // 15 key = 0 on the stack
        insn(LD_IMM64, 1, PSEUDO_MAP_FD, 0, map_fd), // 16
        insn(0, 0, 0, 0, 0),                         // 17 (second half)
        insn(MOV64_REG, 2, 10, 0, 0),                // 18 r2 = fp
        insn(ADD64_IMM, 2, 0, 0, -4),                // 19 r2 = &key
        insn(CALL, 0, 0, 0, 1),                      // 20 bpf_map_lookup_elem
        insn(JEQ_IMM, 0, 0, to(21), 0),              // 21 null → pass
        insn(LDX_DW, 1, 0, 0, 0),                    // 22 r1 = *counter
        insn(ADD64_IMM, 1, 0, 0, 1),                 // 23 r1 += 1
        insn(STX_DW, 0, 1, 0, 0),                    // 24 *counter = r1
        insn(MOV64_IMM, 0, 0, 0, XDP_PASS as i32),   // 25 PASS
        insn(EXIT, 0, 0, 0, 0),                      // 26
    ]
}

// ─── frames ───

/// Ethernet + IPv4 + TCP, 60 bytes. `syn` sets the SYN flag.
fn frame(syn: bool, protocol: u8) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    f[14] = 0x45; // version 4, ihl 5
    f[16..18].copy_from_slice(&46u16.to_be_bytes()); // total length
    f[22] = 64; // ttl
    f[23] = protocol;
    f[26..30].copy_from_slice(&[10, 0, 0, 1]);
    f[30..34].copy_from_slice(&[10, 0, 0, 2]);
    f[34..36].copy_from_slice(&40000u16.to_be_bytes()); // sport
    f[36..38].copy_from_slice(&443u16.to_be_bytes()); // dport
    f[46] = 5 << 4; // data offset
    f[47] = if syn { 0x02 } else { 0x10 }; // SYN or ACK
    f
}

// ─── the syscalls ───

fn map_create() -> Result<Fd, Error> {
    let mut a = Attr::new();
    a.u32_at(0, BPF_MAP_TYPE_ARRAY);
    a.u32_at(4, 4); // key_size
    a.u32_at(8, 8); // value_size
    a.u32_at(12, 1); // max_entries
    a.call(BPF_MAP_CREATE).map(|fd| Fd(fd as i32))
}

fn prog_load(insns: &[Insn], log: &mut [u8]) -> Result<Fd, Error> {
    let license = b"GPL\0";
    let mut a = Attr::new();
    a.u32_at(0, BPF_PROG_TYPE_XDP);
    a.u32_at(4, insns.len() as u32);
    a.u64_at(8, insns.as_ptr() as u64);
    a.u64_at(16, license.as_ptr() as u64);
    a.u32_at(24, 1); // log_level
    a.u32_at(28, log.len() as u32);
    a.u64_at(32, log.as_mut_ptr() as u64);
    a.call(BPF_PROG_LOAD).map(|fd| Fd(fd as i32))
}

fn map_get(map: &Fd) -> Result<u64, Error> {
    let key: u32 = 0;
    let mut value: u64 = 0;
    let mut a = Attr::new();
    a.u32_at(0, map.0 as u32);
    a.u64_at(8, &key as *const u32 as u64);
    a.u64_at(16, &mut value as *mut u64 as u64);
    a.call(BPF_MAP_LOOKUP_ELEM)?;
    Ok(value)
}

/// Execute the program against `data` in the kernel. Returns the XDP
/// verdict and the kernel's reported duration in nanoseconds.
fn test_run(prog: &Fd, data: &[u8], repeat: u32) -> Result<(u32, u32), Error> {
    let mut out = vec![0u8; data.len() + 256];
    let mut a = Attr::new();
    a.u32_at(0, prog.0 as u32); // prog_fd
    a.u32_at(8, data.len() as u32); // data_size_in
    a.u32_at(12, out.len() as u32); // data_size_out
    a.u64_at(16, data.as_ptr() as u64); // data_in
    a.u64_at(24, out.as_mut_ptr() as u64); // data_out
    a.u32_at(32, repeat); // repeat
    a.call(BPF_PROG_TEST_RUN)?;
    Ok((a.read_u32(4), a.read_u32(36))) // retval, duration
}

/// `Ok` when this host can load XDP at all; `Err` names why not.
fn probe() -> Result<(Fd, Fd), String> {
    let map = map_create().map_err(|e| format!("BPF_MAP_CREATE: {e}"))?;
    let mut log = vec![0u8; 16 * 1024];
    let prog = prog_load(&program(map.0), &mut log).map_err(|e| {
        let text = String::from_utf8_lossy(&log);
        let text = text.trim_end_matches('\0').trim();
        format!("BPF_PROG_LOAD: {e}\nverifier log:\n{text}")
    })?;
    Ok((map, prog))
}

// ═══ the evaluation ═══

#[test]
fn x10a_this_kernel_loads_and_executes_an_xdp_parser_without_attaching_it() {
    let (map, prog) = match probe() {
        Ok(v) => v,
        Err(why) => {
            eprintln!("Gate 10: XDP is UNAVAILABLE on this host: {why}");
            return;
        }
    };
    assert_eq!(map_get(&map).unwrap(), 0, "the counter starts at zero");

    // A TCP SYN: parsed, counted, passed.
    let (verdict, _) = test_run(&prog, &frame(true, 6), 1).expect("test run");
    assert_eq!(verdict, XDP_PASS, "the program returns XDP_PASS");
    assert_eq!(map_get(&map).unwrap(), 1, "the kernel executed the parser");

    // A TCP ACK, and a UDP datagram: passed, not counted.
    for f in [frame(false, 6), frame(true, 17)] {
        let (verdict, _) = test_run(&prog, &f, 1).expect("test run");
        assert_eq!(verdict, XDP_PASS);
    }
    assert_eq!(
        map_get(&map).unwrap(),
        1,
        "only the SYN was counted: the bounds-checked parser discriminates"
    );

    // A truncated frame takes the short-frame branch: no out-of-bounds
    // read is possible, because the verifier would not have loaded a
    // program in which one was.
    let (verdict, _) = test_run(&prog, &frame(true, 6)[..20], 1).expect("test run");
    assert_eq!(verdict, XDP_PASS);
    assert_eq!(map_get(&map).unwrap(), 1);

    // Repeat, so the number below is the kernel's own measurement of this
    // program rather than of one syscall.
    let (verdict, duration_ns) = test_run(&prog, &frame(true, 6), 1_000).expect("test run");
    assert_eq!(verdict, XDP_PASS);
    assert_eq!(map_get(&map).unwrap(), 1_001);
    eprintln!(
        "Gate 10: XDP AVAILABLE. 27 instructions, verifier accepted, \
         {duration_ns} ns/run over 1000 runs via BPF_PROG_TEST_RUN. \
         Nothing was attached to any interface."
    );
}

#[test]
fn x10b_the_verifier_is_the_judge_an_unsafe_program_is_refused() {
    // The same parser with the bounds check removed: it reads 54 bytes
    // into a packet whose length it never compared. A program like this
    // is exactly what a hand-written kernel data-path parser gets wrong,
    // and the kernel — not this test — rejects it.
    let Ok(map) = map_create() else {
        eprintln!("Gate 10: BPF unavailable on this host");
        return;
    };
    let mut unsafe_prog = program(map.0);
    unsafe_prog.remove(5); // the JGT data_end guard
    let mut log = vec![0u8; 16 * 1024];
    match prog_load(&unsafe_prog, &mut log) {
        Ok(_) => panic!(
            "the verifier accepted an unbounded packet read; log:\n{}",
            String::from_utf8_lossy(&log)
        ),
        Err(e) => {
            let text = String::from_utf8_lossy(&log);
            let text = text.trim_end_matches('\0').trim();
            assert_eq!(
                e.raw_os_error(),
                Some(libc::EACCES),
                "a rejected program is EACCES, not {e}"
            );
            assert!(
                text.contains("invalid access to packet"),
                "the verifier must name the unbounded packet read; log:\n{text}"
            );
            eprintln!(
                "Gate 10: the verifier refused the unguarded read: {}",
                text.lines()
                    .find(|l| l.contains("invalid access"))
                    .unwrap_or("")
            );
        }
    }
}
