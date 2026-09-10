#!/usr/bin/env python3
"""Independent execution observer: the Linux audit subsystem.

WHY THIS EXISTS
---------------
The prior independence analysis (`validation/linux/INDEPENDENCE.md`) concluded
that no instrument available in this environment observes process execution
through a mechanism Sniffer Dog does not already use, because Tetragon is
blocked by `# CONFIG_KPROBES is not set`.

That conclusion was correct about Tetragon and incomplete about the kernel.
This kernel is built with `CONFIG_AUDIT=y` and `CONFIG_AUDITSYSCALL=y`, and the
audit subsystem answers on `NETLINK_AUDIT`. Verified, not assumed: see
`validation/airi/OBSERVER_INDEPENDENCE.md` for the probe transcript.

MECHANISM, AND WHY IT IS DIFFERENT
----------------------------------
    Sniffer Dog (exec)   sched:sched_process_exec tracepoint
                         -> perf_event_open(PERF_TYPE_TRACEPOINT)
                         -> per-CPU ring buffer
                         -> aip-observe's own binary record decoder

    This observer        audit_syscall_entry/exit hooks on the syscall path
                         -> kernel/auditsc.c record assembly
                         -> NETLINK_AUDIT unicast to one registered consumer
                         -> kernel-formatted text

Different probe site, different kernel subsystem, different delivery path,
different record format, different decoder. For process execution this is
**mechanism independence**, which the tracepoint-based ftrace reader is not.

WHAT THIS PROGRAM DOES NOT DO
-----------------------------
It does not parse semantics, score anything, or decide anything. It copies
kernel-formatted records to a file with a receive timestamp. Every field in the
output is text the kernel produced. That is deliberate: an observer whose
author also wrote the subject is only credible to the extent that it renders
nothing of its own.

LIMITS — read these before citing any result derived from this
--------------------------------------------------------------
1. The audit subsystem delivers to **exactly one** registered consumer pid. If
   anything else on the host is consuming audit, this observer cannot run, and
   this program refuses rather than fighting for the socket.
2. Enabling audit is **global host state**. This program records the prior
   state and restores it on exit, including on signal.
3. Root can disable audit, exactly as root can disable tracepoints. This is not
   a root-compromise-resistant witness and must never be described as one.
4. A kernel-level compromise defeats this and Sniffer Dog identically.
5. Audit's execve record is emitted at syscall **exit**; the sched tracepoint
   fires at a different point in the same syscall. The two therefore carry
   different timestamps for one event. That is expected and is not a
   disagreement.
"""
import argparse
import json
import os
import re
import signal
import socket
import struct
import sys
import time

NETLINK_AUDIT = 9
AUDIT_GET, AUDIT_SET = 1000, 1001
AUDIT_ADD_RULE, AUDIT_DEL_RULE, AUDIT_LIST_RULES = 1011, 1012, 1013
NLMSG_DONE = 3
NLM_F_REQUEST, NLM_F_ACK = 1, 4
STATUS_ENABLED, STATUS_PID = 0x0001, 0x0004

# 0x02 is the ENTRY filter, removed from the kernel years ago; supplying it
# returns EINVAL. EXIT is 0x04.
AUDIT_FILTER_EXIT = 0x04
AUDIT_ALWAYS = 2
FIELD_ARCH = 11
OP_EQUAL = 0x40000000          # operators live in the top nibble of fieldflags
ARCH_X86_64 = 0xC000003E
MAX_FIELDS = 64

# Bounded retries for the global-state enable. See `start`.
ENABLE_ATTEMPTS = 10

# Record types we ask for by name in the output. The kernel emits many more and
# all of them are written out verbatim; these are only for the summary line.
TYPE_NAMES = {
    1300: "SYSCALL", 1302: "PATH", 1305: "CONFIG_CHANGE", 1307: "CWD",
    1309: "EXECVE", 1320: "EOE", 1321: "UNKNOWN_1321", 1327: "PROCTITLE",
}

# x86_64 syscall numbers this observer watches.
SYSCALLS = {"execve": 59, "execveat": 322, "connect": 42, "openat": 257}


class AuditObserver:
    def __init__(self, syscalls, out_path):
        self.syscalls = syscalls
        self.out_path = out_path
        self.sock = None
        self.prior = None
        self.rules = []
        self.prior_rules = []
        self.seq = 0

    # ── netlink plumbing ────────────────────────────────────────────────
    def _send(self, typ, payload, flags=NLM_F_REQUEST | NLM_F_ACK):
        self.seq += 1
        hdr = struct.pack("=IHHII", 16 + len(payload), typ, flags, self.seq, 0)
        self.sock.send(hdr + payload)

    def _ack(self, timeout=3):
        """The error code for the request just sent, or None on timeout.

        Audit delivers EVENT RECORDS on the same socket as command replies, and
        a command of ours (enabling audit, adding a rule) generates records of
        its own. Reading a single message and treating whatever arrives as the
        ack therefore misreads an event record as success — which is how three
        rules came to be recorded as installed while the kernel held none.
        The reply is matched on the netlink sequence number instead, and
        anything else is skipped.
        """
        want = self.seq
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                return None
            _, typ, _, seq, _ = struct.unpack("=IHHII", data[:16])
            if typ == 2 and seq == want:          # NLMSG_ERROR carries the code
                return struct.unpack("=i", data[16:20])[0]
        return None

    def _status(self):
        self._send(AUDIT_GET, b"", NLM_F_REQUEST)
        self.sock.settimeout(3)
        for _ in range(8):
            try:
                data = self.sock.recv(8192)
            except socket.timeout:
                return None
            _, typ, _, _, _ = struct.unpack("=IHHII", data[:16])
            if typ == AUDIT_GET:
                return struct.unpack("=8I", data[16:48])
        return None

    def _set_status(self, mask, enabled=0, pid=0):
        self._send(AUDIT_SET, struct.pack("=8I", mask, enabled, 0, pid, 0, 0, 0, 0))
        return self._ack()

    def _list_rules(self, timeout=3):
        """Every rule currently loaded in the kernel, as raw blobs.

        Audit rules are GLOBAL and persist beyond the process that added them.
        An observer killed with SIGKILL — which the observation-loss scenario
        does deliberately — never runs its own cleanup, so its rules stay
        loaded. A later run then captures through rules it did not install and
        cannot account for, and its result no longer depends on its own
        configuration. That is how mutation M-OBS-5 survived: an observer asked
        to watch only `openat` still received `execve` records, from a leaked
        rule, and the scenario passed while testing nothing.
        """
        self._send(AUDIT_LIST_RULES, b"", NLM_F_REQUEST)
        want = self.seq
        deadline = time.time() + timeout
        rules = []
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                break
            ln = struct.unpack("=I", data[:4])[0]
            typ, seq = struct.unpack("=HxxI", data[4:12])
            if seq != want:                       # an interleaved event record
                continue
            if typ in (NLMSG_DONE, 2):
                break
            if typ == AUDIT_LIST_RULES:
                body = data[16:] if ln == len(data) - 16 else data[16:ln]
                rules.append(body)
        return rules

    def _rule(self, syscall_nr):
        """`-a always,exit -F arch=b64 -S <call>` as an audit_rule_data blob."""
        mask = [0] * MAX_FIELDS
        mask[syscall_nr // 32] |= 1 << (syscall_nr % 32)
        blob = struct.pack("=3I", AUDIT_FILTER_EXIT, AUDIT_ALWAYS, 1)
        blob += struct.pack("=%dI" % MAX_FIELDS, *mask)
        blob += struct.pack("=%dI" % MAX_FIELDS, *([FIELD_ARCH] + [0] * (MAX_FIELDS - 1)))
        blob += struct.pack("=%dI" % MAX_FIELDS, *([ARCH_X86_64] + [0] * (MAX_FIELDS - 1)))
        blob += struct.pack("=%dI" % MAX_FIELDS, *([OP_EQUAL] + [0] * (MAX_FIELDS - 1)))
        blob += struct.pack("=I", 0)
        return blob

    # ── lifecycle ───────────────────────────────────────────────────────
    def start(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
        self.sock.bind((0, 0))
        self.prior = self._status()
        if self.prior is None:
            raise SystemExit("AUDIT_UNAVAILABLE: no reply to AUDIT_GET")
        _, enabled, _, pid = self.prior[:4]
        if pid not in (0, os.getpid()):
            # Refuse rather than steal the socket. Only one consumer exists.
            raise SystemExit(
                f"AUDIT_CONSUMER_BUSY: pid {pid} already registered; "
                "this observer will not contend for the audit socket"
            )
        if self._set_status(STATUS_PID, pid=os.getpid()) != 0:
            raise SystemExit("AUDIT_REGISTER_FAILED")
        # Enabling audit is GLOBAL host state, and a previous observer restoring
        # the prior `enabled` value can land between this enable and its
        # verification — an observed race between back-to-back runs. The enable
        # is therefore re-asserted until the kernel confirms it, a bounded
        # number of times. Bounded, not unbounded: an observer that cannot
        # confirm it is enabled must refuse to run rather than record a stream
        # it cannot vouch for.
        enabled = False
        for _ in range(ENABLE_ATTEMPTS):
            if self._set_status(STATUS_ENABLED, enabled=1) != 0:
                continue
            now = self._status()
            if now and now[1] == 1:
                enabled = True
                break
        if not enabled:
            self.stop()
            raise SystemExit("AUDIT_NOT_ENABLED")
        # Clear the global rule set before installing ours, so what this
        # observer records depends on what this observer asked for and on
        # nothing else. Removed rules are counted and reported; they are not
        # restored, because a leaked rule is not a configuration worth
        # preserving and silently reinstating one would recreate the defect.
        self.prior_rules = self._list_rules()
        for blob in self.prior_rules:
            self._send(AUDIT_DEL_RULE, blob)
            self._ack(timeout=1)
        leftover = self._list_rules()
        if leftover:
            self.stop()
            raise SystemExit(
                f"AUDIT_RULES_NOT_CLEARED: {len(leftover)} rule(s) remain; "
                "refusing to record through a rule set this observer does not "
                "control"
            )
        for name in self.syscalls:
            blob = self._rule(SYSCALLS[name])
            self._send(AUDIT_ADD_RULE, blob)
            err = self._ack()
            if err == 0:
                self.rules.append(blob)
            else:
                sys.stderr.write(
                    f"audit_observer: rule for {name} refused (errno={-err if err else 'timeout'})\n"
                )
        if not self.rules:
            self.stop()
            raise SystemExit("AUDIT_NO_RULES_INSTALLED")
        # Verify by asking the kernel, not by trusting the acks.
        loaded = self._list_rules()
        if len(loaded) != len(self.rules):
            self.stop()
            raise SystemExit(
                f"AUDIT_RULE_SET_UNEXPECTED: asked for {len(self.rules)}, "
                f"kernel reports {len(loaded)}"
            )

    def stop(self):
        try:
            for blob in self.rules:
                self._send(AUDIT_DEL_RULE, blob)
                self._ack(timeout=1)
            self._set_status(STATUS_PID, pid=0)
            if self.prior:
                self._set_status(STATUS_ENABLED, enabled=self.prior[1])
        except Exception as exc:              # restoration is best effort, and loud
            sys.stderr.write(f"audit_observer: restore failed: {exc}\n")

    @staticmethod
    def _payload(data):
        """Return one audit record's text from a raw netlink datagram.

        The audit subsystem does not follow the usual netlink length
        convention. `audit_make_reply()` sets `nlmsg_len` to the size of the
        *payload*, not to `NLMSG_HDRLEN + payload` as every other netlink
        family does. libaudit works around this; so must we.

        Reading it the usual way (`data[16:nlmsg_len]`) silently drops the last
        16 bytes of every record. That is not a cosmetic defect: it truncates
        the hex-encoded tail of an EXECVE argument, which is precisely where a
        run nonce lives. A truncated argv would then fail to match a declared
        tool and the harness would report a non-execution that did not happen —
        the exact class of manufactured false failure this programme forbids.

        Both conventions are handled, and which one applied is recorded, so a
        future kernel changing this cannot fail silently.
        """
        ln = struct.unpack("=I", data[:4])[0]
        avail = len(data) - 16
        if ln == avail:
            body, conv = data[16:], "payload"      # audit's convention
        elif 16 <= ln <= len(data):
            body, conv = data[16:ln], "header"     # generic netlink convention
        else:
            body, conv = data[16:], "unknown"
        return body.decode("utf-8", "replace").rstrip("\x00\n"), ln, avail, conv

    @staticmethod
    def _searchable(body):
        """A marker-matching view of a record. Never written to the output.

        The kernel hex-encodes any `execve` argument containing a character it
        will not print, so a marker the harness executes arrives as hex. To
        stop on it the observer has to look through that encoding. It decodes
        for the stop decision only: `kernel_record` in the output stays exactly
        the bytes the kernel produced.
        """
        parts = [body]
        for run in re.findall(r"(?<![0-9A-Za-z])([0-9A-F]{16,})(?![0-9A-Za-z])", body):
            if len(run) % 2:
                continue
            try:
                parts.append(bytes.fromhex(run).decode("utf-8", "replace"))
            except ValueError:
                continue
        return "\n".join(parts)

    def run(self, until_marker, max_seconds, stall_after="", stall_ms=0):
        """Copy records until `until_marker` is seen in one, or time runs out.

        The marker is how the harness closes the observation window from
        inside the audit stream itself, rather than by wall-clock guessing —
        see PHASE 9 of the mandate and `run_airi_validation.sh`.
        """
        deadline = time.time() + max_seconds
        counts = {}
        stalled = False
        with open(self.out_path, "w") as out:
            out.write(json.dumps({
                "observer": "linux-audit",
                "mechanism": "audit_syscall hooks -> NETLINK_AUDIT",
                "independent_of_sniffer_dog": "mechanism",
                "syscalls": sorted(self.syscalls),
                "observer_pid": os.getpid(),
                "rules_installed": len(self.rules),
                "leaked_rules_removed_at_start": len(self.prior_rules),
                "started_unix_ns": time.time_ns(),
                "record": "observer_ready",
            }) + "\n")
            out.flush()
            self.sock.settimeout(1.0)
            while time.time() < deadline:
                try:
                    data = self.sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                typ = struct.unpack("=H", data[4:6])[0]
                body, ln, avail, conv = self._payload(data)
                counts[typ] = counts.get(typ, 0) + 1
                out.write(json.dumps({
                    "received_unix_ns": time.time_ns(),
                    "type": typ,
                    "type_name": TYPE_NAMES.get(typ, str(typ)),
                    "nlmsg_len": ln,
                    "datagram_payload_len": avail,
                    "length_convention": conv,
                    "kernel_record": body,
                }) + "\n")
                out.flush()
                if stall_after and not stalled and stall_after in self._searchable(body):
                    # Deliberate delivery delay, for the scenario that tests
                    # whether anything downstream orders events by RECEIVE time.
                    # Records queue in the socket buffer meanwhile; netlink
                    # preserves their order, so the stream is late, not wrong.
                    stalled = True
                    out.write(json.dumps({
                        "record": "observer_stalled",
                        "stall_ms": stall_ms,
                        "at_unix_ns": time.time_ns(),
                    }) + "\n")
                    out.flush()
                    time.sleep(stall_ms / 1000.0)
                if until_marker and until_marker in self._searchable(body):
                    break
            out.write(json.dumps({
                "record": "observer_stopped",
                "stopped_unix_ns": time.time_ns(),
                "counts_by_type": {TYPE_NAMES.get(k, str(k)): v for k, v in counts.items()},
            }) + "\n")
        return counts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--syscalls", default="execve,execveat,connect")
    ap.add_argument("--until-marker", default="")
    ap.add_argument("--max-seconds", type=float, default=120.0)
    ap.add_argument("--ready-file", default="")
    ap.add_argument("--stall-after", default="",
                    help="pause the receive loop once, after a record matching "
                         "this text; the delivery delay is the point")
    ap.add_argument("--stall-ms", type=float, default=0.0)
    args = ap.parse_args()

    calls = [c.strip() for c in args.syscalls.split(",") if c.strip()]
    unknown = [c for c in calls if c not in SYSCALLS]
    if unknown:
        raise SystemExit(f"unknown syscall name(s): {unknown}")

    obs = AuditObserver(calls, args.out)

    def bail(signum, frame):
        obs.stop()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, bail)
    signal.signal(signal.SIGINT, bail)

    obs.start()
    if args.ready_file:
        with open(args.ready_file, "w") as f:
            f.write(str(os.getpid()))
    try:
        counts = obs.run(args.until_marker, args.max_seconds,
                         args.stall_after, args.stall_ms)
    finally:
        obs.stop()
    sys.stderr.write(f"audit_observer: {sum(counts.values())} records\n")


if __name__ == "__main__":
    main()
