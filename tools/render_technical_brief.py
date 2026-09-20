#!/usr/bin/env python3
"""Render the Sniffer Dog / AIP technical brief for the RBI FinTech Department.

Why this exists
---------------
Revision 2 of this brief was exported by hand and lives outside the
repository, so it drifted behind the code it describes. By the time it was
next read, seven of its eleven stated pre-production blockers had changed
status and two of its capability statements were simply wrong -- it said the
pilot probe does not drive fanotify or AF_PACKET, and it listed external log
anchoring as not done. A brief that understates what exists is less dangerous
than one that overstates it, but both are defects in a document handed to a
supervisor. This makes the brief a build product of the repository.

Editorial rules this file follows
---------------------------------
1. Nothing is claimed here that the repository does not contain. Every
   changed line in Revision 3 was checked against the code and its tests
   before being written.
2. Where a capability is complete in code but incomplete in a deployment,
   both halves are said. "Done" that quietly means "done except for the part
   the institution must do" is the failure this whole system exists to
   prevent, and it would be self-refuting here.
3. Limitations carried forward from Revision 2 are carried forward verbatim
   unless the repository actually changed. Deleting an inconvenient
   limitation is how briefs become marketing.

Usage:  python3 tools/render_technical_brief.py [output.pdf]
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "docs" / "pilot" / "SNIFFER_DOG_TECHNICAL_BRIEF_RBI.pdf"

REVISION = "Revision 3"
PERIOD = "September 2026"
RUNNING = (
    "VANIAN Technologies  |  Sniffer Dog / AIP: Technical Brief  |  "
    f"{PERIOD}  |  For technical evaluation. Not a commercial offer."
)

INK = colors.HexColor("#111111")
MUTED = colors.HexColor("#555555")
RULE = colors.HexColor("#bfbfbf")
HEAD_BG = colors.HexColor("#e9eef4")
ACCENT = colors.HexColor("#14304f")


def git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return "unknown"


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=19, leading=23,
                                textColor=ACCENT, alignment=0, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=10.5, leading=14,
                              textColor=MUTED, spaceAfter=2),
        "meta": ParagraphStyle("m", parent=base["Normal"], fontSize=8.6, leading=12,
                               textColor=MUTED, spaceAfter=10),
        "h1": ParagraphStyle("h1", parent=base["Heading2"], fontSize=12.5, leading=15.5,
                             textColor=ACCENT, spaceBefore=12, spaceAfter=5),
        "h2": ParagraphStyle("h2", parent=base["Heading3"], fontSize=10.2, leading=13,
                             textColor=INK, spaceBefore=8, spaceAfter=4),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=8.9, leading=12.4,
                            textColor=INK, spaceAfter=5),
        "bul": ParagraphStyle("b", parent=base["Normal"], fontSize=8.9, leading=12.4,
                              textColor=INK, leftIndent=9, spaceAfter=4),
        "th": ParagraphStyle("th", parent=base["Normal"], fontSize=8.1, leading=10.5,
                             textColor=ACCENT),
        "td": ParagraphStyle("td", parent=base["Normal"], fontSize=8.0, leading=10.6,
                             textColor=INK),
        "note": ParagraphStyle("n", parent=base["Normal"], fontSize=8.0, leading=11,
                               textColor=MUTED, spaceAfter=5),
    }


def content(st, width):
    """The brief, as a list of flowables. Text is the deliverable here."""
    P = lambda s: Paragraph(s, st["p"])            # noqa: E731
    B = lambda s: Paragraph(f"•&nbsp; {s}", st["bul"])  # noqa: E731
    H = lambda s: Paragraph(s, st["h1"])           # noqa: E731
    N = lambda s: Paragraph(s, st["note"])         # noqa: E731

    def table(headers, rows, widths):
        data = [[Paragraph(f"<b>{h}</b>", st["th"]) for h in headers]]
        data += [[Paragraph(c, st["td"]) for c in r] for r in rows]
        t = Table(data, colWidths=[w * width for w in widths], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, RULE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    s = []

    # ── Masthead ────────────────────────────────────────────────────────────
    s.append(Paragraph("Sniffer Dog / AIP: Technical Brief", st["title"]))
    s.append(Paragraph(
        "Independent runtime observation and accountability for autonomous AI "
        "in financial systems", st["sub"]))
    s.append(Paragraph(
        "VANIAN Technologies&nbsp; |&nbsp; Prepared for the Reserve Bank of India, "
        f"FinTech Department&nbsp; |&nbsp; {PERIOD}, {REVISION}", st["meta"]))

    # ── 1 ───────────────────────────────────────────────────────────────────
    s.append(H("1. The question this system answers"))
    s.append(P(
        "When an AI agent executes a consequential action inside a regulated entity, "
        "today the only account of what happened is the agent's own: its logs, its "
        "explanation, its self-report. Sniffer Dog exists to produce a second, "
        "independent account, and to compare the two."))
    s.append(P(
        "For every action it answers: what was authorised (signed before the act by an "
        "authority that is not the agent, naming the action, the parameters and the "
        "institutional resource), what actually executed (recorded from the kernel by an "
        "observer that is not the agent and does not trust the agent), what the "
        "institution's own systems received (countersigned by the tool gateway in front "
        "of them), and whether they match. Every record is signed and can be verified "
        "offline by the institution's auditor or by the supervisor, using keys the "
        "institution holds. No step depends on trusting VANIAN."))
    s.append(P(
        "<b>The design principle that governs everything below: absence of evidence is "
        "never converted into an accusation.</b> When the observer was not watching, or "
        "was interfered with, or no gateway receipt exists, the system says so and stops. "
        "It does not guess."))
    s.append(P(
        "<b>What changed since Revision 2.</b> The probe-to-collector link is now "
        "confidential as well as authenticated; the pilot probe drives the file and wire "
        "sensors that were previously demonstrator-only; the observer records container "
        "placement independently rather than taking the authorising side's word for it; "
        "signing keys can live in a PKCS#11 module instead of a wrapped file; log heads "
        "are countersigned by an external witness; the evidence store's controls are "
        "backed by an exercised restore; and the adversarial ledger is reproducible by a "
        "single command. Seven of the eleven pre-production blockers in section 13 have "
        "moved. The hard gate that has not moved is the run on the institution's own "
        "hardware, and it is stated as plainly here as it was before."))

    # ── 2 ───────────────────────────────────────────────────────────────────
    s.append(H("2. Independent authorities"))
    s.append(P(
        "The security argument rests on separation. Each component holds its own signing "
        "key, generated where it runs, and none can produce another's artefact. The first "
        "three form the accountability core; the rest attach to it without being able to "
        "move a verdict."))
    s.append(table(
        ["Authority", "Produces", "Key custody", "Cannot do"],
        [
            ["Decision point",
             "Signed <i>ExpectedExecution</i> before the act, naming action, parameter "
             "commitment and institutional resource; and coverage statements from its own "
             "ledger.",
             "Its own key, separate from the agent's.",
             "Cannot observe. Cannot issue a decision into a window it has already "
             "declared closed."],
            ["Observer / collector",
             "Signed <i>AttestedBatch</i> of kernel-recorded observations, sequence and "
             "chain head, signed health including integrity state.",
             "The only evidence-signing key, on the collector host. Wrapped at rest "
             "(argon2 + XChaCha20-Poly1305), or held in a PKCS#11 module where the private "
             "key is generated inside the module and never leaves it.",
             "Cannot authorise. Cannot mint coverage it did not have; a key holder can "
             "relabel state but not manufacture the coverage a claim needs."],
            ["Reconciler",
             "Signed verdict with reason code and evidence grade, committable to an "
             "append-only log.",
             "Its own key; a fourth authority.",
             "Cannot observe or authorise. Cannot raise evidence strength."],
            ["Tool gateway",
             "Signed <i>ToolReceipt</i>: what request the institution's API or MCP gateway "
             "actually received, as a commitment over the arguments, under which decision, "
             "and what the gateway did with it.",
             "The gateway's own key, operated by the institution.",
             "Cannot be the agent: a gateway anchored under the agent's key is refused."],
            ["External witness",
             "Countersigned receipt over a NEXORA log head, from a system the log operator "
             "does not control.",
             "Its own key, held by the regulated entity or a third party.",
             "Cannot alter the log. An operator who rewrites history can still sign the new "
             "head, but cannot produce a witness receipt for the head they discarded."],
            ["Approval surface, epoch issuer, interlock board",
             "Signed record of what a human was shown; signed capability epoch the enforcer "
             "admits; signed heartbeat the interlock requires.",
             "Each its own key.",
             "None can produce a verdict, raise evidence strength, or make containment "
             "reachable. Each is compared against, never merged into, the core."],
        ],
        [0.15, 0.30, 0.25, 0.30]))

    # ── 3 ───────────────────────────────────────────────────────────────────
    s.append(H("3. Deployment topology"))
    s.append(P(
        "The trust boundary is the deployment. Two boundaries carry the argument and must "
        "be enforced in the institution's environment, not assumed:"))
    s.append(B(
        "<b>Key custody boundary.</b> The evidence-signing key is generated on the "
        "collector host and never leaves it; where a hardware module is used it is "
        "generated inside the module, marked non-extractable, and the host only ever sends "
        "32 bytes and receives a signature. The probe on the observed host has no key and "
        "no signing method. The gateway key lives at the gateway, the registry key with the "
        "institution's infrastructure owner, the witness key on a system the log operator "
        "does not control."))
    s.append(B(
        "<b>Evidence boundary.</b> Independent open-source observers (auditd, Tetragon) are "
        "compared against VANIAN's account and never consumed by it. An instrument the "
        "system consumed would become part of the system and the comparison would stop "
        "being a comparison."))
    s.append(Preformatted(
        "  INSTITUTION AGENT HOST (attacker-reachable)      SEPARATE COLLECTOR HOST (institution-controlled)\n"
        "  -------------------------------------------      -----------------------------------------------\n"
        "  agent workload (the subject)                     aip-collector\n"
        "    . AIRI: agent-signed claims of what it            . holds the ONLY evidence-signing key: wrapped\n"
        "      asked each tool to do (commitments only)          at rest, or non-extractable in a PKCS#11 module\n"
        "  aip-probe                                          . refuses to start on an undisciplined clock\n"
        "    . perf tracepoints: process fork/exec,           . assigns sequence number and chain head\n"
        "      TCP state, TCP send                            . enforces continuity ledger\n"
        "    . netlink process connector (fork/exec/exit,     . absorbs the probe's integrity findings,\n"
        "      gate-independent)                                fail-closed\n"
        "    . fanotify file events (gate-independent)        . signs -> AttestedBatch\n"
        "    . AF_PACKET header tap (gate-independent)        . publishes signed health\n"
        "    . pidfd-anchored /proc reads, container ns\n"
        "    . per-sensor integrity finding in every batch\n"
        "    . HOLDS NO KEY\n"
        "    |  ObservationBatch (unsigned)                                 |\n"
        "    +--- authenticated AND confidential transport ---------------> |\n"
        "         (ed25519 frames inside Noise_NK_25519_ChaChaPoly_SHA256)  v\n"
        "  TOOL GATEWAY (institution's API / MCP gateway)   aip-reconcile\n"
        "    . recomputes the commitment over the request      ExpectedExecution  JOIN  ObservedExecution\n"
        "      it actually received; signs a ToolReceipt       on decision_id + ExecutionBinding\n"
        "    . its own key; refused if it is the agent's                    |\n"
        "                                                                   v\n"
        "  DECISION POINT (separate key)                    aip-ledger      per-agent access ledger, rows named\n"
        "    . signs ExpectedExecution before the act          by the institution's signed resource registry,\n"
        "    . resolves destinations against the signed        each row citing the signed verdict; fifth key\n"
        "      resource registry; refuses unregistered                      |\n"
        "      or ungranted resources                                       v\n"
        "    . records every decision in a coverage ledger  aip-nexora      append-only commitment log\n"
        "                                                                   |\n"
        "  INDEPENDENT CROSS-CHECK (never fed into Vanian)   EXTERNAL WITNESS (entity-controlled, own key)\n"
        "  auditd (NETLINK_AUDIT), Tetragon (kprobes)         countersigns log heads                       \n"
        "    compared AGAINST Vanian's account                             v\n"
        "                                                   aip-verify / nexora-verify\n"
        "                                                     (auditor / regulator, OFFLINE, own keys)",
        ParagraphStyle("pre", fontName="Courier", fontSize=5.6, leading=6.9,
                       textColor=INK)))


    # ── 4 ───────────────────────────────────────────────────────────────────
    s.append(H("4. What is observed, and what is deliberately not"))
    s.append(P(
        "Observation is from the kernel, out of band of the agent process, using Linux "
        "perf tracepoints, the process-event netlink connector, the fanotify queue and an "
        "AF_PACKET header tap, with process identity anchored by pidfd rather than by "
        "reusable PID. <b>Since Revision 2 the pilot probe drives the file and wire sensors "
        "too</b>; they are no longer demonstrator-only, and the last column now says what "
        "each costs in privilege."))
    s.append(table(
        ["Event", "Evidence recorded", "Not recorded", "In the pilot probe"],
        [
            ["Process fork / exec / exit",
             "Kernel-pushed lifecycle event with kernel time; executable content hash and "
             "start time under a pidfd anchor; parent lineage; the container namespaces the "
             "observer read for itself",
             "Command line, environment",
             "Yes (perf tracepoints and netlink connector)"],
            ["TCP connection / state change",
             "Peer address and port, state transition, kernel time; the ledger names the "
             "peer as the institution's registry names it",
             "Payload",
             "Yes"],
            ["TCP send", "Kernel byte count per send", "Message bodies", "Yes"],
            ["Tool invocation (application layer)",
             "Gateway-countersigned receipt: tool identifier, commitment over the arguments, "
             "decision cited, disposition",
             "The arguments themselves: amount, beneficiary, account",
             "Not a probe sensor: the institution's gateway signs it"],
            ["File write",
             "Completed write-and-close on a marked mount, bound to the acting process "
             "through a pidfd the kernel created from the event's own process reference; "
             "path, device and inode",
             "File contents. Nothing is read through the descriptor",
             "<b>Yes</b> (fanotify; needs CAP_SYS_ADMIN, so it is enabled per deployment)"],
            ["Wire frame",
             "IP and TCP headers, flags, sequence numbers and payload length",
             "Payload bytes",
             "<b>Yes</b> (AF_PACKET; needs CAP_NET_RAW)"],
        ],
        [0.15, 0.34, 0.20, 0.31]))
    s.append(P(
        "<b>Content minimisation is structural, not a configuration option:</b> no payload "
        "is captured or hashed anywhere in the observation pipeline, and transaction "
        "arguments enter the mandate, the receipt and the agent's claim only as "
        "domain-separated commitments. Repository tests serialise every signed document of "
        "a transfer and assert that the amount, the beneficiary and the account appear in "
        "none of them; the two sensors added since Revision 2 are held to the same rule by "
        "live tests that write a known secret to a watched file and send a known payload "
        "over a watched socket, then assert that neither appears anywhere in the resulting "
        "batch. Every field that leaves the host is enumerated in a field inventory, and a "
        "test fails the build when a new field is added without one. This is the property "
        "that lets the pilot proceed under the Digital Personal Data Protection Act with a "
        "field-level review by the institution's Data Protection Officer rather than a "
        "data-flow redesign. Everything runs on-premises and offline; no foreign cloud sits "
        "in the trust path."))

    # ── 5 ───────────────────────────────────────────────────────────────────
    s.append(H("5. Authority over named resources, and the access ledger"))
    s.append(P(
        "A capability scope says which actions an agent may take. Inside a regulated entity "
        "the question that matters as much is which systems it may take them against: the "
        "loan ledger, never the payments switch. Three additions answer it without changing "
        "any signed wire format."))
    s.append(B(
        "<b>Resource registry.</b> The institution signs a versioned registry of its named "
        "systems: address ranges, ports, protocol, and a criticality class (informational, "
        "operational, transaction-critical). Overlapping entries are refused at signing. A "
        "verifier resolves any endpoint to exactly one name or to the explicit outcome "
        "<i>unregistered</i>."))
    s.append(B(
        "<b>Resource grants in the scope.</b> A grant to a named resource is an ordinary "
        "entry in the agent's signed capability scope, so it attenuates down a delegation "
        "chain exactly as an action does: a sub-agent cannot hold a resource its parent did "
        "not. The decision point resolves the request's own signed destination against the "
        "registry and refuses <i>DestinationUnregistered</i> and <i>ResourceNotGranted</i>. "
        "An institution that configures no registry gets no resource check, and the decision "
        "point says so; the pilot configures one."))
    s.append(B(
        "<b>Per-agent access ledger.</b> For an agent and a closed window, a signed ledger "
        "of every endpoint it was observed reaching, from attested observer batches only, "
        "each row named by the registry revision it cites and carrying the reconciler's "
        "signed verdicts for that row. A row's standing (verified, adverse, unproven, no "
        "verdict) is a fixed rule over the cited verdicts; a verifier recomputes it and "
        "refuses a ledger whose rows were renamed, dropped, reordered or restated. The "
        "ledger is committed to the append-only log as its own leaf kind and verifies "
        "offline. It is the evidence attachment for the AI inventory the FREE-AI framework "
        "asks the institution to keep, and it is what an inspector reads instead of an "
        "address list."))

    # ── 6 ───────────────────────────────────────────────────────────────────
    s.append(H("6. The tool boundary: authorised, received, claimed"))
    s.append(P(
        "After a disputed transaction a supervisor asks one question the kernel cannot "
        "answer: was the request that reached the payments system the request that was "
        "authorised? The kernel observer sees a socket to the gateway and never the "
        "application payload. The party that can answer is the institution's own tool "
        "gateway, which holds the request bytes and is not operated by the agent."))
    s.append(table(
        ["Document", "Signer", "Says"],
        [
            ["ExpectedExecution (tool-invoke class)", "Decision point",
             "What was authorised: a tool identifier and a commitment to the canonical "
             "arguments, sealed into the parameter digest."],
            ["AIRI ToolInvocation", "The agent",
             "What the agent says it asked for. A claim, never evidence."],
            ["ToolReceipt", "Tool gateway",
             "What the gateway actually received, with the commitment recomputed by the "
             "gateway from the request bytes; the decision cited; the disposition "
             "(forwarded, refused, failed)."],
        ],
        [0.26, 0.15, 0.59]))
    s.append(P(
        "The comparison recomputes the sealed digest from the verified receipt through the "
        "same function the decision point used, so every evaluated answer is arithmetic over "
        "two signed documents that a third party recomputes offline. The named outcomes:"))
    s.append(B(
        "<b>Receipt does not match authorisation.</b> What reached the system is not what "
        "was authorised, whatever the agent claimed. This is the disputed-transaction class, "
        "and the agent's account is not what the finding rests on."))
    s.append(B(
        "<b>Claim does not match authorisation.</b> The gateway received what was "
        "authorised; the agent misreported its own request."))
    s.append(B(
        "<b>Agrees</b>, recording whether the agent's account agreed too, or <b>not "
        "evaluated</b> with a reason. A decision with no receipt is a coverage statement, "
        "never a finding: most actions are not tool invocations, and a gateway that emits no "
        "receipts is a gap to be stated, not scored."))
    s.append(P(
        "<b>Two limits, stated.</b> A receipt says what reached the gateway, not that the "
        "downstream effect occurred; the switch may have acknowledged and failed. And the "
        "finding is surfaced beside the reconciler's verdict rather than inside it: wiring a "
        "tool-boundary divergence into the verdict path is a gated decision with the same "
        "four conditions the approval tier records, and it has not been taken."))

    # ── 7 ───────────────────────────────────────────────────────────────────
    s.append(H("7. What the reconciler can say"))
    s.append(P(
        "The verdict vocabulary is closed. Each verdict carries a machine-readable reason "
        "code and an evidence-strength grade that is strictly separated from severity: a "
        "serious-looking finding on weak evidence stays weak."))
    s.append(table(
        ["Verdict", "Meaning", "Requires"],
        [
            ["VERIFIED_EXECUTION",
             "Authorised action observed executing as authorised, by the bound process.",
             "Signed expectation and signed observation joined on decision identifier and "
             "execution binding."],
            ["UNATTRIBUTED_EFFECT",
             "An effect was observed for which no authorisation exists.",
             "A signed decision-point coverage statement proving the decision list for the "
             "window is complete. Without it the system cannot distinguish 'no "
             "authorisation' from 'authorisation not seen'."],
            ["PHANTOM_CLAIM",
             "An authorised action was claimed but never observed executing.",
             "Attested observer coverage of the window; otherwise it degrades to "
             "CANNOT_PROVE."],
            ["IDENTITY_DIVERGENCE",
             "Execution occurred, but by a process other than the one bound.",
             "Execution binding on both sides. Where both sides recorded container "
             "placement and it differs, that is a positive finding; where only one side "
             "could read it, the answer is 'not comparable', never a divergence."],
            ["CANNOT_PROVE",
             "The default. Observer absent, degraded, blinded, or the window not covered; or "
             "an action class the kernel cannot evidence, such as a tool invocation's "
             "arguments.",
             "Nothing. This is what the system says when it does not know."],
        ],
        [0.19, 0.34, 0.47]))
    s.append(P(
        "Two consequences follow. First, a blinded or interfered-with observer produces a "
        "signed integrity failure and the reconciler answers CANNOT_PROVE with an explicit "
        "reason; it never manufactures a PHANTOM_CLAIM against an innocent workload. Second, "
        "the decision point's coverage statement is computed from its own ledger and never "
        "supplied by a caller, and once issued, the decision point refuses to issue a later "
        "decision into that closed window. A completeness claim, once signed, cannot be "
        "quietly falsified afterwards."))

    # ── 8 ───────────────────────────────────────────────────────────────────
    s.append(H("8. Enforcement, interlock and approval tiers"))
    s.append(P(
        "Three further components exist in the repository. They are kept out of the "
        "observation and reconciliation path by construction, and a test in each reads its "
        "own manifest to keep it so. None produces a verdict or makes autonomous containment "
        "reachable."))
    s.append(table(
        ["Tier", "What it does", "Fail-closed rule", "Status"],
        [
            ["Enforcement (execve gate)",
             "A supervisor in the workload's syscall path, via seccomp user-notify, permits "
             "a program to execute only while a signed capability epoch naming its content "
             "hash is in force. The epoch carries a strictly increasing counter.",
             "No epoch, an expired or replayed epoch, an unhashable program, or a dead "
             "supervisor: deny. If the supervisor dies the kernel fails the pending syscalls.",
             "Built with adversarial tests. The live seccomp test needs a capable host; not "
             "yet run on institution hardware. Bypassed by an attacker who already has root."],
            ["Interlock (dead-man's switch)",
             "Inverts the burden: the host must continuously prove, with a signed counted "
             "heartbeat, that it is in a condition where actuation is permitted. A signed 'I "
             "am blind' from the observer trips it faster than silence.",
             "Tripped is absorbing; only an operator resets. Arming is refused if worst-case "
             "trip time exceeds the actuator's declared stopping budget.",
             "Protocol and state machine built and tested in software. The hardware "
             "controller and its monotonic counter are specified, not deployed."],
            ["Approval (shown versus authorised)",
             "Compares a signed record of what a human was shown and approved against the "
             "signed expectation the decision point sealed. Catches a genuine approval of "
             "something other than what was authorised.",
             "No approval record is 'not evaluated', never a finding; a record for a "
             "different decision is not compared.",
             "Built with adversarial tests. Surfaced beside the verdict; engine integration "
             "gated."],
        ],
        [0.15, 0.33, 0.27, 0.25]))
    s.append(P(
        "<b>Relevance to the draft Model Risk Management guidance:</b> the kill switch it "
        "asks for is the combination of a revoked capability epoch and a withheld heartbeat. "
        "Both exist as fail-closed mechanisms. The trigger from a verdict to a revocation is "
        "the institution's orchestration or SOAR, by design; in the pilot the system stays "
        "advisory."))

    # ── 9 ───────────────────────────────────────────────────────────────────
    s.append(H("9. Security model"))
    for b in [
        "Ed25519 signatures (RFC 8032) and SHA-256 over canonical, length-prefixed "
        "encodings with domain separation, so a signature over one artefact type cannot be "
        "presented as another. Every field a verifier reads is inside the signature that "
        "vouches for it.",
        "Observation batches are sequence-numbered and hash-chained at the collector; a "
        "rolled-back or replayed batch breaks the chain and the collector refuses to sign, "
        "leaving a signed report.",
        "<b>The probe-to-collector link is confidential as well as authenticated</b> "
        "(new since Revision 2). The authenticated protocol runs inside a "
        "Noise_NK_25519_ChaChaPoly_SHA256 session in which the probe pins the collector's "
        "static public key, so a capture of the link reveals neither the probe's identity "
        "nor any observation metadata. The acceptance test is a packet capture asserted to "
        "contain none of it, with a plaintext control proving the search would have found "
        "it.",
        "<b>Signing keys may live in a hardware module</b> (new since Revision 2). A "
        "PKCS#11 custodian generates the key inside the module as sensitive and "
        "non-extractable and reads the policy back from the module rather than assuming it; "
        "the process sends 32 bytes and receives a signature. There is no import path, "
        "because a key that was once outside the module cannot be shown never to have been "
        "copied.",
        "Fail closed for the verdict, fail open for availability: missing or ambiguous "
        "evidence yields CANNOT_PROVE; an observer fault never disturbs the institution's "
        "workload.",
        "Offline verification: the verifier is a pure function of the artefact and the "
        "institution's trusted keys. There is no call-home in the trust path. Two offline "
        "verifiers ship in releases, and release artefacts are now signed rather than only "
        "checksummed.",
        "Independence checks a verifier can make when it knows the agent's key: a decision "
        "point, an observer, a gateway or an approval surface anchored under the agent's own "
        "key is refused.",
        "<b>Log heads are countersigned by an external witness</b> (new since Revision 2). "
        "An append-only log proves inclusion and consistency, but not that today's root is "
        "the root that existed yesterday: whoever holds the log key can build a shorter log "
        "and sign it, and every internal check still passes. A witness on a system the log "
        "operator does not control, holding a key the operator does not have, countersigns "
        "heads. The operator can still sign a rewritten head; they cannot produce a witness "
        "receipt for the head they discarded.",
        "<b>The collector refuses to start on an undisciplined clock</b> (new since "
        "Revision 2). It stamps and signs every attested batch, so an unsynchronised clock "
        "there does not produce one wrong timestamp but an archive that is wrong together "
        "and internally consistent, which nothing in the sealed bytes afterwards reveals. "
        "CERT-In Direction 20(3)/2022 requires NTP-synchronised clocks; a reference chrony "
        "configuration pointing at NIC and NPL servers ships with the pilot kit.",
        "Service layer: bearer keys stored only as hashes, bound to tenant and role; tenant "
        "taken from the key, never the request; append-only evidence store with no delete "
        "path. Revocation is tenant-scoped and consulted by evidence verification. Request "
        "body size, per-request timeout and a global in-flight ceiling are enforced in "
        "process, with TLS and per-client rate limiting at the institution's proxy and a "
        "reference configuration supplied.",
        "Storage controls are enforced by the database under a role the service does not "
        "hold: the service's login has SELECT and INSERT only, triggers make evidence "
        "append-only and enforce legal hold against the owner too, row-level security scopes "
        "an unfiltered query, and a 180-day retention floor is a constraint rather than a "
        "policy. A restore drill dumps a hardened vault, restores it into a separate empty "
        "cluster and asserts that every one of those controls survived the restore.",
    ]:
        s.append(B(b))

    # ── 10 ──────────────────────────────────────────────────────────────────
    s.append(H("10. What has been demonstrated, and what has not"))
    s.append(P(
        "Every claim below corresponds to an executed attack with recorded output, or to an "
        "automated adversarial test. The adversarial ledger holds one row per attack with the "
        "exact command and the classification the stack actually emitted; <b>since Revision 2 "
        "a single command reproduces every row of it that the host's privileges allow</b>, "
        "reports the named reason for every row it cannot run, and fails if a detection the "
        "ledger claims no longer holds. Continuous integration runs it."))
    for b in [
        "<b>Foreign eBPF tracepoint gate</b> attached to each perf sensor (an attacker with "
        "CAP_BPF): the observer signs an integrity-unknown state and the reconciler answers "
        "CANNOT_PROVE with reason ObserverIntegrityUnknown. Control run with no attack yields "
        "VERIFIED_EXECUTION with no false positive. Demonstrated in the single-host "
        "demonstrator by a recorded manual attack run with raw output. In the two-host pilot "
        "topology the finding travels inside the signed batch and the collector fails closed "
        "on a missing finding; that path is covered by automated tests against synthetic "
        "batches. <b>The live attack against the two daemons on institution hardware remains "
        "a pilot Phase 4 item.</b>",
        "Forged observer identity, altered observation after signing, altered measured boot "
        "after signing, unanchored key version, and deserialisation of a record from nothing: "
        "each is refused.",
        "Signed reconciliation verdict: mutation of result or reason, swap of reconciler "
        "identity, and domain confusion are each detected; the verdict can be committed to an "
        "append-only log and verified offline.",
        "Decision-point coverage statements from a ledger, with the closed-window refusal "
        "described in section 7, making UNATTRIBUTED_EFFECT reachable on the live path.",
        "Resource authority: a signed registry with overlap refusal; unregistered and "
        "ungranted destinations refused at the decision point; a delegation hop that tries to "
        "widen a resource grant refused; an unanchored, impostor or tampered registry refused.",
        "Access ledger over the real engine: a verified connection becomes a named row citing "
        "the signed verdict; renaming, dropping, reordering, re-pointing the registry revision "
        "and restating a row's standing are each refused; the ledger commits and verifies "
        "offline as its own leaf kind.",
        "Tool boundary: a gateway receipt for other parameters or another tool is the named "
        "divergence regardless of the agent's claim; an agent misreport over a correct receipt "
        "is named separately; no receipt is never a finding; unanchored, agent-keyed, tampered "
        "and impostor receipts are refused; the arguments appear in no signed document.",
        "<b>Container placement cannot be manufactured from blindness</b> (new since Revision "
        "2). Two observers that both read the namespaces and disagree is a positive finding; "
        "exactly one having read them is 'not comparable', never a difference; and the "
        "placement is deliberately excluded from the identity digest so a privileged observer "
        "and an unprivileged one produce the same digest for the same process. Eight ledger "
        "rows cover this class.",
        "<b>Verdicts and access ledgers are stored and served</b> (new since Revision 2; "
        "Revision 2 listed this as not demonstrated). The evidence API accepts a signed "
        "verdict or ledger only after verifying it under the caller's anchors, returns it "
        "verbatim so the answer never depends on trusting the service, and scopes both by "
        "tenant.",
        "Enforcement, interlock and approval tiers: each with an adversarial suite (replayed "
        "epoch, counter rollback, forged heartbeat, withheld condition, approval for another "
        "decision, stale artefact) and a manifest test that keeps it out of the observation "
        "path.",
    ]:
        s.append(B(b))

    s.append(Paragraph("Not demonstrated. Stated plainly so the evaluation can target it:",
                       st["h2"]))
    for b in [
        "<b>Root or kernel-level compromise of the observed host.</b> A root attacker can "
        "hide a tracepoint gate from the detection query, detach the seccomp supervisor, and "
        "clear the kernel's clock-synchronisation flag on a clock it has just moved. The "
        "off-host collector bounds tampering after collection; it does not make the host "
        "kernel trustworthy. Remedy paths are hardware-rooted or fully off-host observation, "
        "not yet built.",
        "<b>Any performance, throughput, latency or readiness-level figure.</b> None has been "
        "measured and none is quoted in this document.",
        "<b>Autonomous enforcement from a verdict.</b> Containment is designed but stays off. "
        "The enforcement and interlock tiers act on epochs and heartbeats, not on verdicts; no "
        "production evidence path today yields the evidence grade that verdict-driven "
        "containment would require. The system is advisory.",
        "<b>Hardware attestation, TPM/TEE, hardware monotonic counter, post-quantum "
        "cryptography.</b> Not deployed.",
        "<b>Operation in a transaction's critical path.</b> The observer never gates or blocks "
        "a transaction and is not designed to. The execve gate, where an institution chooses to "
        "run it, gates program launch, not transactions.",
        "<b>Kernel-dependent tests in continuous integration.</b> CI runs unprivileged and the "
        "kernel sensor and seccomp tests skip there. Evidence for them is developer runs on "
        "capable hosts and the recorded attack ledger, not a green CI badge.",
        "<b>Gateway integration.</b> The receipt format and its verification exist; the "
        "institution's API or MCP gateway must be extended to compute and sign receipts. That "
        "is integration work at the institution, not a library the pilot ships.",
        "<b>The clock-discipline reading is operational, not attested.</b> It gates the "
        "collector's start and is logged, but it is not inside the signed bytes, so an offline "
        "verifier cannot confirm from a sealed batch that the collector's clock was disciplined "
        "when it signed.",
    ]:
        s.append(B(b))

    s.append(Paragraph("Demonstrator versus pilot deployment", st["h2"]))
    s.append(P(
        "Two configurations exist and the difference matters for what a pilot can conclude. "
        "Since Revision 2 the gap has narrowed to the evidence key's location and the "
        "integrity finding's path, which are the two that carry the security argument."))
    s.append(table(
        ["Property", "Single-host demonstrator", "Two-host pilot daemons"],
        [
            ["Sensors", "Perf tracepoints, netlink connector, fanotify, AF_PACKET",
             "<b>The same four</b>, with fanotify and AF_PACKET enabled per deployment for "
             "their capability cost"],
            ["Gate-independent coverage", "Yes",
             "Yes: the connector, plus fanotify and the wire tap, none of which a "
             "per-tracepoint eBPF program can silently gate"],
            ["Integrity finding path", "Sensor to signer in one process",
             "Inside the signed batch, probe to collector; collector fails closed on silence"],
            ["Evidence key location", "Same host as the sensors",
             "Separate collector host; wrapped at rest or non-extractable in a PKCS#11 module"],
            ["Transport", "In-process",
             "Authenticated and confidential; a capture shows no observation metadata"],
            ["Verdict classes reachable", "All that the evidence supports",
             "Same; PHANTOM_CLAIM needs the connector's process-lifecycle coverage, which the "
             "pilot runs"],
            ["Resource naming and ledger", "Library-level; same code",
             "Same code; registry signed by the institution's infrastructure owner before "
             "Phase 2"],
        ],
        [0.18, 0.32, 0.50]))

    # ── 11 ──────────────────────────────────────────────────────────────────
    s.append(H("11. Threat model"))
    s.append(table(
        ["Attacker", "Capability", "System stance"],
        [
            ["A1 confused agent", "Unintended actions, no evasion",
             "Baseline. The common real case; detected as IDENTITY_DIVERGENCE, "
             "UNATTRIBUTED_EFFECT or an unregistered destination where coverage allows; a "
             "mis-sized transfer surfaces at the tool boundary when the gateway signs receipts."],
            ["A2 adversarial agent, unprivileged", "Evades, misreports, no root",
             "In scope. Expected outcome CANNOT_PROVE or IDENTITY_DIVERGENCE; never a silent "
             "VERIFIED_EXECUTION. A misreported tool call over a correct receipt is named as "
             "such; a forged receipt fails because the agent does not hold the gateway key."],
            ["A2+/A3 agent with CAP_BPF or root",
             "Attaches a tracepoint gate, reads local state, alters the clock, detaches the "
             "supervisor",
             "Detection bound. A CAP_BPF gate is detected. Full root defeats on-host detection "
             "and on-host enforcement; the off-host collector bounds post-collection tampering "
             "only."],
            ["A4 compromised observer", "Controls the sensor",
             "Key custody and the coverage predicate prevent a forged observation from minting "
             "UNATTRIBUTED_EFFECT against an innocent workload. A holder of the collector key "
             "can relabel state but cannot mint coverage it never had. An observer that cannot "
             "read what it is asked about records that it could not, and the comparison answers "
             "'not comparable' rather than turning blindness into a finding."],
            ["A5 compromised gateway or registry signer", "Signs false receipts or a false registry",
             "Out of the observer's reach by design: a receipt is the gateway's claim about "
             "itself and a registry is the institution's. Both are refused if unanchored or "
             "agent-keyed; their custody is the institution's key-management control, and the "
             "brief does not claim otherwise."],
            ["A6 log operator", "Rewrites the commitment log and signs a new head",
             "Bounded by the external witness. The rewritten head verifies internally, but the "
             "operator cannot produce a witness countersignature for the head they discarded, "
             "and a verifier that requires one detects the truncation."],
        ],
        [0.17, 0.22, 0.61]))

    # ── 12 ──────────────────────────────────────────────────────────────────
    s.append(H("12. Proposed pilot: narrowly scoped, observer-only, non-gating"))
    s.append(P(
        "A pilot is a falsifiable experiment, not a demonstration. It passes only if the "
        "observer's honesty holds under the institution's real conditions, and it fails "
        "usefully if it does not."))
    s.append(Paragraph("Scope", st["h2"]))
    for b in [
        "One regulated entity, a small number of Linux hosts running an AI agent that takes "
        "consequential actions (loan decisioning, reconciliation, payments operations support "
        "are natural subjects).",
        "<b>Advisory only.</b> Autonomous containment off; the execve gate and interlock are "
        "not part of the pilot unless the institution asks for them separately. Nothing "
        "freezes a process, drops a packet, changes a firewall or touches an actuator. The "
        "institution names protected processes exempt from any action.",
        "<b>Never in a transaction's critical path.</b> If the observer degrades, the "
        "institution's workload is unaffected; only VANIAN's coverage claim shrinks.",
    ]:
        s.append(B(b))
    s.append(Paragraph(
        "Phases and exit gates (built and validated in dependency order; no phase is skipped)",
        st["h2"]))
    s.append(table(
        ["Phase", "Deliverable", "Exit gate"],
        [
            ["1", "Off-host collector, host-side probe, authenticated and confidential "
                  "transport on institution hardware",
             "A real agent process is observed; its batch is signed by a collector on a "
             "different host; the verifier accepts it offline."],
            ["2", "Decision point issues signed expectations for the pilot agent's actions "
                  "against the institution's signed resource registry",
             "Expectation and observation join; the honest path yields VERIFIED_EXECUTION; a "
             "connection to an unregistered address is refused before the act; the access "
             "ledger for the window names every endpoint reached."],
            ["3", "Reconciler, ledger and evidence API wired; gateway receipts where the "
                  "institution's gateway supports them",
             "Verdicts and ledgers stored and retrievable; authority chain rebuildable; tenant "
             "isolation holds; a deliberately mis-parameterised tool call yields the named "
             "divergence."],
            ["4", "Adversarial and honesty validation on institution hosts",
             "Blinded observer yields ObserverIntegrityUnknown; observer down yields "
             "CANNOT_PROVE; no false PHANTOM_CLAIM; no false divergence with no receipt. <b>A "
             "pilot that skips this has not established honesty, whatever the happy path "
             "shows.</b>"],
            ["5", "Independent cross-check and auditor handoff",
             "VANIAN's account reconciled against auditd and Tetragon; signed audit-export "
             "bundle and access ledgers handed to the institution's auditor; verification "
             "reproduced by them with their own keys."],
        ],
        [0.08, 0.33, 0.59]))
    s.append(Paragraph("Data handling", st["h2"]))
    s.append(P(
        "No payload captured or hashed. Sends are evidenced by byte count, executions by "
        "content hash, connections by endpoint and kernel time, file events by path and inode, "
        "wire frames by header and length. Every field that leaves the observed host is "
        "enumerated in a published field inventory with its personal-data risk and the reason "
        "it is collected, and a test fails the build if a field is added without an entry. "
        "Everything remains on the institution's premises."))

    # ── 13 ──────────────────────────────────────────────────────────────────
    s.append(H("13. Pre-production blockers, stated up front"))
    s.append(P(
        "A pilot may proceed with these open because it is advisory and non-gating. A "
        "regulated production rollout may not. We would rather the FinTech Department see this "
        "list now than discover it later. <b>Seven rows have moved since Revision 2 and are "
        "marked; the hard gate, B8, has not.</b>"))
    s.append(table(
        ["#", "Blocker", "Status"],
        [
            ["B1", "TLS and rate limiting at ingress; confidential probe-to-collector link",
             "<b>Changed.</b> The probe-to-collector link is now encrypted (Noise NK) as well "
             "as authenticated, and the service enforces body-size, timeout and in-flight "
             "limits in process. TLS termination and per-client rate limiting remain the "
             "institution's proxy configuration, for which a reference file ships."],
            ["B2", "Independent security assessment by a CERT-In empanelled auditor, with "
                   "remediation",
             "Not yet done. Hard gate for every segment. Unchanged."],
            ["B3", "Durable, backed-up storage with DR/BCP; storage-enforced immutability and "
                   "retention",
             "<b>Changed.</b> Row-level security, delete revocation, append-only triggers, "
             "legal hold and a 180-day retention floor are enforced by the database under a "
             "role the service does not hold, and a restore drill proves those controls survive "
             "a backup and restore. RPO/RTO, off-site custody, backup encryption and drill "
             "cadence remain the entity's to set."],
            ["B4", "KMS/HSM custody for service, collector, ledger and gateway signing keys; "
                   "key rotation",
             "<b>Changed.</b> A PKCS#11 custodian generates a non-extractable key inside the "
             "module and verifies the policy by reading it back; tested against a real module "
             "through the same interface a hardware device presents. Choice of module and its "
             "certification, PIN custody, dual control and key ceremony remain the entity's."],
            ["B5", "Signed audit-export bundle and standalone verifiers distributed to the "
                   "auditor",
             "<b>Changed.</b> Done, and the earlier caveat is closed: release artefacts are now "
             "signed, not only checksummed."],
            ["B6", "Metrics, monitoring, SIEM export, incident bundle in the CERT-In window, "
                   "runbook",
             "<b>Changed.</b> An authenticated metrics endpoint, CEF-over-syslog export of "
             "verified verdicts, an incident evidence bundle and an on-call runbook exist. "
             "Connecting them to the institution's SIEM and paging remains integration work."],
            ["B7", "Control-framework mapping (RBI IT and cyber directions, Outsourcing, "
                   "Digital Lending, FREE-AI, MRM, CERT-In, DPDP) to code and tests",
             "<b>Changed.</b> The conformance program now emits the regulatory control "
             "dimension alongside the invariant-by-domain matrix."],
            ["B8", "Off-host collector and authenticated transport running on institution "
                   "hardware",
             "<b>The hard gate, unchanged.</b> Components are built, including the connector, "
             "the file and wire sensors, the confidential transport and the integrity finding "
             "across the split. What has not happened is the run on the institution's own "
             "hosts, and no amount of test coverage substitutes for it."],
            ["B9", "Client-side signing so no agent key crosses the wire; agent-framework "
                   "adapters",
             "Partial, unchanged: agent-signed AIRI events exist as a library; framework "
             "adapters not yet done."],
            ["B10", "Gateway receipt issuance at the institution's API or MCP gateway",
             "Unchanged: format and verification built; gateway-side issuance is institution "
             "integration work."],
            ["B11", "External anchoring of log heads to an institution-controlled second system",
             "<b>Changed.</b> An external witness countersigns log heads from a system the log "
             "operator does not control, holding a key the operator does not have; a rewritten "
             "log cannot produce a receipt for the head it discarded. Where the witness runs, "
             "and who holds its key, is the entity's deployment decision."],
        ],
        [0.05, 0.31, 0.64]))

    # ── 14 ──────────────────────────────────────────────────────────────────
    s.append(H("14. What we ask of the FinTech Department"))
    for b in [
        "<b>A technical evaluation session</b> (about 45 minutes) with people who can "
        "challenge the system. We will demonstrate the honest path, an interfered-with "
        "observer, a refused unregistered destination, a mis-parameterised tool call against a "
        "signed receipt, and offline verification performed by your side with keys you hold.",
        "<b>Guidance on the appropriate pathway:</b> the RBI Innovation Hub, the Regulatory "
        "Sandbox, or a direct pilot with a regulated entity.",
        "<b>If the evaluation warrants it, an introduction to one regulated entity</b> willing "
        "to host the pilot described in section 12.",
    ]:
        s.append(B(b))
    s.append(P("We are not asking for endorsement, funding, or regulatory approval of any "
               "product."))
    s.append(Paragraph("References (repository documents; available on request)", st["h2"]))
    s.append(N(
        "RBI Requirements Coverage matrix (requirement by requirement, with the test that "
        "meets each row or an explicit gap); RBI Agent Risk Map; BFSI Pilot Plan; Phase-1 "
        "daemon and transport specification; HSM custody note; backup and recovery note with "
        "its restore drill; operations runbook; Evaluation Package; Production Readiness; "
        "Sniffer Dog Complete Implementation Report; Reconciliation Implementation Report; "
        "Decision Point specification; Adversarial Results ledger (one row per attack, with "
        "raw output and the classification emitted) and the RED suite that reproduces it."))
    return s


def build(out: Path) -> None:
    st = styles()
    page_w, page_h = A4
    lm = rm = 15 * mm
    tm, bm = 17 * mm, 15 * mm
    frame_w = page_w - lm - rm

    commit = git("rev-parse", "--short", "HEAD")

    def decorate(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 6.4)
        canvas.setFillColor(MUTED)
        canvas.drawString(lm, page_h - tm + 6 * mm, RUNNING)
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.4)
        canvas.line(lm, page_h - tm + 4.6 * mm, page_w - rm, page_h - tm + 4.6 * mm)
        canvas.drawCentredString(page_w / 2, bm - 7 * mm,
                                 f"Page {canvas.getPageNumber()}")
        canvas.setFont("Helvetica", 5.8)
        canvas.drawRightString(page_w - rm, bm - 7 * mm, f"repo {commit}")
        canvas.restoreState()

    template = PageTemplate(
        id="body",
        frames=[Frame(lm, bm, frame_w, page_h - tm - bm, id="f")],
        onPage=decorate,
    )
    pdf = BaseDocTemplate(
        str(out), pagesize=A4, pageTemplates=[template],
        title="Sniffer Dog / AIP: Technical Brief",
        author="VANIAN Technologies",
        subject=("Independent runtime observation and accountability for "
                 "autonomous AI in financial systems"),
    )
    pdf.build(content(st, frame_w))


def main() -> int:
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    build(out)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
