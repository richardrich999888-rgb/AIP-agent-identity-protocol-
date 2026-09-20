#!/usr/bin/env python3
"""Two-page covering note for the RBI FinTech Department.

Context: the FinTech Department asked for an email to cgmfintech@rbi.org.in,
copied to the officer who responded, "stating your expectations and ask".
This is the document that accompanies it. A Chief General Manager reads two
pages; the nine-page technical brief is for whoever they hand it to.

The one editorial rule that matters here
----------------------------------------
Maturity is stated as the repository states it: TRL 4, validated in a
laboratory environment, with demonstration in a relevant operational
environment being the thing requested rather than a thing claimed. An
earlier outreach message said "TRL 6". The repository does not support that
-- `docs/idex_open_challenge/02_TECHNOLOGY_AND_TRL.md` says TRL 4 and names
TRL 6-7 as the target of a future programme, and the technical brief's
blocker B8 says the run on institution hardware has not happened. A vendor
selling independent verification of AI agents cannot afford to overstate its
own readiness to its regulator: it is the single claim the reader is most
likely to test, and the one whose failure would discredit everything else in
the document.
"""

from __future__ import annotations

import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "docs" / "pilot" / "RBI_FINTECH_COVER_NOTE.pdf"

INK = colors.HexColor("#111111")
MUTED = colors.HexColor("#555555")
RULE = colors.HexColor("#bfbfbf")
ACCENT = colors.HexColor("#14304f")
BOX = colors.HexColor("#eef2f7")


def build(out: Path) -> None:
    base = getSampleStyleSheet()
    st = {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=16, leading=20,
                                textColor=ACCENT, alignment=0, spaceAfter=1),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9.6, leading=13,
                              textColor=MUTED, spaceAfter=9),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontSize=11, leading=14,
                            textColor=ACCENT, spaceBefore=10, spaceAfter=4),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=9.3, leading=13,
                            textColor=INK, spaceAfter=5),
        "b": ParagraphStyle("b", parent=base["Normal"], fontSize=9.3, leading=13,
                            textColor=INK, leftIndent=10, spaceAfter=4),
        "note": ParagraphStyle("n", parent=base["Normal"], fontSize=8.4, leading=11.5,
                               textColor=MUTED, spaceAfter=4),
    }
    P = lambda s: Paragraph(s, st["p"])                       # noqa: E731
    B = lambda s: Paragraph(f"•&nbsp; {s}", st["b"])      # noqa: E731
    H = lambda s: Paragraph(s, st["h"])                        # noqa: E731

    page_w, page_h = A4
    lm = rm = 20 * mm
    tm, bm = 18 * mm, 16 * mm
    fw = page_w - lm - rm

    def decorate(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 6.6)
        canvas.setFillColor(MUTED)
        canvas.drawString(lm, bm - 7 * mm,
                          "VANIAN Technologies  |  Request for technical evaluation  |  "
                          "Not a commercial offer")
        canvas.drawRightString(page_w - rm, bm - 7 * mm, f"Page {canvas.getPageNumber()} of 2")
        canvas.setStrokeColor(RULE); canvas.setLineWidth(0.4)
        canvas.line(lm, bm - 5 * mm, page_w - rm, bm - 5 * mm)
        canvas.restoreState()

    pdf = BaseDocTemplate(
        str(out), pagesize=A4,
        pageTemplates=[PageTemplate(id="b",
                                    frames=[Frame(lm, bm, fw, page_h - tm - bm)],
                                    onPage=decorate)],
        title="Request for technical evaluation - Sniffer Dog / AIP",
        author="VANIAN Technologies",
        subject="Independent runtime accountability for autonomous AI in financial systems",
    )

    s = []
    s.append(Paragraph("Request for a technical evaluation", st["title"]))
    s.append(Paragraph(
        "Independent runtime evidence for autonomous AI in regulated financial systems<br/>"
        "<b>To:</b> Chief General Manager, FinTech Department, Reserve Bank of India&nbsp; "
        "|&nbsp; <b>Copy:</b> Aditi Dubey, FinTech Department", st["sub"]))

    # ── The ask, first. ────────────────────────────────────────────────────
    s.append(H("1. What we are asking for"))
    s.append(P(
        "A technical evaluation session of approximately 45 minutes with officers who can "
        "challenge the system on its evidence, and the Department's guidance on the "
        "appropriate pathway for that evaluation — the RBI Innovation Hub, the "
        "Regulatory Sandbox, or a directly supervised pilot with one regulated entity."))
    s.append(P(
        "<b>We are not asking for endorsement, funding, regulatory approval, or any "
        "statement the Bank could be quoted on.</b> We are asking to be tested."))

    # ── What it is. ────────────────────────────────────────────────────────
    s.append(H("2. The problem, in one paragraph"))
    s.append(P(
        "When an AI agent executes a consequential action inside a regulated entity — "
        "moving funds, changing a limit, closing a case — the only account of what "
        "happened is usually the agent's own logs and its own explanation. If that account "
        "is wrong, whether through a defect or through compromise, nothing independent "
        "contradicts it. The entity cannot demonstrate to a supervisor what actually ran, "
        "and a customer disputing a transaction is answered by the system that performed it."))
    s.append(P(
        "Sniffer Dog produces a second, independent account. An observer that is not the "
        "agent, and does not trust it, records execution from the Linux kernel. A decision "
        "point that is not the agent signs what was authorised <i>before</i> the act. The "
        "institution's own tool gateway countersigns what it actually received. A reconciler "
        "compares them and signs a verdict. Every record is verifiable offline by the "
        "entity's auditor, or by the Bank, using keys the institution holds. No step "
        "requires trusting VANIAN."))
    s.append(P(
        "<b>The governing design rule is that absence of evidence is never converted into an "
        "accusation.</b> When the observer was not watching, or was interfered with, the "
        "system returns CANNOT_PROVE and says why. A monitoring product that manufactures "
        "confident findings from missing data is worse than none in a regulated setting, "
        "because it is switched off after the first false accusation."))

    # ── Relevance. ─────────────────────────────────────────────────────────
    s.append(H("3. Why we are bringing it to the FinTech Department"))
    for b in [
        "The IT Governance directions require audit trails sufficient for forensics, dispute "
        "resolution and non-repudiation. An agent's self-report is none of those.",
        "The Outsourcing of IT Services directions hold that a regulated entity may outsource "
        "the activity but never the accountability. Independent evidence is what makes "
        "retained accountability demonstrable rather than contractual.",
        "The FREE-AI framework asks entities to maintain an inventory of AI systems and their "
        "behaviour. The system produces a signed per-agent ledger of every system an agent "
        "actually reached, named by the institution's own signed registry.",
        "CERT-In's six-hour incident reporting window is difficult to meet when the evidence "
        "must first be assembled. A signed incident bundle over a stated window is an output "
        "of the system, not a project.",
        "Everything runs on the entity's premises. No payload content is captured or hashed "
        "anywhere in the pipeline, which is what allows a Data Protection Officer to clear it "
        "under the DPDP Act by field-level review rather than a data-flow redesign.",
    ]:
        s.append(B(b))

    # ── Maturity: the honest block. ────────────────────────────────────────
    s.append(H("4. Maturity, stated plainly"))
    tbl = Table([[Paragraph(
        "<b>Integrated-system maturity: TRL 4 — validated in a laboratory environment.</b> "
        "The cryptographic core, the observation pipeline, the reconciler and the adversarial "
        "test suite are implemented and exercised, including recorded attacks against the "
        "observer with their raw output. What has <i>not</i> happened is a demonstration in a "
        "relevant operational environment: the two-daemon pilot has not yet run on a regulated "
        "entity's own hosts, and until it does we do not claim a higher readiness level. "
        "<b>That demonstration is precisely what we are asking the Department to help make "
        "possible.</b>", st["p"])]], colWidths=[fw])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BOX),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    s.append(tbl)
    s.append(Spacer(1, 6))
    s.append(P(
        "The attached technical brief carries a list of eleven pre-production blockers, "
        "stated by us, unprompted, including an independent security assessment by a CERT-In "
        "empanelled auditor which we have not had. We would rather the Department see that "
        "list now than discover it later. We hold two Indian patent applications around the "
        "broader architecture."))

    # ── What we would show. ────────────────────────────────────────────────
    s.append(H("5. What we would demonstrate, live"))
    for b in [
        "The honest path: an authorised action observed executing, reconciled to "
        "VERIFIED_EXECUTION.",
        "An <b>interfered-with observer</b>: an attacker with CAP_BPF blinds a kernel sensor; "
        "the observer signs an integrity failure and the system answers CANNOT_PROVE with a "
        "reason, rather than a false accusation against an innocent workload.",
        "A connection to an <b>unregistered destination</b> refused before the act, against "
        "the institution's own signed registry of named systems.",
        "A <b>mis-parameterised tool call</b> caught against a gateway-countersigned receipt, "
        "where the finding does not rest on the agent's own account of what it asked for.",
        "<b>Offline verification performed by your side</b>, on your hardware, with keys you "
        "hold and our software not in the trust path.",
    ]:
        s.append(B(b))

    # ── Pilot shape + attachments ──────────────────────────────────────────
    s.append(H("6. The pilot we would propose, if the evaluation warrants it"))
    s.append(P(
        "One regulated entity, a small number of Linux hosts running an AI agent that takes "
        "consequential actions. <b>Observer-only and advisory: nothing freezes a process, "
        "drops a packet, changes a firewall or sits in a transaction's critical path.</b> If "
        "the observer degrades, the entity's workload is unaffected and only our coverage "
        "claim shrinks. Five phases, each with a falsifiable exit gate; the fourth is "
        "adversarial validation on the entity's own hosts, and a pilot that skips it has not "
        "established honesty whatever the happy path shows."))

    s.append(H("Enclosed"))
    s.append(Paragraph(
        "<b>Sniffer Dog / AIP: Technical Brief</b> (9 pages) — architecture, independent "
        "authorities and key custody, what is observed and what is deliberately not, the "
        "verdict vocabulary, the security model, what has been demonstrated and what has not, "
        "the threat model, the proposed pilot with its exit gates, and the eleven "
        "pre-production blockers.<br/>"
        "Further repository documents — including a requirement-by-requirement coverage "
        "matrix against the RBI, CERT-In and DPDP instruments, and an adversarial results "
        "ledger with one row per executed attack — are available on request.",
        st["note"]))
    s.append(Spacer(1, 8))
    s.append(Paragraph(
        "Naga Sri Ganesh Kanumuri &nbsp;|&nbsp; Founder &amp; CTO, VANIAN Technologies "
        "&nbsp;|&nbsp; Indian deep-tech, accountability infrastructure for autonomous AI",
        st["note"]))

    pdf.build(s)


def main() -> int:
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    build(out)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
