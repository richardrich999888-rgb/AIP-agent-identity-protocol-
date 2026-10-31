# Founder intent — BitTorrent-inspired model distribution

## What the founder means by P2P (corrected understanding, 2026-10-31)

The primary P2P idea is **BitTorrent-style distribution of AI model packages**
inside a customer's approved network:

1. a model package is split into cryptographically verifiable pieces;
2. approved machines hold different subsets;
3. authenticated peers learn which pieces others have;
4. missing pieces move peer-to-peer on the LAN;
5. every piece and the whole package are verified;
6. interrupted transfers resume;
7. machines that hold verified pieces serve them onward;
8. no public tracker, public DHT or internet is involved.

The model is reassembled on each machine and then runs **ordinary local
inference**. No neural computation is distributed.

## What it is not

| Mechanism | Status |
|---|---|
| A. BitTorrent-style model distribution | **Primary research** (this directory) |
| B. Distributed task execution | Separate hypothesis; BitTorrent does not provide scheduling or data-locality control |
| C. Distributed model inference | Separate, high-risk hypothesis; sharing weight files does not let machines jointly run one model |

Earlier notes (`research/airgap-intelligence/P2P_HYPOTHESES.md`) already
ranked A first and C last, but did not commit to testing A. That is corrected
here: A is tested before anything else.

## How it relates to the rest of SYNTRIASS

| Subsystem | Question it answers |
|---|---|
| SLM / System One research | When is model inference needed, and how cheaply can it be done? |
| BitTorrent-inspired distribution | How do approved model packages and updates reach many machines efficiently and reliably inside a closed network? |
| Air-gap-native architecture | How does all of it work with no external dependency? |

They are complementary but independent. No performance advantage is claimed
from combining them.
