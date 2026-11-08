# Narration scripts (W9.1)

Spoken by a person, live or recorded by that person. **No synthetic voice or
video of anyone is made from these.** Every line points at something on
screen. If it isn't on screen, don't say it.

**Recorded vs live.** A replay of `demos/recording/out/<mode>/terminal.log`
(`scriptreplay -t terminal.timing terminal.log`) or of the screenshots is
**RECORDED** and must say so on screen, with the date of the recording. Only
`demos/launch.sh <mode>` run in front of the audience is live.

Recording set: `demos/recording/out/`, recorded 2026-11-07 on one machine
(4 vCPU, 15 GB RAM, no GPU), AIP `80e8135` (clean), OVERLAY `3d63f95` (clean; local only), as recorded in each `run/launch-*.json`.

---

## Catch the lying agent (`security`, about 25 s machine time)

1. "This is a test agent we scripted to misbehave. It reads an invoice, writes a
   summary, and hides two things: one network connection and one file outside
   its workspace."
2. *(section 1 on screen)* "Here is its own log: start, read input, write
   summary, done. We searched it: no mention of the connection or the file."
3. *(section 2)* "Sniffer Dog watched from the kernel. It saw the connection
   and the file, and tied both to this exact process: pid, start time and the
   hash of the program. The evidence is signed by a collector key that the
   agent never sees."
4. *(section 3)* "auditd, a separate part of the kernel, saw the same
   connection."
5. *(section 4)* "Anyone can check the signature offline with the public key.
   We changed one byte, and the check fails."
6. *(control screen)* "The same agent without the hidden step: nothing
   reported."

**Do not say:**
- "Catches any AI agent." It was shown on a scripted agent.
- "No overhead." Overhead is not measured.
- "Works without root or on any kernel."
- Anything about the clock beyond the note on screen.

---

## Post-quantum in one switch (`pq`, proof of concept, about 36 s)

1. "Two containers run the same unmodified network program, netcat, as a client
   and a server. We never change the program; its hash is identical in every
   row."
2. *(row baseline)* "Without the overlay, our message crosses the wire in
   clear."
3. *(row overlay)* "With the overlay switched on at launch, the server gets the
   message and it never appears on the wire. The extra bytes are the
   handshake."
4. *(rows no_identity, no_id_psk, impostor)* "Take the client's identity away,
   offer it a weaker fallback key, or connect as someone unknown: nothing is
   delivered. It does not fall back."
5. *(row plaintext)* "This client has no overlay, so it sends in clear. That is
   why it shows red. The protected server refuses it: the server app gets
   nothing."

**Say:** "proof of concept". "Both ends run the overlay." "About 13 KB extra
per connection; the time cost was too small to separate from noise in this
test."

**Do not say:**
- "Quantum-proof."
- "Works with any TLS client."
- "Zero overhead."
- "Production-ready."
- "No change at all": starting it with the overlay *is* a change, the program
  file is not.

**Known gap, if asked:** a refused application gets no error; it just
waits.

---

## Quantum X-ray (`quantum`, about 1 s)

1. *(ground truth)* "We built a sample server with four planted problems, and
   checked them with openssl, not with our scanner."
2. *(report)* "The scanner read the running container and found all four, at
   their real paths, and nothing that wasn't there: the old TLS settings, the
   two certificates with quantum-vulnerable keys, and a private key sitting in
   an application config."
3. "The migration list is the engine's own order. Every step needs review, and
   nothing is executed."
4. *(control box)* "We mark no compliance control as met. That needs a
   verified policy pack, and this build doesn't ship one."

**Do not say:**
- "Finds all the cryptography on any server." This is one synthetic sample.
- "CNSA 2.0 compliant."
- The ranked list is complete. It omits 3DES and TLS 1.0/1.1, and repeats
  one RSA key; say so if the list is on screen long enough to be read.

---

## Not recorded

- `customer-<sector>` and `investor-3min`: NOT READY. They need real local
  models (W1.4).
- `teach`: belongs to the teaching-demo loop and is not ready.
