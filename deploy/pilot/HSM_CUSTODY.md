# HSM custody for signing keys (R16)

What `aip-hsm` does, what it refuses, and the three decisions the entity
makes that no code can make for it.

---

## 1. What changes when a key is in a module

With the wrapped-file custodian, the signing key is decrypted into the
signing process's memory for as long as that process runs. Anyone who can
read that memory — a core dump, a debugger attached by an administrator, a
compromised library in the same process — has the key, and nothing in the
evidence afterwards shows that they took it.

With `aip-hsm`, the key is generated **inside** the module with
`CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`. The module's own firmware
refuses to return it: asked for its value it answers
`CKR_ATTRIBUTE_SENSITIVE`, asked to wrap it out it answers
`CKR_KEY_UNEXTRACTABLE`. The signing process sends the module 32 bytes and
receives a signature. There is no import path in `aip-hsm`, because a key
that was ever outside the module cannot be shown never to have been
copied.

This is tested against SoftHSM2 through the same PKCS#11 interface a
hardware module presents, including the negative half: a second session
holding the PIN — the strongest position an attacker with the PIN can be
in — asks for the private key and does not get it.

## 2. What it does not change

A hardware-held key establishes **who signed**. It says nothing about
whether what was signed is true. An observer batch signed through an HSM
is still procfs-derived; a verdict signed through an HSM still rests on
the evidence it cites. No evidence-strength decision anywhere in the
workspace consults which backend signed, and the signature envelope a
module produces is byte-for-byte the one the software signer produces —
a verifier cannot tell, and does not need to.

## 3. What the custodian refuses

Every one of these is checked at open, once, so a misconfigured deployment
fails at start-up rather than at the first signature an audit depends on.

| Refused | Why |
|---|---|
| A key that is extractable, or not sensitive | It can be wrapped out by anyone holding the PIN, which makes the module a slow file. The policy is **read back from the module**, not assumed from how the key was said to be created — a key imported by another tool has whatever policy that tool gave it. |
| Two keys under one label | The custodian will not pick the first. A label that resolves ambiguously is an operational fault to surface. |
| A public object that does not verify what the private object signs | The pair is proven with a probe signature at open. A mislabelled public half is caught once, at commissioning, rather than in an audit. |
| A PIN on the command line | Visible to every process on the host. The PIN comes from an owner-only file or an environment variable. |
| A PIN file readable by group or others | A PIN other users can read is a PIN other users have. |
| A module that will not report the key's policy | An unestablished policy is not a safe one. |

## 4. Commissioning

```
# PIN in an owner-only file, never an argument.
install -m 600 /dev/null /etc/aip/hsm.pin && echo -n '<pin>' > /etc/aip/hsm.pin

aip-hsm provision  --module /usr/lib/<vendor>/libpkcs11.so --token aip-prod \
                   --key reconciler-1 --pin-file /etc/aip/hsm.pin
# → public_key_hex: <64 hex chars>   ← this is what verifiers anchor on

aip-hsm self-test  --module ... --token aip-prod --key reconciler-1 --pin-file /etc/aip/hsm.pin
```

`self-test` opens the custodian — finding the key, refusing weak policy,
proving the pair — then signs and verifies one envelope with the
workspace's ordinary verifier. Run it after a firmware update, a token
replacement, or a PIN change, and attach its output to the commissioning
record.

Tokens are found by **label**, not slot number. Slot numbers change across
restarts and firmware updates; a label does not.

## 5. Two PKCS#11 facts a deployment must know

**Login state is per token per application, not per session.** Once the
process has logged into a token, every session it opens on that token is
logged in, and the PIN of a second custodian on the same token is not
checked. `aip-hsm` treats `CKR_USER_ALREADY_LOGGED_IN` as success and says
so. This is the standard's model of a PIN — it opens the token to the
application — and cannot be tightened from the application side. If two
keys must be protected by two PINs, they go on two tokens.

**Commission when nothing else is using the token.** SoftHSM2's
file-backed object store fails intermittently with `CKR_GENERAL_ERROR`
when a key is generated while any other operation — a search, a signature,
another generation — is in flight on the same token, in this process or
another. Hardware modules generally do not have the limitation; SoftHSM's
SQLite store would not either, but most distribution builds omit it.
`aip-hsm` serialises generation within a process so a multi-threaded tool
cannot trip over itself, and cannot serialise it against a daemon signing
in another process. Provisioning is a once-per-key step: run it before the
signer starts, or with the signer stopped, and run `self-test` afterwards.
Concurrent *signing* is fine and is tested.

## 6. What the entity decides, and the code cannot

| Decision | Why it is the entity's |
|---|---|
| **Which module.** A FIPS 140-3 Level 3 network HSM, a PCIe card, a USB token, or a cloud HSM. | The evidentiary weight of "the key never left the module" is the weight of the module's certification and the entity's key-ceremony record. `aip-hsm` speaks PKCS#11 to any of them and cannot tell them apart. |
| **Who holds the PIN, and how.** | A PIN in a file the platform team can read is a key the platform team can use. Whether that is acceptable depends on who the evidence is meant to be independent of — see `ANCHOR_WITNESS.md` for the same question asked of the log. |
| **Dual control and key ceremony.** | Whether the key is generated under two-person control, in a recorded ceremony, with the public key attested by witnesses, is a procedure. The code generates a key; it cannot generate a ceremony. |
| **Backup and disaster recovery of the key.** | A non-extractable key cannot be backed up by copying it. Vendor-specific cloning between modules of the same family, or accepting that loss of the module is loss of the key and rotating to a new one, is a policy choice with regulatory consequences. **Open** — see matrix row E5. |

A module on the same host as the signer, whose PIN is in a file the same
administrator can read, still removes the key from process memory — a real
improvement — but does not remove it from that administrator. The
custodian cannot tell the difference, and no flag would let it.
