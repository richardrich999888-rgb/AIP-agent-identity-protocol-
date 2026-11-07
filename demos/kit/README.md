# Offline demo kit (W7.1)

```sh
demos/kit/build_bundle.sh OUT_DIR                       # needs clean AIP and OVERLAY trees
sudo demos/kit/install_test.sh OUT_DIR/syntriass-demo-kit-*.tar.gz RESULTS_DIR
```

On the target machine, from the extracted archive:

```sh
kit/verify.sh                                  # every file against SHA256SUMS; stop if it fails
sudo SYNTRIASS_OVERLAY=$PWD/kit/overlay python3 kit/aip/demos/launch.py check
sudo SYNTRIASS_OVERLAY=$PWD/kit/overlay python3 kit/aip/demos/launch.py run security
```

`kit/MANIFEST.json` names both commits, every binary's sha256, and what the host
must already have (`host_needs`). Result files written from the kit take their
commit from that manifest (`"source": "kit MANIFEST.json"`, `"dirty": null`).

**What the install test shows:** in a new network namespace with no interface but
loopback, in an empty directory, the archive checks against its `.sha256`, all
files check against `SHA256SUMS`, a single flipped byte is refused, and the
`pq` and `quantum` modes pass from the kit.

**What it does not show:**
- **A clean machine.** It runs on this host, so docker, auditd, openssl, gcc and
  the kernel are this host's.
- **`security` without a network.** That mode runs from the same kit, but in the
  host network namespace: `aip-probe`'s netlink process-connector sensor works only
  in the initial network namespace and refuses to start anywhere else. The first
  install test tried it inside the namespace and failed for that reason.
- **The modes that need models.** No model weights are in the kit, so
  `customer-<sector>` and `investor-3min` stay NOT READY. `teach` belongs to the
  teaching-demo loop.
