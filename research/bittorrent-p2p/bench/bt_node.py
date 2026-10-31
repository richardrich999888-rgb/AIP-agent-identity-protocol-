"""One BitTorrent node (libtorrent 2.1.1) for the closed-network experiment.

usage: bt_node.py TORRENT SAVE_DIR LISTEN_IP PEERS_CSV REPORT_JSON [--ssl CERT KEY DH] [--seed-mode]

--seed-mode makes the node announce every piece WITHOUT hashing its local
data (libtorrent seed_mode). Used only to emulate a malicious or faulty
seeder serving corrupted bytes; receivers must reject them by hash.

Air-gap settings: DHT, local service discovery, UPnP, NAT-PMP and peer
exchange are disabled; the torrent is private; peers are given statically
(the emulated "tracker" is the provisioning list). Nothing contacts any
address outside PEERS_CSV.

The node writes a progress report every 0.5 s and keeps seeding after it
completes (swarming), until it receives SIGTERM.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import time

import libtorrent as lt

PORT = 6881


def main() -> None:
    torrent, save, ip, peers_csv, report = sys.argv[1:6]
    ssl = "--ssl" in sys.argv
    settings = {
        "listen_interfaces": f"{ip}:{PORT}" + (f",{ip}:{PORT + 1}s" if ssl else ""),
        "enable_dht": False,
        "enable_lsd": False,
        "enable_upnp": False,
        "enable_natpmp": False,
        "announce_to_all_trackers": False,
        "alert_mask": lt.alert.category_t.error_notification | lt.alert.category_t.status_notification
        | lt.alert.category_t.peer_notification,
        "connections_limit": 50,
    }
    ses = lt.session(settings)
    ses.add_extension("smart_ban")  # bans peers whose data fails hash checks
    atp = lt.add_torrent_params()
    atp.ti = lt.torrent_info(torrent)
    atp.save_path = save
    atp.flags &= ~lt.torrent_flags.auto_managed
    atp.flags &= ~lt.torrent_flags.paused
    if "--seed-mode" in sys.argv:
        atp.flags |= lt.torrent_flags.seed_mode
    h = ses.add_torrent(atp)
    if ssl:
        i = sys.argv.index("--ssl")
        cert, key, dh = sys.argv[i + 1:i + 4]
        h.set_ssl_certificate(cert, key, dh)
    peers = [p for p in peers_csv.split(",") if p and p != ip]
    port = PORT + 1 if ssl else PORT
    stop = {"v": False}
    signal.signal(signal.SIGTERM, lambda *a: stop.__setitem__("v", True))
    t0 = time.monotonic()
    done_at = None
    hash_fail = 0
    last_connect = 0.0
    events = []
    while not stop["v"]:
        now = time.monotonic()
        if now - last_connect > 1.0:
            for p in peers:
                h.connect_peer((p, port))
            last_connect = now
        for a in ses.pop_alerts():
            if isinstance(a, lt.hash_failed_alert):
                hash_fail += 1
            if isinstance(a, (lt.peer_error_alert, lt.peer_disconnected_alert)) and len(events) < 50:
                events.append(a.message()[:160])
        s = h.status()
        if done_at is None and s.is_seeding:
            done_at = now - t0
        json.dump({"progress": s.progress, "seconds_to_complete": done_at, "elapsed": now - t0,
                   "payload_down": s.total_payload_download, "payload_up": s.total_payload_upload,
                   "all_time_up": s.all_time_upload, "peers": s.num_peers, "hash_failures": hash_fail,
                   "state": str(s.state), "events": events}, open(report + ".tmp", "w"))
        os.replace(report + ".tmp", report)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
