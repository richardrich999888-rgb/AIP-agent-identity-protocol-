#!/usr/bin/env python3
"""External fiducial observer — the one physical-observation instrument that
runs in this environment.

WHAT THIS IS
------------
A collector that watches a scene *from outside the subject*, detects AprilTag
36h11 fiducials, and emits `ExternalObservation` records for the Vanian
external adapter to classify.

The topology it is built for:

    ROBOT ── onboard telemetry ──> (self-report, never corroboration)
      │
      │  physical space
      ▼
    EXTERNAL CAMERA ──> OpenCV/AprilTag ──> THIS COLLECTOR ──> adapter

WHAT IT IS NOT
--------------
It is not a proof of physical effect, and it cannot become one by running.

* `--source synthetic` renders the scene itself. The detector is real; the
  scene is not. Records are emitted with provenance `SimulatorGroundTruth`,
  and the adapter REFUSES them as physical claims. That refusal is the
  correct answer, and it is the whole point of running this mode.
* `--source camera` reads a real camera. Records are emitted
  `ExternalSensorUnanchored` unless `--anchored-collector` is passed, which
  the operator may only pass when the collector is a separate machine from
  the subject and holds its own key. This script cannot check that and does
  not pretend to: it records the operator's assertion and says so.

Even `ExternalSensorAnchored` does not reach a physical-effect claim in this
build, because no `SourceMechanism` carries an optical observation. See
`../../README.md`.

DETERMINISM
-----------
Synthetic mode takes `--seed` and renders from it alone. No randomness is used
anywhere else. Two runs with the same seed produce byte-identical frames and
byte-identical records, which is what makes the trace re-derivable offline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import time
from dataclasses import dataclass

try:
    import cv2
    import numpy as np
except ImportError as e:  # pragma: no cover - environment guard
    sys.exit(f"BLOCKED: {e}. Install with: pip install opencv-python-headless numpy")

# AprilTag 36h11, via OpenCV's own dictionary. Same family the standalone
# AprilTag 3 library uses; one library that can both render and detect keeps
# the synthetic mode honest, because the renderer and the detector agree on the
# encoding by construction rather than by assumption.
TAG_FAMILY = "apriltag_36h11"


@dataclass(frozen=True)
class Detection:
    """One tag, as the detector reported it. No interpretation."""

    marker_id: int
    centre_px: tuple[float, float]
    corners_px: list[tuple[float, float]]


def _dictionary():
    return cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_APRILTAG_36h11)


def render_scene(marker_id: int, centre_px: tuple[int, int], size_px: int,
                 frame_size: tuple[int, int], seed: int) -> np.ndarray:
    """Render a synthetic scene containing one tag at a known position.

    Deterministic in `seed`: the seed selects only the background grey level,
    so a change in seed changes the image bytes without changing the geometry.
    Nothing here is random.
    """
    w, h = frame_size
    background = 40 + (seed % 8) * 10  # deterministic, not random
    frame = np.full((h, w), background, dtype=np.uint8)
    marker = cv2.aruco.generateImageMarker(_dictionary(), marker_id, size_px)
    cx, cy = centre_px
    x0, y0 = cx - size_px // 2, cy - size_px // 2
    if x0 < 0 or y0 < 0 or x0 + size_px > w or y0 + size_px > h:
        raise ValueError("the tag does not fit in the frame at that position")
    frame[y0:y0 + size_px, x0:x0 + size_px] = marker
    return frame


def detect(frame: np.ndarray) -> list[Detection]:
    """Run the real detector. Returns what it found, in its own terms."""
    detector = cv2.aruco.ArucoDetector(_dictionary(), cv2.aruco.DetectorParameters())
    corners, ids, _rejected = detector.detectMarkers(frame)
    out: list[Detection] = []
    if ids is None:
        return out
    for quad, marker_id in zip(corners, ids.flatten()):
        pts = quad.reshape(4, 2)
        cx, cy = float(pts[:, 0].mean()), float(pts[:, 1].mean())
        out.append(
            Detection(
                marker_id=int(marker_id),
                centre_px=(cx, cy),
                corners_px=[(float(x), float(y)) for x, y in pts],
            )
        )
    return sorted(out, key=lambda d: d.marker_id)


def observation_record(
    detection: Detection,
    event_type: str,
    payload: dict,
    provenance_class: str,
    observer_id: str,
    sequence: int,
    timestamp_ms: int,
    detector_version: str,
) -> dict:
    """Build one ExternalObservation, in the adapter's wire shape.

    RAW is the detector's own output line, verbatim, hashed at capture. The
    frame is stored beside the trace and referenced by digest: keeping a
    multi-megabyte image inside every record would make the trace unreadable
    without making it more auditable.
    """
    raw_bytes = json.dumps(
        {
            "marker_id": detection.marker_id,
            "centre_px": list(detection.centre_px),
            "corners_px": [list(c) for c in detection.corners_px],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "source": observer_id,
        "mechanism": f"{TAG_FAMILY} via OpenCV {cv2.__version__}",
        "timestamp_ms": timestamp_ms,
        "subject_identity": {"FiducialMarker": {"marker_id": detection.marker_id}},
        "event_type": event_type,
        "payload": payload,
        "provenance_class": provenance_class,
        "nonce": {"observer_id": observer_id, "sequence": sequence},
        "raw": {
            "tool": "opencv-aruco-apriltag",
            "tool_version": detector_version,
            "captured_at_ms": timestamp_ms,
            "bytes": list(raw_bytes),
            "digest": list(hashlib.sha256(raw_bytes).digest()),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", choices=("synthetic", "camera"), default="synthetic",
                    help="synthetic renders the scene; camera reads a real device")
    ap.add_argument("--camera-index", type=int, default=0)
    ap.add_argument("--anchored-collector", action="store_true",
                    help="operator assertion: this collector is a separate machine from the "
                         "subject and holds its own key. Recorded, never checked.")
    ap.add_argument("--marker-id", type=int, default=7)
    ap.add_argument("--mm-per-px", type=float, default=2.0,
                    help="declared scale. A calibration this script does not perform.")
    ap.add_argument("--start-px", type=int, nargs=2, default=(200, 240))
    ap.add_argument("--end-px", type=int, nargs=2, default=(600, 240))
    ap.add_argument("--tag-px", type=int, default=120)
    ap.add_argument("--frame", type=int, nargs=2, default=(800, 480))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--observer-id", default="external-camera-1")
    ap.add_argument("--out", type=pathlib.Path, required=True,
                    help="trace directory; created if absent, never overwritten in place")
    args = ap.parse_args()

    if args.source == "camera":
        provenance = ("ExternalSensorAnchored" if args.anchored_collector
                      else "ExternalSensorUnanchored")
    else:
        if args.anchored_collector:
            return _fail("--anchored-collector is meaningless for a synthetic scene: there is "
                         "no camera and nothing outside the subject to anchor.")
        provenance = "SimulatorGroundTruth"

    out: pathlib.Path = args.out
    if out.exists() and any(out.iterdir()):
        return _fail(f"{out} exists and is not empty; traces are never overwritten in place")
    out.mkdir(parents=True, exist_ok=True)

    frames: list[tuple[str, np.ndarray]] = []
    if args.source == "synthetic":
        for label, centre in (("start", tuple(args.start_px)), ("end", tuple(args.end_px))):
            frames.append((label, render_scene(args.marker_id, centre, args.tag_px,
                                               tuple(args.frame), args.seed)))
    else:
        cap = cv2.VideoCapture(args.camera_index)
        if not cap.isOpened():
            return _fail(f"camera {args.camera_index} did not open; nothing was observed")
        try:
            for label in ("start", "end"):
                ok, frame = cap.read()
                if not ok:
                    return _fail("the camera stopped delivering frames mid-run")
                frames.append((label, cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)))
                input(f"[{label}] positioned; press Enter to capture the next frame ")
        finally:
            cap.release()

    records: list[dict] = []
    centres: dict[str, tuple[float, float]] = {}
    t0 = int(time.time() * 1000)
    for seq, (label, frame) in enumerate(frames, start=1):
        png = out / f"frame_{label}.png"
        cv2.imwrite(str(png), frame)
        frame_digest = hashlib.sha256(png.read_bytes()).hexdigest()
        found = [d for d in detect(frame) if d.marker_id == args.marker_id]
        if not found:
            # An empty detection is a real result and is recorded as one. It is
            # NOT an observation that the subject was absent.
            records.append({
                "note": "no detection",
                "label": label,
                "frame_sha256": frame_digest,
                "observer_posture_hint": "PresentAndSilent",
            })
            continue
        d = found[0]
        centres[label] = d.centre_px
        records.append(observation_record(
            detection=d,
            event_type="PoseMeasurement",
            payload={
                "label": label,
                "centre_px": list(d.centre_px),
                "x_mm": d.centre_px[0] * args.mm_per_px,
                "y_mm": d.centre_px[1] * args.mm_per_px,
                "mm_per_px_declared": args.mm_per_px,
                "frame_sha256": frame_digest,
            },
            provenance_class=provenance,
            observer_id=args.observer_id,
            sequence=seq,
            timestamp_ms=t0 + seq,
            detector_version=cv2.__version__,
        ))

    if "start" in centres and "end" in centres:
        dx = centres["end"][0] - centres["start"][0]
        dy = centres["end"][1] - centres["start"][1]
        dist_px = float((dx * dx + dy * dy) ** 0.5)
        records.append(observation_record(
            detection=Detection(args.marker_id, centres["end"], []),
            event_type="Displacement",
            payload={
                "displacement_px": dist_px,
                "displacement_mm": dist_px * args.mm_per_px,
                "mm_per_px_declared": args.mm_per_px,
                "from_px": list(centres["start"]),
                "to_px": list(centres["end"]),
            },
            provenance_class=provenance,
            observer_id=args.observer_id,
            sequence=len(frames) + 1,
            timestamp_ms=t0 + len(frames) + 1,
            detector_version=cv2.__version__,
        ))

    manifest = {
        "experiment_id": "ROBOTICS-PHYSICAL-OBSERVATION-001",
        "run_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_mode": args.source,
        "provenance_class": provenance,
        "anchored_collector_asserted_by_operator": bool(args.anchored_collector),
        "tag_family": TAG_FAMILY,
        "opencv_version": cv2.__version__,
        "numpy_version": np.__version__,
        "python": sys.version.split()[0],
        "seed": args.seed,
        "mm_per_px_declared": args.mm_per_px,
        "calibration_performed": False,
        "marker_attachment_verified": False,
        "physical_claim_supported": False,
        "why": ("A synthetic scene is not an observation of any world. A real camera without an "
                "anchored collector is a party the verifier cannot name. Neither reaches a "
                "physical-effect claim in this build, because no SourceMechanism carries an "
                "optical observation."),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "observations.json").write_text(json.dumps(records, indent=2) + "\n")

    print(f"wrote {len(records)} record(s) to {out}")
    print(f"provenance class: {provenance}")
    print("physical claim supported: NO")
    return 0


def _fail(msg: str) -> int:
    print(f"REFUSED: {msg}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
