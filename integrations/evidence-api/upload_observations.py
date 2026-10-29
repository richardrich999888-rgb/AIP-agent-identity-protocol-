"""File a stable collector archive snapshot using an institutional Machine key.

The API verifies against separately provisioned, tenant-bound public anchors.
This operator tool never receives an evidence private key and never runs on
the monitored workload as a requirement of observation.
"""

import argparse
import json
import os
from pathlib import Path
from urllib.request import Request

from vanian import VanianClient


def bounded_file(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("snapshot exceeds API admission limit; export a smaller signed window")
    return data.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer-id", required=True)
    parser.add_argument("--key-version", type=int, required=True)
    parser.add_argument("--batches", required=True)
    parser.add_argument("--health", required=True)
    args = parser.parse_args()
    client = VanianClient(os.environ["VANIAN_BASE_URL"], lambda: os.environ["VANIAN_API_TOKEN"],
        retries=0, ca_file=os.environ.get("VANIAN_CA_FILE"))
    batches = bounded_file(args.batches, 524288)
    health = bounded_file(args.health, 524288 - len(batches.encode()))
    data = json.dumps({"observer_id": args.observer_id, "key_version": args.key_version,
        "batches_jsonl": batches, "health_jsonl": health}).encode()
    token = client.credential_provider()
    if not token or any(c.isspace() for c in token):
        raise ValueError("invalid bearer credential")
    request = Request(client.base_url + "/v1/observations", data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token}, method="POST")
    with client._opener.open(request, timeout=client.timeout) as response:
        raw = response.read(4097)
    if len(raw) > 4096:
        raise ValueError("unexpected response size")
    result = json.loads(raw)
    # Metadata only: no records, credentials or key material in the transcript.
    print(json.dumps({"observation_id": result["observation_id"], "verification_scope": result["verification_scope"]}))


if __name__ == "__main__":
    main()
