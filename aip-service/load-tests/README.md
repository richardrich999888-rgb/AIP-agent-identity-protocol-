# AIP Identity Load Tests

This folder contains the Locust profile for AIP HTTP load testing. It targets
the real service endpoints:

- `POST /v1/identity/issue`
- `POST /v1/identity/verify`
- `POST /v1/identity/delegate`
- `POST /v1/identity/verify-chain`
- `POST /v1/identity/revoke`

Start the service locally:

```bash
mkdir -p /tmp/airon-aip

AIP_PORT=8081 \
AIP_KEY_PATH=/tmp/airon-aip/signing.key \
AIP_DELEGATION_LOG_PATH=/tmp/airon-aip/delegation.jsonl \
AIP_REVOCATION_LOG_PATH=/tmp/airon-aip/revocation.jsonl \
AIP_ISSUER_URL=http://127.0.0.1:8081 \
cargo run --manifest-path aip-service/Cargo.toml
```

Install and run Locust:

```bash
python3 -m pip install locust

locust -f aip-service/load-tests/locustfile.py \
  --host http://127.0.0.1:8081 \
  --headless \
  -u 500 \
  -r 50 \
  --run-time 5m \
  --csv pilot-results/aip_locust
```

For 50,000 concurrent users, run Locust in distributed mode across dedicated
load-generator hosts. A local Mac run is useful for API correctness and rough
latency screening only; it is not banking-scale concurrency evidence.
