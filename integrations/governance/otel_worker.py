#!/usr/bin/env python3
"""Runs only in the isolated pinned SDK interpreter, after controller cleanup."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--endpoint', required=True)
    args = parser.parse_args()
    endpoint = urlsplit(args.endpoint)
    if (endpoint.scheme != 'http' or endpoint.hostname != '127.0.0.1' or
            not endpoint.port or not 1 <= endpoint.port <= 65535 or endpoint.path != '/v1/traces'
            or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment):
        raise ValueError('only the bounded local Collector endpoint is approved')
    spec = importlib.util.spec_from_file_location('aip_controller_telemetry_validation', Path(__file__).with_name('telemetry.py'))
    validation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validation)
    payload = validation.read_json(args.input)
    if type(payload) is not dict or set(payload) != {'nonce', 'records'} or type(payload['nonce']) is not str or not re.fullmatch('[0-9a-f]{32}', payload['nonce']):
        raise ValueError('invalid private controller export request')
    records = validation.validate_records(payload['records'])
    # No SDK is imported by the core controller. Only this isolated process
    # imports OpenTelemetry and its own compatible protobuf/HTTP packages.
    import requests
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.trace import Status, StatusCode

    session = requests.Session()
    session.trust_env = False  # no caller proxies, netrc authentication or cookies
    exporter = OTLPSpanExporter(endpoint=args.endpoint, headers={}, session=session, timeout=8, max_request_size=1024 * 1024)
    provider = TracerProvider(resource=Resource({'service.name': 'aip-validation-controller',
        'aip.source_authority': validation.SOURCE}), shutdown_on_exit=False)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer('aip.controller.governance', '1.0')
    root_index = next(i for i, r in enumerate(records) if r['phase'] == 'aip.run')
    def attributes(index):
        return {**records[index]['attributes'], 'aip.telemetry.export_nonce': payload['nonce'],
            'aip.telemetry.record_index': index, 'aip.telemetry.export_mode': validation.MODE}
    whole = records[root_index]
    root = tracer.start_span(whole['phase'], start_time=whole['start_time_unix_nano'], attributes=attributes(root_index))
    context = trace.set_span_in_context(root)
    try:
        for index, record in enumerate(records):
            if index == root_index: continue
            span = tracer.start_span(record['phase'], context=context, start_time=record['start_time_unix_nano'], attributes=attributes(index))
            if record['attributes'].get('aip.controller.status') in ('FAIL', 'ERROR'):
                span.set_status(Status(StatusCode.ERROR))
            span.end(end_time=record['end_time_unix_nano'])
        if whole['attributes'].get('aip.controller.status') in ('FAIL', 'ERROR'):
            root.set_status(Status(StatusCode.ERROR))
        trace_id = format(root.get_span_context().trace_id, '032x')
        root.end(end_time=whole['end_time_unix_nano'])
        if not provider.force_flush(timeout_millis=10000):
            raise RuntimeError('bounded SDK flush did not complete')
    finally:
        provider.shutdown()
        session.close()
    print(json.dumps({'status': 'PASS', 'classification': validation.SOURCE,
        'export_mode': validation.MODE, 'nonce': payload['nonce'], 'span_count': len(records),
        'trace_id': trace_id, 'claim_limit': 'SDK execution returned; the controller must separately verify original Collector receipt'}))


if __name__ == '__main__':
    raise SystemExit(main())
