"""Controller measurements; no matched unobserved baseline or complete ground truth."""
import math
import os
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'integrations/real_agents'))
from evidence import ARCHIVES, event_time, records


def snapshot(processes, cgroup):
    result = {'controller_wall_ms':time.time_ns()//1_000_000, 'processes':{}}
    for name, pid in processes.items():
        try:
            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
            status = dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
            result['processes'][name] = {'pid':pid, 'start_ticks':int(fields[19]),
                'cpu_ticks':int(fields[11])+int(fields[12]),
                'lifetime_peak_rss_kib':int(status['VmHWM'].split()[0]) if 'VmHWM' in status else None}
        except (OSError, ValueError, IndexError, KeyError):
            result['processes'][name] = {'pid':pid, 'measurement':'UNAVAILABLE'}
    try:
        cpu = dict(line.split() for line in (Path(cgroup)/'cpu.stat').read_text().splitlines())
        result['workload_cgroup'] = {'usage_usec':int(cpu['usage_usec']),
            'lifetime_peak_memory_bytes':int((Path(cgroup)/'memory.peak').read_text())}
    except (OSError, ValueError, KeyError):
        result['workload_cgroup'] = {'measurement':'UNAVAILABLE'}
    return result


def report(before, after, archive):
    duration = (after['controller_wall_ms']-before['controller_wall_ms'])/1000
    if duration <= 0:
        raise ValueError('nonpositive performance measurement interval')
    processes = {}
    for name, ending in after['processes'].items():
        starting = before['processes'].get(name,{})
        if ('cpu_ticks' not in starting or 'cpu_ticks' not in ending
                or (starting['pid'],starting['start_ticks']) != (ending['pid'],ending['start_ticks'])
                or ending['cpu_ticks'] < starting['cpu_ticks']):
            processes[name] = {'measurement':'UNAVAILABLE_OR_PROCESS_CHANGED'}
            continue
        seconds = (ending['cpu_ticks']-starting['cpu_ticks'])/os.sysconf('SC_CLK_TCK')
        processes[name] = {'controller_measured_cpu_seconds':seconds,
            'cpu_percent_of_one_core_during_interval':seconds/duration*100,
            'lifetime_peak_rss_kib':ending['lifetime_peak_rss_kib'],
            'scope':'named service process only; excludes child-process CPU'}
    group = {'measurement':'UNAVAILABLE'}
    if 'usage_usec' in before['workload_cgroup'] and 'usage_usec' in after['workload_cgroup']:
        use = after['workload_cgroup']['usage_usec']-before['workload_cgroup']['usage_usec']
        if use >= 0:
            group = {'controller_measured_cpu_seconds':use/1_000_000,
                'lifetime_peak_memory_bytes':after['workload_cgroup']['lifetime_peak_memory_bytes'],
                'scope':'all constrained model/gateway/tool/agent descendants; includes service work in interval'}
    batches = records(Path(archive)/ARCHIVES[0])
    latency = []
    unknown_times = 0
    count = 0
    for signed in batches:
        for event in signed['batch']['kernel_events']:
            count += 1
            stamp = event_time(signed['batch'],event)
            if stamp is None:
                unknown_times += 1
            else:
                latency.append(signed['attested_at_ms']-stamp)
    latency.sort()
    boundaries = [signed['batch'][field] for signed in batches for field in ('claimed_from_ms','claimed_to_ms')]
    span = (max(boundaries)-min(boundaries))/1000 if boundaries else 0
    timings = {'samples':len(latency),'unknown_event_time':unknown_times,
        'scope':'signed clock-anchor event time to collector attestation; includes queue/transport/signing; not isolated collector processing'}
    if latency:
        timings.update(min_ms=latency[0],median_ms=statistics.median(latency),
            p95_ms=latency[max(0,math.ceil(len(latency)*0.95)-1)],max_ms=latency[-1],
            negative_clock_uncertainty_samples=sum(x<0 for x in latency))
    return {'classification':'MEASURED_OBSERVED_RUN_WITHOUT_MATCHED_BASELINE',
        'measurement_from_ms':before['controller_wall_ms'],'measurement_to_ms':after['controller_wall_ms'],
        'elapsed_seconds':duration,'processes':processes,'workload_cgroup':group,
        'archive_storage_bytes':sum((Path(archive)/name).stat().st_size for name in ARCHIVES),
        'signed_kernel_events':count,'archive_claimed_span_seconds':span,
        'archive_event_rate_per_second':count/span if span>0 else None,
        'event_to_attestation_latency':timings,'reconciliation_processing_latency_ms':None,
        'matched_observer_overhead_percent':None,'agent_task_completion_impact_percent':None,
        'limitations':['No matched unobserved task baseline; CPU consumption is not causal task overhead.',
            'RSS/memory peaks cover service lifetime, including initialization; CPU deltas cover only declared interval.',
            'Archive rate covers all captured host events, not independently complete workload ground truth.',
            'Latency is estimated from held signed clocks; uncertainty/negative samples remain visible.']}
