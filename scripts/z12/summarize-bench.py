#!/usr/bin/env python3
import math
import re
import statistics
import sys
from pathlib import Path

files = [Path(p) for p in sys.argv[1:]]
records = {}
for path in files:
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"^(Benchmark\S+)\s+\d+\s+([0-9.]+) ns/op(.*)$", line.strip())
        if not m:
            continue
        name, value, tail = m.groups()
        records.setdefault(name, []).append(float(value))
        for metric, metric_value in re.findall(r"([0-9.]+)\s+(witness-ns/op|prove-ns/op|local-verify-ns/op|gateway-total-ns/op)", tail):
            records.setdefault(name + ":" + metric_value, []).append(float(metric))

for name, values in records.items():
    ordered = sorted(values)
    n = len(ordered)
    p95 = ordered[max(0, math.ceil(.95*n)-1)]
    p99 = f"{ordered[max(0, math.ceil(.99*n)-1)]:.0f}" if n >= 100 else "not reported (N<100)"
    sd = statistics.stdev(ordered) if n > 1 else 0.0
    median = statistics.median(ordered)
    print(f"{name}: N={n}; mean={statistics.mean(ordered):.0f} ns; median={median:.0f} ns; min={ordered[0]:.0f} ns; max={ordered[-1]:.0f} ns; P95={p95:.0f} ns; P99={p99}; sample_SD={sd:.0f} ns")
if not records:
    print("No Go benchmark samples parsed.")
    raise SystemExit(1)
