"""
benchmark.py
============
Throughput / latency benchmark for the dashboard's data pipeline — measured, not
claimed. It times the two hot paths the "real-time" claim depends on:

  * **normalise** — raw Wazuh/Suricata alert dicts → canonical DataFrame
    (``data_processor.normalize_alerts``), and
  * **metrics**  — full evaluation bundle over that DataFrame
    (``metrics.compute_all``: confusion matrix, MTTD, 3-way baseline, …).

For each target alert volume it reports the best-of-N wall-clock time and the
derived throughput (alerts/second), so you can show how processing scales with
load. Run it to (re)produce the numbers for the dissertation's performance
section:

    python src/benchmark.py                       # default size sweep -> table + CSV
    python src/benchmark.py -n 1000 5000 20000    # custom sizes
"""

from __future__ import annotations

import argparse
import os
import time
from typing import Any

import pandas as pd

import data_processor as dp
import ingest
import metrics as mx
from config import settings
from logging_config import get_logger

log = get_logger("benchmark")

DEFAULT_SIZES = (1_000, 5_000, 10_000, 25_000, 50_000, 100_000)


def _base_alerts(min_n: int = 1000) -> list[dict[str, Any]]:
    """A pool of canonical alert dicts to replicate up to each target size."""
    import mock_data_generator as mdg

    alerts = ingest.read_mock_alerts()
    if len(alerts) < min_n:
        mdg.generate()
        alerts = ingest.read_mock_alerts()
    return alerts


def run_benchmark(
    sizes: tuple[int, ...] | list[int] = DEFAULT_SIZES, *, repeats: int = 3
) -> pd.DataFrame:
    """Time the normalise + metrics pipeline at each alert volume in ``sizes``.

    Returns a DataFrame with one row per size: normalise/metrics/total time (ms)
    and throughput (alerts/sec, based on total time). ``repeats`` runs are taken
    and the best (lowest-noise) time is reported per stage.
    """
    base = _base_alerts(min_n=max(1, min(sizes)))
    gt = ingest.load_ground_truth()
    rows: list[dict[str, Any]] = []

    for n in sizes:
        # Replicate the canonical pool up to the target volume.
        reps = (n // len(base)) + 1
        raw = (base * reps)[:n]

        norm_best = float("inf")
        df: pd.DataFrame = pd.DataFrame()
        for _ in range(max(1, repeats)):
            t0 = time.perf_counter()
            df = dp.normalize_alerts(raw)
            norm_best = min(norm_best, time.perf_counter() - t0)

        met_best = float("inf")
        for _ in range(max(1, repeats)):
            t0 = time.perf_counter()
            mx.compute_all(df, gt)
            met_best = min(met_best, time.perf_counter() - t0)

        total = norm_best + met_best
        rows.append(
            {
                "alerts": n,
                "normalise_ms": round(norm_best * 1000, 1),
                "metrics_ms": round(met_best * 1000, 1),
                "total_ms": round(total * 1000, 1),
                "throughput_per_s": int(n / total) if total > 0 else 0,
            }
        )
        log.info(
            "benchmark n=%d total=%.1fms throughput=%d/s",
            n,
            total * 1000,
            rows[-1]["throughput_per_s"],
        )

    return pd.DataFrame(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark the SOC pipeline throughput.")
    ap.add_argument("-n", "--sizes", type=int, nargs="+", default=list(DEFAULT_SIZES))
    ap.add_argument("-r", "--repeats", type=int, default=3)
    ap.add_argument("--out", default=os.path.join(settings.DOCS_DIR, "benchmark_results.csv"))
    args = ap.parse_args(argv)

    df = run_benchmark(tuple(args.sizes), repeats=args.repeats)
    print(df.to_string(index=False))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
