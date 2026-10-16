"""Run the whole Component 4 pipeline in order (simulated data).

simulate -> features -> trends -> forecast -> risk -> correlation -> recommend -> export -> report

Each step reads the previous steps' files (paths in config.yaml), so any step
can also be run on its own with `python -m src.<step>`. When Component 2 is
ready, its events replace the simulate step and everything after it runs
unchanged.
"""

import argparse
import time

from . import correlation, export, features, forecast, recommend, report, risk, simulate, trends


def run(quick=False):
    steps = [
        ("simulate", lambda: simulate.run()),
        ("features", features.main),
        ("trends", trends.main),
        ("forecast", lambda: forecast.run(quick=quick)),
        ("risk", lambda: risk.run(quick=quick)),
        ("correlation", correlation.run),
        ("recommend", recommend.run),
        ("export", export.run),
        ("report", report.run),
    ]
    start = time.time()
    for i, (name, step) in enumerate(steps, start=1):
        print(f"\n=== [{i}/{len(steps)}] {name} ===")
        t0 = time.time()
        step()
        print(f"--- {name} done in {time.time() - t0:.0f} s")
    print(f"\nPipeline finished in {time.time() - start:.0f} s{' (quick mode)' if quick else ''}.")


def main():
    parser = argparse.ArgumentParser(description="Run simulate -> ... -> export -> report (simulated data).")
    parser.add_argument("--quick", action="store_true", help="quick forecast and risk settings for a smoke test")
    run(quick=parser.parse_args().quick)


if __name__ == "__main__":
    main()
