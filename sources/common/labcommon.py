#!/usr/bin/env python3
"""
labcommon.py - helpers shared by the lab containers.

Every container reads the same start time T0 from /results/t0 (written once by the
run script, using the clock of the Docker VM). All logs use absolute Unix
timestamps, and the analysis shifts them to "seconds since T0", so the client,
detector and attacker logs line up exactly.
"""
import os
import time

RESULTS = os.getenv("RESULTS", "/results")
T0_FILE = os.getenv("LAB_T0_FILE", os.path.join(RESULTS, "t0"))
EVENTS = os.path.join(RESULTS, "events.csv")


def read_t0(timeout=300.0):
    """Wait for /results/t0 to exist and return the start time (does not sleep until it)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(T0_FILE) as f:
                return float(f.read().strip())
        except (OSError, ValueError):
            time.sleep(0.2)
    raise SystemExit(f"[labcommon] no start time found in {T0_FILE}")


def sleep_until(ts):
    delay = ts - time.time()
    if delay > 0:
        time.sleep(delay)


def log_event(source, event, detail=""):
    """Append one line to the shared timeline. Keep detail free of commas."""
    detail = str(detail).replace(",", ";").replace("\n", " ")
    line = f"{time.time():.3f},{source},{event},{detail}\n"
    # One short write in append mode: safe when many containers write at once.
    with open(EVENTS, "a", encoding="utf-8") as f:
        f.write(line)
