#!/usr/bin/env python3
"""
client_monitor.py - one legitimate user.

Sends an HTTP request to the victim at a steady pace for the whole timeline and
records success and latency. This is how the lab measures the real effect of the
attack on availability and the real effect of the defense.

Scale it (docker compose up --scale client=6): each container has its own IP and
its own request rate, like different users.
"""
import csv
import http.client
import os
import random
import socket
import time

from labcommon import RESULTS, read_t0, sleep_until

VICTIM = os.getenv("VICTIM_IP", "172.20.0.2")
TOTAL = float(os.getenv("TOTAL", "220"))
BASELINE = float(os.getenv("BASELINE", "60"))
ATTACK = float(os.getenv("ATTACK", "120"))
FLASH_MULT = float(os.getenv("FLASH_MULT", "1"))   # flash crowd: same users, more requests
TIMEOUT = 2.0          # a user gives up after 2 s


def my_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "unknown"


def one_request():
    t0 = time.time()
    status = 0
    try:
        conn = http.client.HTTPConnection(VICTIM, 80, timeout=TIMEOUT)
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()
        status = resp.status
        conn.close()
    except Exception:
        status = 0
    return status == 200, status, time.time() - t0


def main():
    t0 = read_t0()
    ip = my_ip()
    os.makedirs(os.path.join(RESULTS, "clients"), exist_ok=True)
    open(os.path.join(RESULTS, "clients", ip), "w").close()      # ground truth: this IP is legitimate

    rng = random.Random(hash(ip) & 0xFFFF)
    interval = rng.uniform(0.25, 0.6)           # each user has its own pace (about 2-4 requests/s)
    sleep_until(t0 + rng.uniform(0, 1.0))
    print(f"[client {ip}] start, interval about {interval:.2f}s, total {TOTAL:.0f}s", flush=True)

    out = os.path.join(RESULTS, f"client_{ip}.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "t", "ok", "status", "latency_ms"])
        while time.time() - t0 < TOTAL:
            ok, status, lat = one_request()
            now = time.time()
            w.writerow([f"{now:.3f}", f"{now - t0:.3f}", int(ok), status, f"{lat * 1000:.1f}"])
            f.flush()
            pace = interval
            if FLASH_MULT > 1 and BASELINE <= now - t0 < BASELINE + ATTACK:
                pace = interval / FLASH_MULT
            time.sleep(max(0.0, pace * rng.uniform(0.7, 1.3) - lat))
    print(f"[client {ip}] done", flush=True)


if __name__ == "__main__":
    main()
