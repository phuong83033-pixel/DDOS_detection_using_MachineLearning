#!/usr/bin/env python3
"""
detector.py - real-time DDoS detector for the Docker lab (Topic 10).

Runs in the victim's network namespace, reads packet headers live, and works in
two layers, as described in the midterm report:

  Layer 1 - window statistics (every WINDOW seconds)
      Packet rate, Shannon entropy of the source addresses, SYN/ACK ratio,
      UDP share, unique-source ratio. The normal range is learned from the first
      CALIB_WINDOWS windows. A window raises the alarm when the packet rate is
      well above normal AND the mix of sources has changed (entropy moved more
      than K_Z standard deviations, or the number of distinct sources doubled),
      or when SYNs far outnumber ACKs (SYN flood). A flash crowd (same users, more
      requests) raises the rate but not the source mix, so it does not alarm.
      The window also gets an attack type: syn_flood / udp_flood / http_flood.

  Layer 2 - who is attacking
      http / udp flood : K-means (k=3) on the packets-per-source counts, then the
                         entropy-ratio test from the midterm: a source is an
                         attacker if adding it to the "normal" group drops the
                         entropy below RATIO_RHO of its value. Attackers are
                         blocked with iptables.
      syn flood        : the sources are forged, so there is nobody to block.
                         SYN cookies are switched on instead (iptables SYN rate
                         limit as fallback).
      ML mode          : when a trained model is present (ml_layer.py), flow
                         classification decides which sources are attackers.

Every window also records what a fixed packet-rate threshold would have said, so
analyze_results.py can compare the two detectors on the same data.

Output (in /results):  detector_windows.csv, events.csv (shared timeline)
"""
import csv
import math
import os
import shutil
import subprocess
import sys
import time
from collections import Counter

import numpy as np

from capture import Capture, ip_to_str, str_to_ip, TCP, UDP, SYN, ACK
from labcommon import RESULTS, read_t0, log_event

ENV = os.environ.get
IFACE = ENV("IFACE", "eth0")
VICTIM_IP = ENV("VICTIM_IP", "172.20.0.2")
GATEWAY_IP = ENV("GATEWAY_IP", "172.20.0.1")
WINDOW = float(ENV("WINDOW", "5"))
CALIB_WINDOWS = int(ENV("CALIB_WINDOWS", "5"))
TOTAL = float(ENV("TOTAL", "220"))
K_Z = float(ENV("K_Z", "3"))                 # source-entropy shift: |z| above this counts as a composition change
K_FIXED = float(ENV("K_FIXED", "3"))         # fixed-threshold baseline: mean + K*std of packet rate
RATE_GATE = float(ENV("RATE_GATE", "2.0"))   # the alarm needs the packet rate >= 2 x normal ...
SRC_JUMP = float(ENV("SRC_JUMP", "2.0"))     # ... and a changed source mix: entropy shift or >= 2 x distinct sources
DEFENSE_ON = ENV("DEFENSE", "1") == "1"      # 0 = detection only (dry run): log what would be blocked
SYN_MIN_RATE = float(ENV("SYN_MIN_RATE", "50"))     # SYN/s
SYN_ACK_RATIO = float(ENV("SYN_ACK_RATIO", "2.0"))  # SYN packets per ACK packet
RATIO_RHO = float(ENV("RATIO_RHO", "0.95"))
BUSY_FACTOR = float(ENV("BUSY_FACTOR", "2"))   # attacker also sends >= 2 x the busiest normal source of the baseline
BLOCK_TTL = float(ENV("BLOCK_TTL", "300"))   # a block expires after 300 s (midterm slide 18)
QUIET_WINDOWS = int(ENV("QUIET_WINDOWS", "3"))
CONFIRM_WINDOWS = int(ENV("CONFIRM_WINDOWS", "1"))   # suspicious windows in a row needed before the alarm acts (1 = at once)
MODE_REQ = ENV("DETECTOR_MODE", "auto").lower()
MODEL_DIR = ENV("MODEL_DIR", "/app/models")
RECORD_FLOWS = ENV("RECORD_FLOWS", "0") == "1"   # write flow features to /results/lab_flows.csv (training data)

NEVER_BLOCK = {str_to_ip(VICTIM_IP), str_to_ip(GATEWAY_IP)}

CSV_COLUMNS = [
    "ts", "t", "mode", "window", "pkts", "pps", "bytes", "uniq_src", "H_src", "Hn_src",
    "z_H", "z_pps", "syn_in", "syn_rate", "ack_in", "syn_ack_ratio", "udp_share",
    "syn_uniq_ratio", "synack_out", "kern_pkts", "kern_drops", "ml_flows", "ml_attack_flows",
    "alarm_entropy", "alarm_syn", "alarm_thr", "alarm", "attack_type", "n_blocked", "action",
]


def entropy_bits(counts):
    c = np.asarray(list(counts), dtype=float)
    c = c[c > 0]
    if c.size == 0:
        return 0.0
    p = c / c.sum()
    return float(-(p * np.log2(p)).sum())


# --------------------------------------------------------------------------- defense
class Defense:
    """iptables blocks and SYN-flood protection, applied inside the victim's namespace."""

    def __init__(self):
        self.blocked = {}                 # ip (int) -> time it was blocked
        self.syn_protection = None        # None | "tcp_syncookies" | "iptables_hashlimit"
        self.ipt = self._find_iptables()
        print(f"[defense] iptables backend: {self.ipt or 'NOT AVAILABLE'}", flush=True)

    @staticmethod
    def _find_iptables():
        for cmd in ("iptables", "iptables-legacy", "iptables-nft"):
            if shutil.which(cmd):
                r = subprocess.run([cmd, "-w", "-L", "INPUT", "-n"], capture_output=True)
                if r.returncode == 0:
                    return cmd
        return None

    def block(self, ips):
        ips = [ip for ip in ips if ip not in self.blocked and ip not in NEVER_BLOCK]
        if not ips or not self.ipt:
            return []
        restore = shutil.which(self.ipt + "-restore")
        ok = False
        if restore:
            rules = "*filter\n" + "".join(f"-I INPUT -s {ip_to_str(ip)} -j DROP\n" for ip in ips) + "COMMIT\n"
            ok = subprocess.run([restore, "--noflush"], input=rules, text=True,
                                capture_output=True).returncode == 0
        if not ok:                         # fall back to one call per address
            done = []
            for ip in ips:
                if subprocess.run([self.ipt, "-w", "-I", "INPUT", "-s", ip_to_str(ip), "-j", "DROP"],
                                  capture_output=True).returncode == 0:
                    done.append(ip)
            ips = done
        now = time.time()
        for ip in ips:
            self.blocked[ip] = now
        return ips

    def expire(self):
        now = time.time()
        for ip in [i for i, t in self.blocked.items() if now - t > BLOCK_TTL]:
            if self.ipt:
                subprocess.run([self.ipt, "-w", "-D", "INPUT", "-s", ip_to_str(ip), "-j", "DROP"],
                               capture_output=True)
            del self.blocked[ip]
            log_event("detector", "unblock", ip_to_str(ip))

    def enable_syn_protection(self):
        """SYN cookies if /proc/sys is writable, otherwise an iptables SYN rate limit."""
        if self.syn_protection:
            return self.syn_protection
        try:
            with open("/proc/sys/net/ipv4/tcp_syncookies", "w") as f:
                f.write("1")
            with open("/proc/sys/net/ipv4/tcp_syncookies") as f:
                if f.read().strip() == "1":
                    self.syn_protection = "tcp_syncookies"
        except OSError as e:
            print(f"[defense] cannot write tcp_syncookies: {e}", flush=True)
        if not self.syn_protection and self.ipt:
            r = subprocess.run([self.ipt, "-w", "-A", "INPUT", "-p", "tcp", "--syn", "-m", "hashlimit",
                                "--hashlimit-name", "synlimit", "--hashlimit-mode", "srcip",
                                "--hashlimit-above", "50/sec", "--hashlimit-burst", "100", "-j", "DROP"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                self.syn_protection = "iptables_hashlimit"
            else:
                print(f"[defense] hashlimit failed: {r.stderr.strip()}", flush=True)
        return self.syn_protection or "failed"


# ---------------------------------------------------------------------- attribution
def attribute(counts, busiest_normal):
    """K-means (k=3) on packets-per-source, then the entropy-ratio test.

    counts: {source ip (int): packets in this window}. Returns [(ip, packets, ratio)].
    The lowest K-means cluster is the "normal" group. A source outside it is an
    attacker when adding it to the normal group lowers the entropy below RATIO_RHO
    of its value (a normal user leaves the ratio near 1) AND it sends at least
    BUSY_FACTOR times the packets of the busiest source seen during calibration.
    The second condition stops starved or unevenly served real users from being
    mistaken for attackers while the server is overloaded.
    """
    if len(counts) < 4:
        return []
    from sklearn.cluster import KMeans
    items = list(counts.items())
    vals = np.log1p(np.array([c for _, c in items], dtype=float)).reshape(-1, 1)
    km = KMeans(n_clusters=3, n_init=5, random_state=0).fit(vals)
    low = int(np.argmin(km.cluster_centers_.ravel()))
    normal = [c for (_, c), lab in zip(items, km.labels_) if lab == low]
    h0 = entropy_bits(normal)
    if h0 <= 0:
        return []
    floor = max(50.0, BUSY_FACTOR * busiest_normal)
    out = []
    for (ip, c), lab in zip(items, km.labels_):
        if lab == low or c < floor:
            continue
        ratio = entropy_bits(normal + [c]) / h0
        if ratio < RATIO_RHO:
            out.append((ip, c, ratio))
    return out


# ------------------------------------------------------------------------- window
class Window:
    def __init__(self):
        self.pkts = self.bytes = self.tcp = self.udp = 0
        self.syn = self.ack = self.synack_out = 0
        self.src = Counter()
        self.syn_src = set()


class Baseline:
    def __init__(self):
        self.pps, self.H, self.syn_rate, self.uniq, self.top_src = [], [], [], [], []
        self.ready = False
        self.mu_pps = self.sd_pps = self.mu_H = self.sd_H = self.mu_uniq = self.busiest = 0.0

    def add(self, pps, H, syn_rate, uniq, top_src):
        self.top_src.append(top_src)
        self.uniq.append(uniq)
        self.pps.append(pps)
        self.H.append(H)
        self.syn_rate.append(syn_rate)

    def fit(self):
        self.mu_pps = float(np.mean(self.pps))
        # floors keep a quiet baseline from making the thresholds hypersensitive
        self.sd_pps = max(float(np.std(self.pps)), 0.25 * self.mu_pps, 5.0)
        self.mu_H = float(np.mean(self.H))
        self.sd_H = max(float(np.std(self.H)), 0.15)
        self.mu_uniq = max(float(np.mean(self.uniq)), 1.0)
        self.busiest = float(max(self.top_src)) if self.top_src else 0.0
        self.ready = True
        print(f"[baseline] pps={self.mu_pps:.1f} (sd {self.sd_pps:.1f})  H={self.mu_H:.2f} bits "
              f"(sd {self.sd_H:.2f})  sources={self.mu_uniq:.1f}  busiest source={self.busiest:.0f} pkts/window", flush=True)
        log_event("detector", "baseline",
                  f"pps={self.mu_pps:.1f};H={self.mu_H:.2f};sd_pps={self.sd_pps:.1f};sd_H={self.sd_H:.2f};sources={self.mu_uniq:.1f}")


# --------------------------------------------------------------------------- main
def main():
    t0 = read_t0()
    ml = None
    try:
        from ml_layer import load_ml_layer
        ml = load_ml_layer(
            MODEL_DIR, use_model=MODE_REQ in ("auto", "ml"),
            record_path=os.path.join(RESULTS, "lab_flows.csv") if RECORD_FLOWS else None,
            t0=t0, ignore={str_to_ip(VICTIM_IP)})
    except Exception as e:                           # a broken model must not break the lab
        print(f"[ml] could not start the ML layer: {e}", flush=True)
    if MODE_REQ == "ml" and not (ml and ml.has_model):
        sys.exit("[ERROR] DETECTOR_MODE=ml but no usable model in " + MODEL_DIR)
    ml_active = bool(ml and ml.has_model)
    mode = "ML" if ml_active else "ENTROPY"

    defense = Defense()
    cap = Capture(IFACE)
    base = Baseline()
    log_event("detector", "start", f"mode={mode};window={WINDOW};iptables={defense.ipt};k_z={K_Z};defense={int(DEFENSE_ON)};confirm={CONFIRM_WINDOWS}")
    print(f"[detector] mode={mode}  window={WINDOW}s  confirm={CONFIRM_WINDOWS} window(s)  total={TOTAL}s", flush=True)

    out_path = os.path.join(RESULTS, "detector_windows.csv")
    f = open(out_path, "w", newline="", encoding="utf-8")
    writer = csv.writer(f)
    writer.writerow(CSV_COLUMNS)

    w = Window()
    k = 0                       # window index
    in_episode = False
    quiet = 0
    suspect = [0]               # consecutive suspicious windows (a list so close_window can change it)
    syn_noted = False
    would_block = set()                                  # dry-run only
    cap.kernel_stats()          # reset kernel counters
    end_time = t0 + TOTAL
    total_pkts = total_drops = 0

    def close_window(k, w, now):
        nonlocal in_episode, quiet, syn_noted, total_pkts, total_drops
        T = WINDOW
        pps = w.pkts / T
        uniq = len(w.src)
        H = entropy_bits(w.src.values())
        Hn = H / math.log2(uniq) if uniq > 1 else (1.0 if uniq == 1 else 0.0)
        syn_rate = w.syn / T
        syn_ack_ratio = w.syn / max(1, w.ack)
        udp_share = w.udp / max(1, w.pkts)
        syn_uniq_ratio = len(w.syn_src) / max(1, w.syn)
        kp, kd = cap.kernel_stats()
        total_pkts += kp
        total_drops += kd

        ml_flows = ml_attack = 0
        ml_votes = {}
        if ml:
            ml_flows, ml_attack, ml_votes = ml.end_window(now)

        z_H = z_pps = float("nan")
        a_ent = a_syn = a_thr = 0
        if 1 <= k <= CALIB_WINDOWS:                       # window 0 is start-up noise
            base.add(pps, H, syn_rate, uniq, max(w.src.values()) if w.src else 0)
            if k == CALIB_WINDOWS:
                base.fit()
        elif base.ready:
            z_H = (H - base.mu_H) / base.sd_H
            z_pps = (pps - base.mu_pps) / base.sd_pps
            a_thr = int(z_pps > K_FIXED)                  # fixed packet-rate threshold (comparison baseline)
            rate_surge = pps >= RATE_GATE * base.mu_pps
            new_mix = abs(z_H) > K_Z or uniq >= SRC_JUMP * base.mu_uniq
            a_ent = int(rate_surge and new_mix)
            a_syn = int(syn_rate >= SYN_MIN_RATE and syn_ack_ratio >= SYN_ACK_RATIO)
        alarm = int(bool(a_ent or a_syn or (ml_active and ml_attack >= 10)))   # this window looks like an attack
        suspect[0] = suspect[0] + 1 if alarm else 0
        # The alarm only acts (announce, block) after CONFIRM_WINDOWS suspicious windows in a row,
        # or at once if an attack episode is already running.
        act = bool(alarm and (in_episode or suspect[0] >= CONFIRM_WINDOWS))
        if alarm and not act:
            print(f"[SUSPECT] window {k}: pps={pps:.0f}  waiting to confirm ({suspect[0]}/{CONFIRM_WINDOWS})", flush=True)

        attack_type = ""
        action = ""
        if act:
            if a_syn:
                attack_type = "syn_flood"
            elif udp_share > 0.5:
                attack_type = "udp_flood"
            else:
                attack_type = "http_flood"
            if not in_episode:
                in_episode = True
                log_event("detector", "alarm",
                          f"{attack_type};z_H={z_H:.1f};pps={pps:.0f};window={k}")
                print(f"[ALARM] window {k}: {attack_type}  pps={pps:.0f}  z_H={z_H:+.1f}", flush=True)
            quiet = 0

            if attack_type == "syn_flood":
                if not syn_noted:
                    syn_noted = True
                    if DEFENSE_ON:
                        method = defense.enable_syn_protection()
                        action = f"syn_protection:{method}"
                        log_event("detector", "syncookies", method)
                        print(f"[DEFEND] SYN protection: {method}", flush=True)
                    else:
                        log_event("detector", "would_syncookies", "dry-run")
                        print("[DRY-RUN] would enable SYN protection", flush=True)
            else:
                residual = {ip: c for ip, c in w.src.items()
                            if ip not in defense.blocked and ip not in NEVER_BLOCK}
                if ml_active:
                    # enough attack-flagged flows AND a clearly abnormal packet rate (same guard as K-means)
                    floor = max(50.0, BUSY_FACTOR * base.busiest)
                    attackers = [ip for ip, votes in ml_votes.items()
                                 if ip in residual and votes >= ml.k_votes and residual[ip] >= floor]
                    detail = {ip: f"ml;votes={ml_votes[ip]}" for ip in attackers}
                    why = "ml"
                else:
                    found = attribute(residual, base.busiest)
                    attackers = [ip for ip, _, _ in found]
                    detail = {ip: f"kmeans_ratio;pkts={c};ratio={r:.2f}" for ip, c, r in found}
                    why = "kmeans_ratio"
                if not DEFENSE_ON:                       # detection only: record, do not touch iptables
                    new = [ip for ip in attackers if ip not in would_block]
                    would_block.update(new)
                    for ip in new:
                        log_event("detector", "would_block", f"{ip_to_str(ip)};{detail[ip]}")
                    done = []
                else:
                    done = defense.block(attackers)
                if done:
                    action = f"block:{len(done)}"
                    for ip in done:
                        log_event("detector", "block", f"{ip_to_str(ip)};{detail[ip]}")
                    print(f"[DEFEND] blocked {len(done)} sources ({why})", flush=True)
        else:
            quiet += 1
            if in_episode and quiet >= QUIET_WINDOWS:
                in_episode = False
                log_event("detector", "recovered", f"window={k}")
                print(f"[OK] traffic back to normal (window {k})", flush=True)

        defense.expire()
        writer.writerow([
            f"{now:.3f}", f"{now - t0:.1f}", mode, k, w.pkts, f"{pps:.1f}", w.bytes, uniq,
            f"{H:.3f}", f"{Hn:.3f}", f"{z_H:.2f}", f"{z_pps:.2f}", w.syn, f"{syn_rate:.1f}", w.ack,
            f"{syn_ack_ratio:.2f}", f"{udp_share:.3f}", f"{syn_uniq_ratio:.3f}", w.synack_out,
            kp, kd, ml_flows, ml_attack, a_ent, a_syn, a_thr, alarm, attack_type,
            len(defense.blocked), action,
        ])
        f.flush()
        if k % 4 == 0 and not alarm:
            print(f"[w{k:03d}] pps={pps:7.1f}  src={uniq:3d}  H={H:.2f}  z_H={z_H:+.1f}  "
                  f"syn/s={syn_rate:.0f}", flush=True)

    # ---- capture loop: packets are assigned to the window their timestamp falls in ----
    while True:
        p = cap.read()
        now = time.time()
        while now >= t0 + (k + 1) * WINDOW:
            close_window(k, w, t0 + (k + 1) * WINDOW)
            w = Window()
            k += 1
        if now >= end_time:
            break
        if p is None or p.ts < t0:
            continue
        if ml:
            ml.add_packet(p)
        if p.inbound:
            if p.src in defense.blocked:
                w.src[p.src] += 1                         # still counted: the attack is still going on
                w.pkts += 1
                w.bytes += p.ip_len
                if p.proto == UDP:
                    w.udp += 1
                continue
            w.pkts += 1
            w.bytes += p.ip_len
            w.src[p.src] += 1
            if p.proto == TCP:
                w.tcp += 1
                if p.flags & SYN and not p.flags & ACK:
                    w.syn += 1
                    w.syn_src.add(p.src)
                elif p.flags & ACK:
                    w.ack += 1
            elif p.proto == UDP:
                w.udp += 1
        elif p.proto == TCP and p.flags & SYN and p.flags & ACK:
            w.synack_out += 1

    f.close()
    loss = 100.0 * total_drops / max(1, total_pkts)
    log_event("detector", "stop", f"windows={k};kernel_pkts={total_pkts};kernel_drops={total_drops};loss={loss:.2f}%")
    print(f"[detector] done. windows={k}  kernel packets={total_pkts}  dropped={total_drops} ({loss:.2f}%)",
          flush=True)


if __name__ == "__main__":
    main()
