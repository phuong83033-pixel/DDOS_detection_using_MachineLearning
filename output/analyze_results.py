#!/usr/bin/env python3
"""
analyze_results.py - turn one lab run into a chart and a summary table.

    python output/analyze_results.py output/runs/http_20261123-150000 --attack http

Reads (all produced by the lab):
    t0, events.csv, detector_windows.csv, client_<ip>.csv,
    attackers/<ip> and clients/<ip>   (ground truth: who is an attacker / a real user)
Writes into the same folder:
    ddos_analysis.png, summary.json, summary.txt

Everything is aligned on t0, the shared start time, so "t" is seconds since the start.
"""
import argparse
import glob
import json
import math
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

BIN = 5.0   # seconds per bin for client curves


def load(run):
    t0 = float(open(os.path.join(run, "t0")).read().strip())
    ev = pd.read_csv(os.path.join(run, "events.csv"), on_bad_lines="skip")
    ev = ev.dropna(subset=["ts"]).copy()
    ev["ts"] = pd.to_numeric(ev["ts"], errors="coerce")
    ev = ev.dropna(subset=["ts"])
    ev["t"] = ev["ts"] - t0
    ev["detail"] = ev["detail"].astype(str)

    frames = [pd.read_csv(p) for p in sorted(glob.glob(os.path.join(run, "client_*.csv")))
              if os.path.getsize(p) > 0]
    cl = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(
        columns=["ts", "t", "ok", "status", "latency_ms"])
    det_path = os.path.join(run, "detector_windows.csv")
    det = pd.read_csv(det_path) if os.path.exists(det_path) else pd.DataFrame()
    return t0, ev, cl, det


def read_ips(folder):
    if not os.path.isdir(folder):
        return set()
    return {n for n in os.listdir(folder) if n.count(".") == 3 and not n.startswith("syn_attacker")}


def binary_metrics(y_true, y_pred):
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if tp and prec == prec and rec == rec else (0.0 if tp + fp + fn else float("nan"))
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else float("nan")
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1, fpr=fpr, mcc=mcc)


def phase_stats(cl, a, b):
    """Client success rate and latency in [a, b)."""
    sub = cl[(cl["t"] >= a) & (cl["t"] < b)]
    if sub.empty:
        return dict(requests=0, success_pct=None, p50_ms=None, p95_ms=None)
    ok = sub[sub["ok"] == 1]["latency_ms"]
    return dict(
        requests=int(len(sub)),
        success_pct=round(100 * float(sub["ok"].mean()), 1),
        p50_ms=round(float(ok.median()), 1) if len(ok) else None,
        p95_ms=round(float(ok.quantile(0.95)), 1) if len(ok) else None,
    )


def success_curve(cl, end):
    if cl.empty:
        return np.array([]), np.array([]), np.array([])
    bins = np.arange(0, end + BIN, BIN)
    idx = np.digitize(cl["t"].to_numpy(), bins) - 1
    succ, lat = [], []
    for i in range(len(bins) - 1):
        m = idx == i
        if m.sum() == 0:
            succ.append(np.nan)
            lat.append(np.nan)
            continue
        succ.append(100 * cl["ok"].to_numpy()[m].mean())
        okm = m & (cl["ok"].to_numpy() == 1)
        lat.append(np.median(cl["latency_ms"].to_numpy()[okm]) if okm.any() else np.nan)
    return bins[:-1], np.array(succ), np.array(lat)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run", help="run folder (contains t0, events.csv, ...)")
    ap.add_argument("--attack", default="?", help="http | udp | syn | none (for the title)")
    args = ap.parse_args()
    run = args.run

    t0, ev, cl, det = load(run)
    end = float(cl["t"].max()) if not cl.empty else float(det["t"].max())
    S = {"run": os.path.basename(os.path.normpath(run)), "attack": args.attack}
    tl_path = os.path.join(run, "timeline.json")
    tl = json.load(open(tl_path)) if os.path.exists(tl_path) else {}
    flash = None                                  # flash crowd: legitimate surge, not an attack
    if args.attack == "flash" and tl:
        flash = (float(tl["baseline"]), float(tl["baseline"]) + float(tl["attack_seconds"]))
        S["flash_period_s"] = flash

    starts = ev[ev["event"] == "attack_start"]["t"]
    stops = ev[ev["event"] == "attack_stop"]["t"]
    a0 = float(starts.min()) if len(starts) else None
    a1 = float(stops.max()) if len(stops) else (end if a0 is not None else None)
    S["attack_start_s"] = round(a0, 1) if a0 is not None else None
    S["attack_stop_s"] = round(a1, 1) if a1 is not None else None

    mode = det["mode"].iloc[0] if not det.empty else "?"
    S["detector_mode"] = mode

    # ---- detection and defense timing -------------------------------------------------
    alarms = ev[(ev["source"] == "detector") & (ev["event"] == "alarm")]
    defs = ev[(ev["source"] == "detector") & (ev["event"].isin(["block", "syncookies"]))]
    rec_ev = ev[(ev["source"] == "detector") & (ev["event"] == "recovered")]
    t_alarm = float(alarms["t"].min()) if len(alarms) else None
    t_def = float(defs["t"].min()) if len(defs) else None
    if a0 is not None:
        t_alarm_after = alarms[alarms["t"] >= a0]["t"]
        t_alarm = float(t_alarm_after.min()) if len(t_alarm_after) else None
        S["detection_delay_s"] = round(t_alarm - a0, 1) if t_alarm is not None else None
        d_after = defs[defs["t"] >= a0]["t"]
        t_def = float(d_after.min()) if len(d_after) else None
        S["time_to_defense_s"] = round(t_def - a0, 1) if t_def is not None else None
    S["false_alarm_events_before_attack"] = int(
        (alarms["t"] < (a0 if a0 is not None else end + 1)).sum())
    S["syn_protection"] = None
    sc = ev[(ev["source"] == "detector") & (ev["event"] == "syncookies")]
    if len(sc):
        S["syn_protection"] = sc["detail"].iloc[0]

    # ---- client view: before / attack (undefended) / defended / after ------------------
    if a0 is not None:
        d = t_def if t_def is not None else a1
        phases = {
            "baseline": (0, a0),
            "attack_before_defense": (a0, d),
            "attack_with_defense": (d, a1),
            "after_attack": (a1, end + 1),
        }
    else:
        phases = {"baseline": (0, end + 1)}
    S["client"] = {name: phase_stats(cl, a, b) for name, (a, b) in phases.items()}

    # recovery: first time after the defense when 5 s success is >= 90% for two bins in a row
    S["client_recovery_s"] = None
    if t_def is not None and not cl.empty:
        x, succ, _ = success_curve(cl, end)
        for i in range(len(x) - 1):
            if x[i] >= t_def and succ[i] >= 90 and succ[i + 1] >= 90:
                S["client_recovery_s"] = round(float(x[i] - t_def), 1)
                break

    # ---- who was blocked --------------------------------------------------------------
    attackers = read_ips(os.path.join(run, "attackers"))
    clients_truth = read_ips(os.path.join(run, "clients"))
    block_ev = ev[(ev["source"] == "detector") & (ev["event"].isin(["block", "would_block"]))]
    blocked = {d.split(";")[0] for d in block_ev["detail"]}
    S["defense_active"] = bool(len(ev[(ev["source"] == "detector") & (ev["event"].isin(["block", "syncookies"]))]))
    if attackers:
        tp = len(blocked & attackers)
        S["block"] = dict(
            attackers=len(attackers), blocked=len(blocked),
            precision=round(tp / len(blocked), 3) if blocked else None,
            recall=round(tp / len(attackers), 3),
            legit_clients_blocked=sorted(blocked & clients_truth),
        )
    else:
        S["block"] = dict(blocked=len(blocked), legit_clients_blocked=sorted(blocked & clients_truth))

    # ---- window-level detection quality (entropy detector vs fixed threshold) ----------
    if not det.empty:
        w = det.copy()
        w = w[w["z_H"].notna()]                         # only windows after calibration
        win = float(np.median(np.diff(det["t"]))) if len(det) > 1 else 5.0
        mid = w["t"] - win / 2
        if t_def is not None:                  # after the defense the attack is mitigated: not a detection test
            keep = mid <= t_def + win
            w, mid = w[keep], mid[keep]
        if a0 is not None:                      # a window is an attack window if it overlaps the attack by >= 1 s
            overlap = np.minimum(w["t"], a1) - np.maximum(w["t"] - win, a0)
            truth = (overlap >= 1.0).astype(int)
        else:
            truth = pd.Series(0, index=w.index)
        S["windows"] = {
            "note": "windows up to the first defense action" if t_def is not None else "all windows after calibration",
            "evaluated": int(len(w)), "attack_windows": int(truth.sum()),
            "detector": binary_metrics(truth, w["alarm"]),
            "fixed_rate_threshold": binary_metrics(truth, w["alarm_thr"]),
        }
        pk, dr = int(det["kern_pkts"].sum()), int(det["kern_drops"].sum())
        S["capture"] = {"kernel_packets": pk, "dropped": dr, "loss_pct": round(100 * dr / max(1, pk), 2)}
        if det["ml_flows"].sum() > 0:
            S["ml"] = {"flows": int(det["ml_flows"].sum()), "attack_flows": int(det["ml_attack_flows"].sum())}

    # ---- chart --------------------------------------------------------------------------
    fig, ax = plt.subplots(4, 1, figsize=(13, 13), sharex=True)
    fig.suptitle(f"DDoS lab: {args.attack} flood  |  detector mode {mode}", fontsize=14, fontweight="bold")

    x, succ, lat = success_curve(cl, end)
    ax[0].plot(x + BIN / 2, succ, color="#2ca02c", lw=2, label="success rate")
    ax[0].set_ylabel("client success (%)")
    ax[0].set_ylim(-5, 105)
    ax[0].set_title("Legitimate users: do their requests still work?", fontsize=10, loc="left")
    ax0b = ax[0].twinx()
    ax0b.plot(x + BIN / 2, lat, color="#ff7f0e", lw=1.2, alpha=0.8, label="median latency")
    ax0b.set_ylabel("latency (ms)", color="#ff7f0e")

    if not det.empty:
        tt = det["t"] - WINDOW_FOR(det) / 2
        ax[1].plot(tt, det["pps"], color="#1f77b4", lw=1.6, label="packets/s to victim")
        base = det[det["z_pps"].notna()].head(1)
        if not base.empty:
            mu = det["pps"].iloc[1:6].mean()
            ax[1].axhline(mu, color="grey", ls="--", lw=1, label="normal level")
        ax[1].set_yscale("log")
        ax[1].set_ylabel("packets/s (log)")
        ax[1].set_title("Packet rate", fontsize=10, loc="left")

        ax[2].plot(tt, det["H_src"], color="#9467bd", lw=1.8, label="source entropy H (bits)")
        mu_h = det["H_src"].iloc[1:6].mean()
        ax[2].axhline(mu_h, color="grey", ls="--", lw=1, label="normal level")
        ax[2].set_ylabel("entropy (bits)")
        ax[2].set_title("Entropy of source addresses", fontsize=10, loc="left")
        ax2b = ax[2].twinx()
        ax2b.plot(tt, det["alarm"], color="#d62728", drawstyle="steps-mid", lw=1, alpha=0.6, label="alarm")
        ax2b.set_ylim(-0.1, 3)
        ax2b.set_yticks([0, 1])
        ax2b.set_ylabel("alarm", color="#d62728")

        ax[3].plot(tt, det["syn_rate"], color="#8c564b", lw=1.5, label="SYN/s")
        ax[3].plot(tt, det["syn_ack_ratio"] * 100, color="#e377c2", lw=1.2, label="SYN/ACK ratio x100")
        ax[3].set_yscale("symlog")
        ax[3].set_ylabel("SYN signals")
        ax[3].set_title("SYN rate and SYN/ACK ratio", fontsize=10, loc="left")
        ax3b = ax[3].twinx()
        ax3b.step(det["t"], det["n_blocked"], color="#17becf", lw=1.5, where="post", label="blocked sources")
        ax3b.set_ylabel("blocked IPs", color="#17becf")
    ax[3].set_xlabel("seconds since start (T0)")

    for a in ax:
        if a0 is not None:
            a.axvspan(a0, a1, color="#d62728", alpha=0.08)
            a.axvline(a0, color="#d62728", lw=1.2)
        if flash:
            a.axvspan(flash[0], flash[1], color="#1f77b4", alpha=0.08)
        if t_alarm is not None:
            a.axvline(t_alarm, color="#ff7f0e", ls="--", lw=1.2)
        if t_def is not None:
            a.axvline(t_def, color="#1f77b4", ls="-.", lw=1.2)
        a.grid(alpha=0.3)
        h, l = a.get_legend_handles_labels()
        if h:
            a.legend(h, l, loc="lower left", fontsize=8)
    if a0 is not None:
        ax[0].text(a0, 108, " attack", color="#d62728", fontsize=9, va="bottom")
    if flash:
        ax[0].text(flash[0], 108, " flash crowd (legitimate)", color="#1f77b4", fontsize=9, va="bottom")
    if t_alarm is not None:
        ax[0].text(t_alarm, 108, " alarm", color="#ff7f0e", fontsize=9, va="bottom")
    if t_def is not None:
        ax[0].text(t_def, 98, " defense", color="#1f77b4", fontsize=9, va="top")
    plt.tight_layout(rect=[0, 0, 1, 0.97])
    png = os.path.join(run, "ddos_analysis.png")
    plt.savefig(png, dpi=130)
    plt.close(fig)

    # ---- text summary -------------------------------------------------------------------
    json.dump(S, open(os.path.join(run, "summary.json"), "w"), indent=2, default=lambda o: None)
    lines = [f"Run: {S['run']}   attack: {args.attack}   detector mode: {mode}", ""]
    if a0 is not None:
        lines += [
            f"Attack:            {a0:.0f}s -> {a1:.0f}s",
            f"Detection delay:   {S.get('detection_delay_s')} s after the attack started",
            f"Time to defense:   {S.get('time_to_defense_s')} s"
            + (f"   (SYN protection: {S['syn_protection']})" if S.get("syn_protection") else ""),
            f"Client recovery:   {S.get('client_recovery_s')} s after the defense started",
        ]
    if flash:
        n_al = int(((alarms["t"] >= flash[0]) & (alarms["t"] <= flash[1] + 10)).sum())
        lines += [f"Flash crowd {flash[0]:.0f}s -> {flash[1]:.0f}s (legitimate users, 4x the requests): "
                  f"detector alarms = {n_al}"]
    lines += [f"False alarms before the attack: {S['false_alarm_events_before_attack']}", "", "Client success (legitimate users):"]
    for name, st in S["client"].items():
        lines.append(f"  {name:<24} requests={st['requests']:>5}  success={st['success_pct']}%  "
                     f"p50={st['p50_ms']} ms  p95={st['p95_ms']} ms")
    b = S["block"]
    lines += ["", f"{'Blocked' if S['defense_active'] else 'Would-block (dry run)'} sources: {b.get('blocked')}"
              + (f"   precision={b.get('precision')}  recall={b.get('recall')}  (attackers={b.get('attackers')})"
                 if "attackers" in b else ""),
              f"Legitimate clients blocked: {b['legit_clients_blocked'] or 'none'}"]
    if "windows" in S:
        wv = S["windows"]
        lines += ["", f"Window-level detection ({wv['evaluated']} windows, {wv['attack_windows']} attack; {wv['note']}):",
                  f"  {'detector':<22}{'prec':>7}{'recall':>8}{'F1':>7}{'FPR':>8}{'MCC':>8}   TP/FP/FN/TN"]
        for name in ("detector", "fixed_rate_threshold"):
            m = wv[name]
            f3 = lambda v: "  n/a" if v != v else f"{v:.3f}"
            lines.append(f"  {name:<22}{f3(m['precision']):>7}{f3(m['recall']):>8}{f3(m['f1']):>7}"
                         f"{f3(m['fpr']):>8}{f3(m['mcc']):>8}   {m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}")
        c = S["capture"]
        lines += ["", f"Capture: {c['kernel_packets']} packets seen by the kernel, {c['dropped']} dropped ({c['loss_pct']}%)"]
    text = "\n".join(lines)
    open(os.path.join(run, "summary.txt"), "w", encoding="utf-8").write(text + "\n")
    print("\n" + text)
    print(f"\nChart: {png}")


def WINDOW_FOR(det):
    return float(np.median(np.diff(det["t"]))) if len(det) > 1 else 5.0


if __name__ == "__main__":
    main()
