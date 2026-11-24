import argparse
import glob
import json
import math
import os
import sys
import time
import warnings

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.tree import DecisionTreeClassifier

from flow_extractor import FEATURES

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))        # the detection/ folder
SEED = 42
BLOCK = 2000
K_VOTES = 3
LAB_ATTACK_CAP = 20000        # per lab run, so one HTTP run does not outweigh the dataset
UDP_WEIGHT = 10.0             # a UDP flood yields few (aggregated) flows; weight them up


def make_rf(n_jobs=4):
    return RandomForestClassifier(n_estimators=120, max_depth=14, min_samples_leaf=2,
                                  class_weight="balanced_subsample", n_jobs=n_jobs, random_state=SEED)


def metrics(y, pred):
    y, pred = np.asarray(y, int), np.asarray(pred, int)
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec == prec and rec == rec and prec + rec > 0) else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / d if d else float("nan")
    return dict(n=len(y), attacks=int(y.sum()), tp=tp, fp=fp, fn=fn, tn=tn,
                precision=prec, recall=rec, f1=f1, fpr=fpr, mcc=mcc)


def clean(X):
    X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X["Flow Duration"] = X["Flow Duration"].clip(lower=0)      # the CSV has a few -1 values
    return X.astype(np.float32)


def load_cic(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        sys.exit(f"[ERROR] CIC file lacks columns: {missing}")
    X = clean(df[FEATURES])
    y = (df["Label"].astype(str).str.strip() != "BENIGN").astype(int).to_numpy()
    return X, y


def load_lab(run_dirs):
    runs = {}
    for d in run_dirs:
        path = os.path.join(d, "lab_flows.csv")
        if not os.path.exists(path):
            continue
        att = {n for n in os.listdir(os.path.join(d, "attackers"))} if os.path.isdir(os.path.join(d, "attackers")) else set()
        cli = {n for n in os.listdir(os.path.join(d, "clients"))} if os.path.isdir(os.path.join(d, "clients")) else set()
        df = pd.read_csv(path)
        label = df["src_ip"].map(lambda ip: 1 if ip in att else (0 if ip in cli else -1))
        df = df[label >= 0].copy()
        label = label[label >= 0]
        if len(df) == 0:
            continue
        X = clean(df[FEATURES])
        proto = df["proto"].to_numpy()
        src = df["src_ip"].to_numpy()
        y = label.to_numpy()
        # keep every benign flow, cap the attack flows
        rng = np.random.default_rng(SEED)
        keep = np.ones(len(y), bool)
        a = np.where(y == 1)[0]
        if len(a) > LAB_ATTACK_CAP:
            keep[a] = False
            keep[rng.choice(a, LAB_ATTACK_CAP, replace=False)] = True
        runs[os.path.basename(os.path.normpath(d))] = dict(
            X=X[keep].reset_index(drop=True), y=y[keep], proto=proto[keep], src=src[keep])
    return runs


def source_level(src, y, pred, k=K_VOTES):
    """What the detector actually does: a source is blocked after k attack-flagged flows."""
    s = pd.DataFrame({"src": src, "y": y, "p": pred})
    g = s.groupby("src").agg(is_attacker=("y", "max"), votes=("p", "sum"))
    blocked = g["votes"] >= k
    att, ben = g["is_attacker"] == 1, g["is_attacker"] == 0
    return dict(attackers=int(att.sum()), attackers_blocked=int((blocked & att).sum()),
                clients=int(ben.sum()), clients_wrongly_blocked=int((blocked & ben).sum()))


def fmt(m):
    f = lambda v: "  n/a" if v != v else f"{v:.4f}"
    return (f"prec {f(m['precision'])}  recall {f(m['recall'])}  F1 {f(m['f1'])}  FPR {f(m['fpr'])}  "
            f"MCC {f(m['mcc'])}   TP/FP/FN/TN {m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cic", default=os.path.join(HERE, "data", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"))
    ap.add_argument("--runs", default=os.path.join(HERE, "..", "output", "runs", "*-nodefense_*"),
                    help="glob of lab runs recorded with -Record")
    ap.add_argument("--out", default=os.path.join(HERE, "models"))
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    t_start = time.time()
    lines, R = [], {}

    def say(s=""):
        print(s, flush=True)
        lines.append(s)

    say(f"Features used: {len(FEATURES)}   scikit-learn {sklearn.__version__}")
    Xc, yc = load_cic(args.cic)
    say(f"CIC-IDS-2017 Friday: {len(yc):,} flows ({int(yc.sum()):,} DDoS, {int((yc == 0).sum()):,} benign)")
    lab = load_lab(sorted(glob.glob(args.runs)))
    for name, r in lab.items():
        say(f"  lab run {name}: {len(r['y']):,} flows ({int(r['y'].sum()):,} attack, {int((r['y'] == 0).sum()):,} benign)")
    if not lab:
        say("  (no recorded lab runs found: training on CIC only)")

    # ---- A. CIC blocked cross-validation --------------------------------------------------
    say("\nA. CIC-IDS-2017, blocked 5-fold cross-validation (blocks of 2000 consecutive flows)")
    blocks = np.arange(len(yc)) // BLOCK
    fold = blocks % 5
    oof_rf = np.zeros(len(yc))
    oof_thr = np.zeros(len(yc), int)
    for k in range(5):
        tr, te = fold != k, fold == k
        rf = make_rf(args.jobs).fit(Xc[tr], yc[tr])
        oof_rf[te] = rf.predict_proba(Xc[te])[:, 1]
        stump = DecisionTreeClassifier(max_depth=1, random_state=SEED).fit(Xc.loc[tr, ["Flow Packets/s"]], yc[tr])
        oof_thr[te] = stump.predict(Xc.loc[te, ["Flow Packets/s"]])
    R["cic_cv"] = {"random_forest": metrics(yc, oof_rf >= 0.5), "fixed_threshold": metrics(yc, oof_thr)}
    say("  random forest        " + fmt(R["cic_cv"]["random_forest"]))
    say("  fixed rate threshold " + fmt(R["cic_cv"]["fixed_threshold"]))
    # smallest threshold that keeps the false-positive rate at 1% or less
    neg = np.sort(oof_rf[yc == 0])
    thr_fpr1 = float(neg[int(math.ceil(0.99 * len(neg))) - 1]) if len(neg) else 0.5
    threshold = max(0.5, min(0.95, thr_fpr1 + 1e-6))
    R["threshold"] = {"fpr_1pct_threshold": thr_fpr1, "chosen": threshold}
    say(f"  threshold for FPR <= 1% on the held-out blocks: {thr_fpr1:.3f}  -> alarm threshold {threshold:.3f}")

    # ---- B/C. lab runs -------------------------------------------------------------------
    def stack(parts):
        X = pd.concat([p[0] for p in parts], ignore_index=True)
        y = np.concatenate([p[1] for p in parts])
        w = np.concatenate([p[2] for p in parts])
        return X, y, w

    def weights(r):
        w = np.ones(len(r["y"]))
        w[(r["proto"] == 17) & (r["y"] == 1)] = UDP_WEIGHT
        return w

    cic_part = (Xc, yc, np.ones(len(yc)))
    if lab:
        say("\nB. Lab leave-one-run-out: train on CIC + the other lab runs, test on the held-out run")
        R["lab_loro"] = {}
        for name, r in lab.items():
            others = [(o["X"], o["y"], weights(o)) for n, o in lab.items() if n != name]
            X, y, w = stack([cic_part] + others)
            rf = make_rf(args.jobs).fit(X, y, sample_weight=w)
            p = rf.predict_proba(r["X"])[:, 1] >= threshold
            stump = DecisionTreeClassifier(max_depth=1, random_state=SEED).fit(X[["Flow Packets/s"]], y)
            pt = stump.predict(r["X"][["Flow Packets/s"]])
            res = {"random_forest": metrics(r["y"], p), "fixed_threshold": metrics(r["y"], pt),
                   "sources": source_level(r["src"], r["y"], p)}
            R["lab_loro"][name] = res
            say(f"  {name}")
            say("    random forest        " + fmt(res["random_forest"]))
            say("    fixed rate threshold " + fmt(res["fixed_threshold"]))
            s = res["sources"]
            say(f"    per source (blocked after {K_VOTES} attack flows): attackers blocked {s['attackers_blocked']}/{s['attackers']}, "
                f"clients wrongly blocked {s['clients_wrongly_blocked']}/{s['clients']}")

        say("\nC. Model trained on CIC-IDS-2017 ONLY, tested on lab traffic (domain gap)")
        R["cic_only_on_lab"] = {}
        rf0 = make_rf(args.jobs).fit(Xc, yc)
        for name, r in lab.items():
            p = rf0.predict_proba(r["X"])[:, 1] >= threshold
            res = {"random_forest": metrics(r["y"], p), "sources": source_level(r["src"], r["y"], p)}
            R["cic_only_on_lab"][name] = res
            s = res["sources"]
            say(f"  {name}\n    " + fmt(res["random_forest"]) +
                f"\n    attackers blocked {s['attackers_blocked']}/{s['attackers']}, clients wrongly blocked {s['clients_wrongly_blocked']}/{s['clients']}")

    # ---- final model ---------------------------------------------------------------------
    say("\nFinal model: CIC-IDS-2017 + all lab runs")
    parts = [cic_part] + [(r["X"], r["y"], weights(r)) for r in lab.values()]
    X, y, w = stack(parts)
    final = make_rf(args.jobs).fit(X, y, sample_weight=w)

    # which features matter? (checked on a held-out CIC block fold, to spot shortcut features)
    te = fold == 0
    rf_chk = make_rf(args.jobs).fit(Xc[~te], yc[~te])
    pi = permutation_importance(rf_chk, Xc[te].iloc[:6000], yc[te][:6000], n_repeats=3, random_state=SEED, n_jobs=2)
    imp = pd.Series(pi.importances_mean, index=FEATURES).sort_values(ascending=False)
    R["permutation_importance_top10"] = {k: round(float(v), 4) for k, v in imp.head(10).items()}
    say("  top features by permutation importance (held-out CIC blocks):")
    for k, v in imp.head(10).items():
        say(f"    {k:<30s} {v:.4f}")

    bundle = {
        "model": final, "features": FEATURES, "classes": ["BENIGN", "ATTACK"],
        "threshold": threshold, "k_votes": K_VOTES, "sklearn": sklearn.__version__,
        "trained_on": f"CIC-IDS-2017 Friday ({len(yc)} flows) + {len(lab)} lab runs ({int(sum(len(r['y']) for r in lab.values()))} flows)",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    # classes: sklearn orders them 0,1 -> BENIGN, ATTACK
    joblib.dump(bundle, os.path.join(args.out, "ddos_model.joblib"), compress=3)
    say(f"\nSaved {os.path.join(args.out, 'ddos_model.joblib')}  ({time.time() - t_start:.0f}s)")

    json.dump(R, open(os.path.join(args.out, "evaluation.json"), "w"), indent=2)
    open(os.path.join(args.out, "evaluation.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    top = pd.Series(final.feature_importances_, index=FEATURES).sort_values().tail(15)
    fig, ax = plt.subplots(figsize=(8, 5))
    top.plot.barh(ax=ax, color="#1f77b4")
    ax.set_title("Final model: 15 most important features")
    ax.set_xlabel("Gini importance")
    plt.tight_layout()
    plt.savefig(os.path.join(args.out, "feature_importance.png"), dpi=120)


if __name__ == "__main__":
    main()
