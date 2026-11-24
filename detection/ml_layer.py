import csv
import os
import warnings
from collections import Counter

import numpy as np

from capture import UDP, ip_to_str
from flow_extractor import FEATURES, FlowTable

MODEL_FILE = "ddos_model.joblib"
FWD_PKTS = FEATURES.index("Total Fwd Packets")
UDP_MANY = 100                  # a UDP flow with at least this many packets counts as k_votes


class MLLayer:
    def __init__(self, bundle=None, record_path=None, t0=0.0, ignore=()):
        self.t0 = t0
        self.ignore = set(ignore)
        self.table = FlowTable()
        self.model = None
        self.k_votes = 3
        self.threshold = 0.5
        if bundle is not None:
            self.model = bundle["model"]
            self.threshold = float(bundle.get("threshold", 0.5))
            self.k_votes = int(bundle.get("k_votes", 3))
            self.idx = [FEATURES.index(f) for f in bundle["features"]]
            self.attack_col = list(bundle["classes"]).index("ATTACK")
            self.model_features = list(bundle["features"])
        self._file = self._writer = None
        if record_path:
            self._file = open(record_path, "w", newline="", encoding="utf-8")
            self._writer = csv.writer(self._file)
            self._writer.writerow(["t", "src_ip", "dst_port", "proto"] + FEATURES)

    @property
    def has_model(self):
        return self.model is not None

    def add_packet(self, p):
        self.table.add(p)

    def end_window(self, now):
        """Returns (flows seen, flows classified as attack, {source ip: attack flows})."""
        flows = [f for f in self.table.collect(now) if f[0] not in self.ignore]
        if self._writer:
            for src, dport, proto, feat in flows:
                self._writer.writerow([f"{now - self.t0:.1f}", ip_to_str(src), dport, proto] + [f"{v:.6g}" for v in feat])
            self._file.flush()
        if not self.model or not flows:
            return len(flows), 0, {}
        X = np.array([[feat[i] for i in self.idx] for _, _, _, feat in flows], dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        with warnings.catch_warnings():
            # The model was fitted on a named table; here the columns are in the same order
            # but passed as a plain array. scikit-learn warns about that on every call.
            warnings.filterwarnings("ignore", message="X does not have valid feature names")
            proba = self.model.predict_proba(X)[:, self.attack_col]
        mask = proba >= self.threshold
        votes = Counter()
        for (src, _, proto, feat), m in zip(flows, mask):
            if not m:
                continue
            # A UDP "flow" is one source's whole window (the source port changes on every
            # packet), so it stands for hundreds of datagrams: it counts as k_votes at once.
            many = proto == UDP and feat[FWD_PKTS] >= UDP_MANY
            votes[src] += self.k_votes if many else 1
        return len(flows), int(mask.sum()), dict(votes)


def load_ml_layer(model_dir, use_model=True, record_path=None, t0=0.0, ignore=()):
    """Return an MLLayer, or None when there is nothing to do (no model, no recording)."""
    bundle = None
    path = os.path.join(model_dir, MODEL_FILE)
    if use_model and os.path.exists(path):
        import joblib
        import sklearn
        with warnings.catch_warnings():
            warnings.simplefilter("error")           # a version mismatch must not pass silently
            try:
                bundle = joblib.load(path)
            except Exception as e:
                print(f"[ml] cannot load {path}: {e}", flush=True)
                bundle = None
        if bundle is not None:
            if bundle.get("sklearn") != sklearn.__version__:
                print(f"[ml] WARNING: model trained with scikit-learn {bundle.get('sklearn')}, "
                      f"running {sklearn.__version__}", flush=True)
            print(f"[ml] model loaded: {len(bundle['features'])} features, threshold {bundle.get('threshold', 0.5)}, "
                  f"trained on {bundle.get('trained_on', '?')}", flush=True)
    if bundle is None and not record_path:
        return None
    return MLLayer(bundle, record_path, t0, ignore)
