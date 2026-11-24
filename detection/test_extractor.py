import math
import statistics
import sys

from capture import Packet, TCP, UDP, SYN, ACK, FIN, PSH, str_to_ip
from flow_extractor import FEATURES, FlowTable

OK = FAIL = 0


def check(name, got, want, tol=1e-6):
    global OK, FAIL
    good = math.isclose(got, want, rel_tol=tol, abs_tol=tol)
    OK += good
    FAIL += not good
    print(f"  {'ok  ' if good else 'FAIL'} {name}: got {got:.6g}, expected {want:.6g}")


def pkt(ts, src, dst, sport, dport, proto, payload, flags=0, inbound=True):
    p = Packet()
    p.ts, p.src, p.dst, p.sport, p.dport, p.proto = ts, str_to_ip(src), str_to_ip(dst), sport, dport, proto
    p.payload, p.flags, p.inbound = payload, flags, inbound
    p.ip_len = payload + 40
    p.l4_hdr, p.win = 20, 0
    return p


def feat(vec, name):
    return vec[FEATURES.index(name)]


print("TCP flow: client 10.0.0.5:4000 -> victim 10.0.0.2:80")
C, V = "10.0.0.5", "10.0.0.2"
t = 1000.0
table = FlowTable()
seq = [                                    # (time, forward?, payload, flags)
    (0.000, True, 0, SYN), (0.001, False, 0, SYN | ACK), (0.002, True, 0, ACK),
    (0.010, True, 100, PSH | ACK), (0.030, False, 1000, ACK), (0.050, False, 400, PSH | ACK),
    (0.060, True, 0, FIN | ACK), (0.061, False, 0, FIN | ACK),
]
for dt, fwd, pl, fl in seq:
    table.add(pkt(t + dt, C if fwd else V, V if fwd else C, 4000 if fwd else 80, 80 if fwd else 4000, TCP, pl, fl, inbound=fwd))
out = table.collect(t + 0.1)
assert len(out) == 1, out
src, dport, proto, v = out[0]
check("source ip", src, str_to_ip(C))
check("Flow Duration (us)", feat(v, "Flow Duration"), 61000)
check("Total Fwd Packets", feat(v, "Total Fwd Packets"), 4)
check("Total Backward Packets", feat(v, "Total Backward Packets"), 4)
check("Total Length of Fwd Packets", feat(v, "Total Length of Fwd Packets"), 100)
check("Total Length of Bwd Packets", feat(v, "Total Length of Bwd Packets"), 1400)
fwd_len = [0, 0, 100, 0]
check("Fwd Packet Length Std (sample)", feat(v, "Fwd Packet Length Std"), statistics.stdev(fwd_len))
check("Fwd Packet Length Mean", feat(v, "Fwd Packet Length Mean"), statistics.mean(fwd_len))
check("Bwd Packet Length Max", feat(v, "Bwd Packet Length Max"), 1000)
check("Flow Bytes/s (payload)", feat(v, "Flow Bytes/s"), 1500 / 0.061, 1e-4)
check("Flow Packets/s", feat(v, "Flow Packets/s"), 8 / 0.061, 1e-4)
gaps = [1000, 1000, 8000, 20000, 20000, 10000, 1000]
check("Flow IAT Mean (us)", feat(v, "Flow IAT Mean"), statistics.mean(gaps), 1e-4)
check("Flow IAT mean x (n-1) = duration", feat(v, "Flow IAT Mean") * 7, 61000, 1e-4)
check("Flow IAT Std (sample)", feat(v, "Flow IAT Std"), statistics.stdev(gaps), 1e-4)
fg = [2000, 8000, 50000]
check("Fwd IAT Total", feat(v, "Fwd IAT Total"), sum(fg), 1e-4)
check("Fwd IAT Min", feat(v, "Fwd IAT Min"), min(fg), 1e-4)
check("Down/Up Ratio (integer)", feat(v, "Down/Up Ratio"), 1)
check("act_data_pkt_fwd", feat(v, "act_data_pkt_fwd"), 1)
for name, want in [("SYN Flag Count", 1), ("FIN Flag Count", 1), ("PSH Flag Count", 1), ("ACK Flag Count", 1),
                   ("RST Flag Count", 0), ("URG Flag Count", 0)]:
    check(name + " (0/1)", feat(v, name), want)

print("UDP flood: one source, a new source port on every packet -> ONE flow per window")
table = FlowTable()
for i in range(50):
    table.add(pkt(t + i * 0.001, "10.0.0.9", V, 20000 + i, 53, UDP, 64, 0, inbound=True))
out = table.collect(t + 1)
check("UDP flows from one source", len(out), 1)
check("UDP packets in the flow", feat(out[0][3], "Total Fwd Packets"), 50)
check("UDP flows after reset", len(table.collect(t + 2)), 0)

print("Single idle SYN becomes a 1-packet flow after the idle time")
table = FlowTable()
table.add(pkt(t, "10.0.0.7", V, 5555, 80, TCP, 0, SYN))
check("not ready yet", len(table.collect(t + 0.5)), 0)
out = table.collect(t + 2)
check("emitted after idle", len(out), 1)
check("duration of a 1-packet flow", feat(out[0][3], "Flow Duration"), 0)
check("Flow Bytes/s for duration 0", feat(out[0][3], "Flow Bytes/s"), 0)

print(f"\n{OK} checks passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
