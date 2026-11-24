#!/usr/bin/env python3
"""
flow_extractor.py - build CIC-IDS-2017 style flow features from live packet headers.

The definitions below were checked against the real Friday-DDoS CSV:
  * packet length  = payload bytes (a bare SYN or ACK has length 0)
  * IAT and duration are in microseconds; Flow IAT is the gap between consecutive
    packets in either direction (so mean x (n-1) = duration)
  * standard deviations are the SAMPLE standard deviation (n-1)
  * Down/Up Ratio is an integer division, backward packets / forward packets
  * the "Flag Count" columns are 0/1: was the flag seen anywhere in the flow
  * Flow Bytes/s and Flow Packets/s are 0 when the duration is 0

Only features that can be computed identically live and from the CSV are used. Port
numbers, window sizes, header lengths and the active/idle/bulk columns are left out
on purpose: they either identify the lab setup rather than the attack, or the live
tool cannot reproduce CICFlowMeter's exact value.

Flows
  TCP : one flow per 5-tuple, both directions. A flow is handed to the classifier when
        it closes (RST, or FIN seen both ways), goes idle for IDLE seconds, or is
        still open after MAX_AGE seconds (one snapshot).
  UDP : one flow per (source, destination, destination port), reset every window,
        because a UDP flood changes the source port on every packet.
"""
import math

from capture import TCP, UDP, FIN, SYN, RST, PSH, ACK

URG = 0x20

FEATURES = [
    "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Down/Up Ratio", "act_data_pkt_fwd",
]

IDLE = 1.0          # seconds without packets: the flow is over
MAX_AGE = 3.0       # still open after this long: classify a snapshot once


class Stat:
    """Running count / sum / sum of squares / min / max."""
    __slots__ = ("n", "s", "q", "mn", "mx")

    def __init__(self):
        self.n = 0
        self.s = 0.0
        self.q = 0.0
        self.mn = math.inf
        self.mx = -math.inf

    def add(self, x):
        self.n += 1
        self.s += x
        self.q += x * x
        if x < self.mn:
            self.mn = x
        if x > self.mx:
            self.mx = x

    def mean(self):
        return self.s / self.n if self.n else 0.0

    def var(self):                       # sample variance, like CICFlowMeter
        if self.n < 2:
            return 0.0
        v = (self.q - self.s * self.s / self.n) / (self.n - 1)
        return v if v > 0 else 0.0

    def std(self):
        return math.sqrt(self.var())

    def lo(self):
        return self.mn if self.n else 0.0

    def hi(self):
        return self.mx if self.n else 0.0


class Flow:
    __slots__ = ("src", "dst", "sport", "dport", "proto", "t0", "t_last", "t_prev",
                 "t_fwd", "t_bwd", "fwd", "bwd", "alln", "iat", "fiat", "biat",
                 "flags", "act_fwd", "fin_f", "fin_b", "closed", "emitted")

    def __init__(self, p):
        self.src, self.dst, self.sport, self.dport, self.proto = p.src, p.dst, p.sport, p.dport, p.proto
        self.t0 = self.t_last = self.t_prev = p.ts
        self.t_fwd = self.t_bwd = None
        self.fwd, self.bwd, self.alln = Stat(), Stat(), Stat()
        self.iat, self.fiat, self.biat = Stat(), Stat(), Stat()
        self.flags = 0
        self.act_fwd = 0
        self.fin_f = self.fin_b = self.closed = self.emitted = False

    def add(self, p, forward):
        us = 1e6
        if self.alln.n:
            self.iat.add((p.ts - self.t_prev) * us)
        self.t_prev = self.t_last = p.ts
        self.alln.add(p.payload)
        if forward:
            if self.t_fwd is not None:
                self.fiat.add((p.ts - self.t_fwd) * us)
            self.t_fwd = p.ts
            self.fwd.add(p.payload)
            if p.payload > 0:
                self.act_fwd += 1
        else:
            if self.t_bwd is not None:
                self.biat.add((p.ts - self.t_bwd) * us)
            self.t_bwd = p.ts
            self.bwd.add(p.payload)
        if p.proto == TCP:
            self.flags |= p.flags
            if p.flags & RST:
                self.closed = True
            elif p.flags & FIN:
                if forward:
                    self.fin_f = True
                else:
                    self.fin_b = True
                if self.fin_f and self.fin_b:
                    self.closed = True


def features(fl):
    """Feature vector in FEATURES order."""
    dur = (fl.t_last - fl.t0) * 1e6
    sec = dur / 1e6
    nf, nb = fl.fwd.n, fl.bwd.n
    tot_b = fl.fwd.s + fl.bwd.s
    bps = tot_b / sec if sec > 0 else 0.0
    pps = (nf + nb) / sec if sec > 0 else 0.0
    f = fl.flags
    return [
        dur,
        nf, nb,
        fl.fwd.s, fl.bwd.s,
        fl.fwd.hi(), fl.fwd.lo(), fl.fwd.mean(), fl.fwd.std(),
        fl.bwd.hi(), fl.bwd.lo(), fl.bwd.mean(), fl.bwd.std(),
        bps, pps,
        fl.iat.mean(), fl.iat.std(), fl.iat.hi(), fl.iat.lo(),
        fl.fiat.s, fl.fiat.mean(), fl.fiat.std(), fl.fiat.hi(), fl.fiat.lo(),
        fl.biat.s, fl.biat.mean(), fl.biat.std(), fl.biat.hi(), fl.biat.lo(),
        nf / sec if sec > 0 else 0.0, nb / sec if sec > 0 else 0.0,
        fl.alln.lo(), fl.alln.hi(), fl.alln.mean(), fl.alln.std(), fl.alln.var(),
        int(bool(f & FIN)), int(bool(f & SYN)), int(bool(f & RST)), int(bool(f & PSH)),
        int(bool(f & ACK)), int(bool(f & URG)),
        (nb // nf) if nf else 0, fl.act_fwd,
    ]


class FlowTable:
    def __init__(self, idle=IDLE, max_age=MAX_AGE):
        self.idle = idle
        self.max_age = max_age
        self.tcp = {}
        self.udp = {}

    def add(self, p):
        if p.proto == TCP:
            key = (p.src, p.dst, p.sport, p.dport)
            fl = self.tcp.get(key)
            forward = True
            if fl is None:
                fl = self.tcp.get((p.dst, p.src, p.dport, p.sport))
                forward = False
                if fl is None:
                    if p.flags & RST and not p.flags & ACK:
                        return
                    fl = self.tcp[key] = Flow(p)
                    forward = True
            fl.add(p, forward)
        elif p.proto == UDP and p.inbound:
            key = (p.src, p.dst, p.dport)
            fl = self.udp.get(key)
            if fl is None:
                fl = self.udp[key] = Flow(p)
            fl.add(p, True)

    def collect(self, now):
        """Flows ready for classification: [(source ip, destination port, protocol, features)]."""
        out = []
        done = []
        for key, fl in self.tcp.items():
            idle = now - fl.t_last > self.idle
            if fl.closed or idle:
                if not fl.emitted:
                    out.append((fl.src, fl.dport, TCP, features(fl)))
                done.append(key)
            elif not fl.emitted and now - fl.t0 > self.max_age:
                fl.emitted = True
                out.append((fl.src, fl.dport, TCP, features(fl)))
        for key in done:
            del self.tcp[key]
        for fl in self.udp.values():
            out.append((fl.src, fl.dport, UDP, features(fl)))
        self.udp = {}
        return out
