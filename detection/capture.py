import socket
import struct
import time

ETH_P_IP = 0x0800
SOL_PACKET = 263
PACKET_STATISTICS = 6
SO_RCVBUFFORCE = 33
PACKET_OUTGOING = 4

TCP, UDP = 6, 17
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

_unpack_H = struct.Struct("!H").unpack_from
_unpack_HH = struct.Struct("!HH").unpack_from
_unpack_II = struct.Struct("!II").unpack_from


def ip_to_str(n):
    return socket.inet_ntoa(struct.pack("!I", n))


def str_to_ip(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


class Packet:
    """Header fields of one IPv4 packet. __slots__ keeps it cheap at high rates."""
    __slots__ = ("ts", "inbound", "src", "dst", "proto", "sport", "dport",
                 "ip_len", "l4_hdr", "payload", "flags", "win")


class Capture:
    def __init__(self, iface="eth0", rcvbuf=64 * 1024 * 1024):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, rcvbuf)
        except OSError:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.2)
        self._buf = bytearray(2048)
        self._view = memoryview(self._buf)

    def kernel_stats(self):
        """(packets seen by the kernel, packets dropped) since the last call."""
        try:
            raw = self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            pkts, drops = struct.unpack("II", raw)
            return pkts, drops
        except OSError:
            return 0, 0

    def read(self):
        """Return one Packet, None on timeout or for packets we do not parse."""
        try:
            n, addr = self.sock.recvfrom_into(self._buf)
        except socket.timeout:
            return None
        except BlockingIOError:
            return None
        b = self._buf
        if n < 34 or (b[14] >> 4) != 4:
            return None
        ihl = (b[14] & 0x0F) * 4
        p = Packet()
        p.ts = time.time()
        p.inbound = addr[2] != PACKET_OUTGOING
        p.proto = b[23]
        p.ip_len = _unpack_H(b, 16)[0]
        p.src, p.dst = _unpack_II(b, 26)
        l4 = 14 + ihl
        p.sport = p.dport = 0
        p.flags = 0
        p.win = 0
        if p.proto == TCP and n >= l4 + 20:
            p.sport, p.dport = _unpack_HH(b, l4)
            p.l4_hdr = (b[l4 + 12] >> 4) * 4
            p.flags = b[l4 + 13]
            p.win = _unpack_H(b, l4 + 14)[0]
        elif p.proto == UDP and n >= l4 + 8:
            p.sport, p.dport = _unpack_HH(b, l4)
            p.l4_hdr = 8
        else:
            p.l4_hdr = 0
        p.payload = max(0, p.ip_len - ihl - p.l4_hdr)
        return p
