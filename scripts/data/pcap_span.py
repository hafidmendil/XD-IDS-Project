#!/usr/bin/env python3
"""Période couverte par un PCAP ou PCAPNG, même tronqué : nb de paquets, 1er/dernier timestamp."""
import datetime
import os
import struct
import sys


def span_classic(f, size):
    h = f.read(24)
    magic = struct.unpack("<I", h[:4])[0]
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        raise SystemExit(f"magic {h[:4].hex()} : format non géré (pcap big-endian ?)")
    div = 1e6 if magic == 0xA1B2C3D4 else 1e9
    n, first, last, pos = 0, None, None, 24
    while True:
        r = f.read(16)
        if len(r) < 16:
            break
        s, frac, cl, _ = struct.unpack("<IIII", r)
        if pos + 16 + cl > size:
            break
        f.seek(cl, 1)
        pos += 16 + cl
        t = s + frac / div
        first = t if first is None else first
        last, n = t, n + 1
    return n, first, last, pos


def span_pcapng(f, size):
    bom = f.read(12)[8:12]
    e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
    f.seek(0)
    pos, n, first, last, nif, res = 0, 0, None, None, 0, {}
    while True:
        h = f.read(8)
        if len(h) < 8:
            break
        btype, blen = struct.unpack(e + "II", h)
        if blen < 12 or pos + blen > size:
            break                                   # bloc final tronqué
        if btype == 6:                              # Enhanced Packet Block
            iface, th, tl = struct.unpack(e + "III", f.read(12))
            f.seek(blen - 8 - 12, 1)
            t = ((th << 32) | tl) / res.get(iface, 1e6)
            first = t if first is None else first
            last, n = t, n + 1
        else:
            body = f.read(blen - 8)
            if btype == 0x0A0D0D0A:                 # nouvelle section
                nif, res = 0, {}
            elif btype == 1:                        # Interface Description Block
                div, opts, o = 1e6, body[8:-4], 0
                while o + 4 <= len(opts):
                    code, ln = struct.unpack(e + "HH", opts[o:o + 4])
                    if code == 0:
                        break
                    if code == 9 and ln >= 1:       # if_tsresol
                        v = opts[o + 4]
                        div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                    o += 4 + ((ln + 3) & ~3)
                res[nif] = div
                nif += 1
        pos += blen
    return n, first, last, pos


def span(path):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        fmt = "pcapng" if f.read(4) == b"\x0a\x0d\x0d\x0a" else "pcap"
        f.seek(0)
        res = span_pcapng(f, size) if fmt == "pcapng" else span_classic(f, size)
    return (fmt, *res, size)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        fmt, n, a, b, ok, size = span(p)
        u = lambda t: datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"{p} [{fmt}]: {n} paquets | {u(a)} -> {u(b)} | durée {(b - a) / 3600:.2f} h | "
              f"octets valides {ok}/{size} (queue tronquée : {size - ok} o)")
