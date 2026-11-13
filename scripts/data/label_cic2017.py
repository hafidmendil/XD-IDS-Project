#!/usr/bin/env python3
"""Etiquette les connexions Zeek (conn.log) de CIC-IDS2017 et les range en blocs de session.

Regle (jour Tuesday) : 172.16.0.1 -> 192.168.10.50 port 21 = FTP-Patator, port 22 = SSH-Patator.
Tout le reste = BENIGN. Monday = 100 % BENIGN. Les regles sont a valider avec les CSV ISCX.
Usage : python scripts/data/label_cic2017.py --conn <conn.log> --day tuesday --out <sortie.csv>
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ATTACKER = "172.16.0.1"
VICTIM = "192.168.10.50"
RULES = {
    "monday": [],
    "tuesday": [
        {"family": "FTP-Patator", "orig_h": ATTACKER, "resp_h": VICTIM, "resp_p": "21"},
        {"family": "SSH-Patator", "orig_h": ATTACKER, "resp_h": VICTIM, "resp_p": "22"},
    ],
}
KEEP = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
        "duration", "orig_bytes", "resp_bytes", "conn_state", "orig_pkts", "resp_pkts"]


def read_conn(path):
    fields = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#"):
                if fields is None:
                    raise SystemExit("conn.log sans ligne #fields (format TSV Zeek attendu)")
                yield dict(zip(fields, line.split("\t")))


def family_of(row, rules):
    for r in rules:
        if (row.get("id.orig_h") == r["orig_h"] and row.get("id.resp_h") == r["resp_h"]
                and row.get("id.resp_p") == r["resp_p"]):
            return r["family"]
    return "BENIGN"


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--day", required=True, choices=sorted(RULES))
    ap.add_argument("--out", required=True)
    ap.add_argument("--block-seconds", type=int, default=300, help="duree d'un bloc de session")
    a = ap.parse_args()

    rows = list(read_conn(a.conn))
    if not rows:
        raise SystemExit("conn.log vide")
    rows.sort(key=lambda r: float(r["ts"]))
    t0 = float(rows[0]["ts"])
    rules = RULES[a.day]

    fam_count, fam_span = Counter(), {}
    blocks = defaultdict(Counter)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    cols = [k for k in KEEP if k in rows[0]] + ["label", "family", "session", "source_day"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow([c.replace(".", "_") for c in cols])
        for r in rows:
            ts = float(r["ts"])
            fam = family_of(r, rules)
            lab = 0 if fam == "BENIGN" else 1
            sess = f"{a.day}-b{int((ts - t0) // a.block_seconds):03d}"
            fam_count[fam] += 1
            lo, hi = fam_span.get(fam, (ts, ts))
            fam_span[fam] = (min(lo, ts), max(hi, ts))
            blocks[sess][lab] += 1
            vals = [("" if r[k] == "-" else r[k]) for k in KEEP if k in r]
            w.writerow(vals + [lab, fam, sess, a.day])

    mixed = [s for s, c in blocks.items() if c[0] and c[1]]
    summary = {
        "day": a.day, "conn_log": a.conn, "total": len(rows), "block_seconds": a.block_seconds,
        "families": {k: {"n": v, "first_utc": iso(fam_span[k][0]), "last_utc": iso(fam_span[k][1])}
                     for k, v in fam_count.items()},
        "n_blocks": len(blocks),
        "blocks_attack_only": sum(1 for c in blocks.values() if c[1] and not c[0]),
        "blocks_benign_only": sum(1 for c in blocks.values() if c[0] and not c[1]),
        "blocks_mixed": len(mixed),
    }
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
