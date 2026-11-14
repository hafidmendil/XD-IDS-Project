#!/usr/bin/env python3
"""Convertit un conn.log Zeek de CIC-IDS2017 en CSV de flux pour build_windows.py.

- label : regles IP/port de scripts/data/label_cic2017.py (jour monday ou tuesday).
- capture_id : bloc de temps (300 s par defaut) calcule comme build_windows.py le fait
  pour ses fenetres : un flux appartient a la fenetre de ts + duration, ancree sur
  l'epoque Unix. Un bloc etant un multiple de la fenetre, aucune fenetre ne chevauche
  deux blocs, et chaque bloc devient une session E2.

Usage (depuis la racine du depot) :
  python -m scripts.preprocessing.cic_flows --conn <conn.log> --day tuesday -o <flux.csv>
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from scripts.data.label_cic2017 import RULES
from scripts.preprocessing.preprocess_data import (
    add_flow_metadata,
    engineer_features,
    load_conn_log,
)


def label_flows(df, day):
    """Retourne (label 0/1, famille) selon les regles IP/port du jour."""
    label = pd.Series(0, index=df.index, dtype=int)
    family = pd.Series("BENIGN", index=df.index, dtype=object)
    resp_port = pd.to_numeric(df["id.resp_p"], errors="coerce")
    for rule in RULES[day]:
        mask = (
            (df["id.orig_h"] == rule["orig_h"])
            & (df["id.resp_h"] == rule["resp_h"])
            & (resp_port == int(rule["resp_p"]))
        )
        label.loc[mask] = 1
        family.loc[mask] = rule["family"]
    return label, family


def block_index(ts, duration, window_seconds, block_seconds):
    """Indice de bloc de la fenetre causale (ts + duration) de chaque flux."""
    window_end = np.ceil((ts + duration) / window_seconds) * window_seconds
    window_start = window_end - window_seconds
    return np.floor(window_start / block_seconds).astype("int64")


def iso(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--conn", required=True, help="conn.log Zeek (TSV ou JSON)")
    ap.add_argument("--day", required=True, choices=sorted(RULES))
    ap.add_argument("-o", "--output", required=True, help="CSV de flux en sortie")
    ap.add_argument("--window-seconds", type=float, default=60.0)
    ap.add_argument("--block-seconds", type=float, default=300.0)
    args = ap.parse_args()

    if args.block_seconds % args.window_seconds != 0:
        raise SystemExit("block-seconds doit etre un multiple de window-seconds.")

    df = load_conn_log(args.conn)
    features = engineer_features(df)
    features = add_flow_metadata(features, df, capture_id="tmp")
    label, family = label_flows(df, args.day)
    features["label"] = label

    known = features["duration"].notna() & features["ts"].notna()
    dropped = int((~known).sum())
    features = features.loc[known].copy()
    family = family.loc[known]
    blocks = block_index(
        features["ts"].to_numpy(dtype=float),
        features["duration"].to_numpy(dtype=float),
        args.window_seconds,
        args.block_seconds,
    )
    features["capture_id"] = [f"{args.day}-b{value}" for value in blocks]

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(out, index=False)

    per_block = (
        pd.DataFrame({"capture_id": features["capture_id"], "block": blocks,
                      "label": features["label"], "family": family})
        .groupby(["capture_id", "block"])
        .agg(flows=("label", "size"), attack_flows=("label", "sum"),
             families=("family", lambda s: "+".join(sorted(set(s) - {"BENIGN"})) or "BENIGN"))
        .reset_index()
        .sort_values("block")
    )
    per_block["block_start_utc"] = [iso(b * args.block_seconds) for b in per_block["block"]]
    per_block.to_csv(out.with_suffix(".blocks.csv"), index=False)

    summary = {
        "day": args.day,
        "flows_written": int(len(features)),
        "flows_dropped_unknown_duration": dropped,
        "flows_per_label": {str(k): int(v) for k, v in features["label"].value_counts().items()},
        "flows_per_family": {k: int(v) for k, v in family.value_counts().items()},
        "blocks": int(len(per_block)),
        "blocks_with_attack": int((per_block["attack_flows"] > 0).sum()),
        "first_block_utc": per_block["block_start_utc"].iloc[0],
        "last_block_utc": per_block["block_start_utc"].iloc[-1],
    }
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
