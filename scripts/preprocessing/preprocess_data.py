#!/usr/bin/env python3
"""
Prétraitement des conn.log Zeek vers des features et métadonnées de flux.
Gère les logs TSV (par défaut) et JSON. Étiquetage : 0 = normal, 1 = attaque.
Les adresses sont conservées uniquement pour le regroupement par appareil.
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

# Catégories FIXES (pas de fit sur les données => aucune fuite train/test)
PROTO_CATS = ["tcp", "udp", "icmp"]
STATE_CATS = ["S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR",
              "RSTOS0", "RSTRH", "SH", "SHR", "OTH"]
NUM_COLS = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]


def load_conn_log(path):
    """Charge un conn.log Zeek (TSV ou JSON) en DataFrame."""
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        first = f.readline().strip()

    if first.startswith("{"):  # format JSON lines
        df = pd.read_json(path, lines=True)
    else:  # format TSV classique
        fields = None
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                    break
        if fields is None:
            raise ValueError("Ligne '#fields' introuvable : conn.log invalide.")
        df = pd.read_csv(path, sep="\t", comment="#", names=fields,
                         na_values=["-", "(empty)"], low_memory=False)
    return df


def build_labels(df, attacker_ips, label_value):
    """Label 1 si l'une des IP du flux est dans la liste des attaquants."""
    if attacker_ips:
        ips = set(attacker_ips)
        is_att = df["id.orig_h"].isin(ips) | df["id.resp_h"].isin(ips)
        return is_att.astype(int)
    return pd.Series(label_value, index=df.index, dtype=int)


def engineer_features(df):
    """Sélection, nettoyage, encodage, features dérivées."""
    out = pd.DataFrame(index=df.index)

    # Les champs absents sont imputés à zéro, sauf duration utilisée pour la causalité.
    for c in NUM_COLS:
        values = pd.to_numeric(df.get(c), errors="coerce")
        # Sans durée, la disponibilité causale des statistiques du flux est inconnue.
        out[c] = values if c == "duration" else values.fillna(0)

    # Features dérivées (utiles pour détecter scans / flood / exfiltration)
    out["total_bytes"] = out["orig_bytes"] + out["resp_bytes"]
    out["total_pkts"] = out["orig_pkts"] + out["resp_pkts"]
    out["bytes_ratio"] = out["orig_bytes"] / (out["total_bytes"] + 1)
    out["pkts_per_sec"] = out["total_pkts"] / (out["duration"] + 1e-6)
    out["bytes_per_pkt"] = out["total_bytes"] / (out["total_pkts"] + 1)

    # One-hot à catégories fixes
    proto = df["proto"].fillna("other").str.lower()
    state = df["conn_state"].fillna("OTH")
    for p in PROTO_CATS:
        out[f"proto_{p}"] = (proto == p).astype(int)
    for s in STATE_CATS:
        out[f"state_{s}"] = (state == s).astype(int)

    return out


def add_flow_metadata(features, df, capture_id):
    """Ajoute les métadonnées nécessaires au regroupement causal des flux."""
    required = {"ts", "duration", "id.orig_h", "id.resp_h"}
    missing = required.difference(df.columns)
    if missing:
        raise KeyError(
            "Champs Zeek nécessaires au regroupement absents : "
            + ", ".join(sorted(missing))
        )

    features["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    features["capture_id"] = capture_id
    features["src_ip"] = df["id.orig_h"].astype("string").fillna("")
    features["dst_ip"] = df["id.resp_h"].astype("string").fillna("")
    return features


def main():
    ap = argparse.ArgumentParser(description="Prétraitement conn.log Zeek")
    ap.add_argument("conn_log", help="Chemin du conn.log")
    ap.add_argument("-o", "--output", required=True, help="CSV de sortie")
    ap.add_argument("--capture-id", default=None,
                    help="Identifiant de la capture/session (sert au split anti-fuite)")
    ap.add_argument("--attacker-ips", default="",
                    help="IP des attaquants séparées par des virgules")
    ap.add_argument("--label", type=int, choices=[0, 1], default=0,
                    help="Label global si --attacker-ips absent (0 normal, 1 attaque)")
    args = ap.parse_args()

    df = load_conn_log(args.conn_log)
    print(f"[INFO] {len(df)} flux chargés depuis {args.conn_log}")

    ips = [x.strip() for x in args.attacker_ips.split(",") if x.strip()]
    labels = build_labels(df, ips, args.label)

    feats = engineer_features(df)
    feats = add_flow_metadata(
        feats, df, args.capture_id or Path(args.conn_log).parent.name
    )
    feats["label"] = labels.values

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    feats.to_csv(args.output, index=False)
    print(f"[SUCCESS] Dataset : {args.output}")
    print(feats["label"].value_counts().to_string())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        sys.exit(1)