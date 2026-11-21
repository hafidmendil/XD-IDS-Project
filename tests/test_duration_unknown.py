import pandas as pd

from scripts.preprocessing.preprocess_data import engineer_features


def _flows(durations, orig_pkts, resp_pkts):
    n = len(durations)
    return pd.DataFrame(
        {
            "duration": durations,
            "orig_bytes": [0] * n,
            "resp_bytes": [0] * n,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "proto": ["tcp"] * n,
            "conn_state": ["S0"] * n,
        }
    )


def test_single_packet_flow_without_duration_is_instantaneous():
    out = engineer_features(_flows(["-", "-", "2.5"], [1, 3, 4], [0, 0, 2]))
    assert out["duration_unknown"].tolist() == [1, 0, 0]
    assert out.loc[0, "duration"] == 0.0
    assert out.loc[0, "pkts_per_sec"] == 0.0
    assert pd.isna(out.loc[1, "duration"])  # plusieurs paquets : reste inconnu
    assert out.loc[2, "duration"] == 2.5
