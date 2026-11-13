"""Tests de l’audit des PCAP et du registre deduplicated."""

from scapy.all import IP, TCP, wrpcap

from scripts.data.audit_pcaps import (
    audit_pcap_directory,
    build_capture_registry,
    flag_duplicates,
    infer_label,
)


def _make_pcap(path, start_time, payload_size, attack=False):
    packets = []
    for index in range(2):
        payload = b"x" * payload_size if not attack else b"y" * payload_size
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=1234, dport=80, seq=index + 1, flags="PA"
        ) / payload
        packet.time = float(start_time + index)
        packets.append(packet)
    wrpcap(str(path), packets)


def test_audit_pcap_directory_and_duplicate_detection(tmp_path):
    root = tmp_path / "captures"
    root.mkdir()

    normal_path = root / "normal.pcap"
    duplicate_path = root / "normal_copy.pcap"
    attack_path = root / "mirai.pcap"
    attack_duplicate_path = root / "mirai_dup.pcap"

    _make_pcap(normal_path, 100.0, 10, attack=False)
    _make_pcap(duplicate_path, 100.0, 10, attack=False)
    _make_pcap(attack_path, 200.0, 18, attack=True)
    _make_pcap(attack_duplicate_path, 200.0, 18, attack=True)

    inventory = audit_pcap_directory(root)
    flagged = flag_duplicates(inventory)
    retained = build_capture_registry(flagged)

    assert len(inventory) == 4
    assert flagged["is_duplicate"].sum() == 2
    assert len(retained) == 2
    assert {record["id"] for record in retained} == {"normal", "mirai"}
    assert infer_label("normal.pcap") == 0
    assert infer_label("mirai.pcap") == 1
