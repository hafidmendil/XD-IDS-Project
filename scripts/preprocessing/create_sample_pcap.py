#!/usr/bin/env python3
""" Génère un fichier PCAP factice pour tester l'extraction Zeek """
import sys
from pathlib import Path

try:
    from scapy.all import IP, TCP, UDP, Raw, wrpcap
except ImportError:
    print("[!] Le module 'scapy' est requis pour générer le pcap de test.")
    print("    Installation : pip install scapy")
    sys.exit(1)

out_dir = Path("~/XD-IDS_Project/data/raw_pcap").expanduser().resolve()
out_dir.mkdir(parents=True, exist_ok=True)
pcap_file = out_dir / "sample_test.pcap"

pkts = [
    IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="S"),
    IP(src="192.168.1.1", dst="192.168.1.50")/TCP(sport=80, dport=12345, flags="SA"),
    IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="A")/Raw(b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n"),
    IP(src="192.168.1.100", dst="192.168.1.1")/UDP(sport=1883, dport=1883)/Raw(b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"),
]

wrpcap(str(pcap_file), pkts)
print(f"[SUCCESS] Fichier PCAP de test généré : {pcap_file}")
