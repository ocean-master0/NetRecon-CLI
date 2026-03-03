from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .models import SnifferResult


class PacketSniffer:
    """Packet sniffer for suspicious traffic heuristics."""

    def capture(self, *, limit: int = 200, timeout: int = 15) -> SnifferResult:
        warnings: list[str] = []
        suspicious: list[str] = []

        try:
            from scapy.all import ARP, DNS, DNSRR, IP, sniff  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            return SnifferResult(
                packets_captured=0,
                warnings=["scapy is not installed. Install with: pip install scapy"],
            )

        packets: list[Any]
        try:
            packets = sniff(count=max(1, limit), timeout=max(1, timeout), store=True)
        except PermissionError as exc:
            return SnifferResult(packets_captured=0, warnings=[f"Sniffing requires elevated privileges: {exc}"])
        except OSError as exc:
            return SnifferResult(packets_captured=0, warnings=[f"Sniffing failed: {exc}"])

        src_counter: Counter[str] = Counter()
        arp_map: dict[str, str] = {}
        dns_answer_map: dict[str, set[str]] = defaultdict(set)

        for packet in packets:
            if packet.haslayer(IP):
                src_counter[str(packet[IP].src)] += 1

            if packet.haslayer(ARP) and int(packet[ARP].op) == 2:
                psrc = str(packet[ARP].psrc)
                hwsrc = str(packet[ARP].hwsrc).lower()
                if psrc in arp_map and arp_map[psrc] != hwsrc:
                    suspicious.append(f"Possible ARP spoofing: {psrc} changed MAC {arp_map[psrc]} -> {hwsrc}")
                arp_map[psrc] = hwsrc

            if packet.haslayer(DNS) and packet.haslayer(DNSRR):
                qname = str(packet[DNS].qd.qname, errors="ignore") if packet[DNS].qd else ""
                answer = str(packet[DNSRR].rdata)
                if qname:
                    dns_answer_map[qname].add(answer)
                    if len(dns_answer_map[qname]) > 3:
                        suspicious.append(f"Potential DNS poisoning: high answer variance for {qname}")

        high_traffic = [src for src, count in src_counter.items() if count > max(30, int(limit * 0.25))]
        for source in high_traffic:
            suspicious.append(f"High traffic anomaly detected from source {source}")

        if not packets:
            warnings.append("No packets captured in the selected window.")

        return SnifferResult(
            packets_captured=len(packets),
            suspicious_events=sorted(set(suspicious)),
            warnings=warnings,
        )
