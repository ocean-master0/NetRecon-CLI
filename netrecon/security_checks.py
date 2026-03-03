from __future__ import annotations

import ipaddress
from typing import Iterable

from .models import ExternalIPInfo, FirewallDetectionResult, PortScanResult, SecurityCheckResult, TracerouteResult, WhoisResult

VPN_KEYWORDS = [
    "vpn",
    "wireguard",
    "openvpn",
    "nord",
    "expressvpn",
    "mullvad",
    "tunnel",
]

PROXY_KEYWORDS = [
    "proxy",
    "socks",
    "tor",
    "relay",
    "anonymizer",
]

HOSTING_KEYWORDS = [
    "datacenter",
    "hosting",
    "vps",
    "colo",
    "cloud",
    "digitalocean",
    "linode",
    "ovh",
    "aws",
    "azure",
    "gcp",
]


class SecurityChecker:
    """Evaluate network security indicators and firewall probability."""

    def __init__(self, risky_ports: list[int] | None = None) -> None:
        self.risky_ports = sorted(set(risky_ports or [21, 23, 25, 445, 3389, 5900]))

    def evaluate(
        self,
        ip_value: str | None,
        external_info: ExternalIPInfo | None = None,
        reverse_dns: str | None = None,
        whois_result: WhoisResult | None = None,
        open_ports: Iterable[int] | None = None,
        port_scan: PortScanResult | None = None,
        traceroute: TracerouteResult | None = None,
    ) -> SecurityCheckResult:
        """Return security classification and heuristic indicators."""
        classification = "Unknown"
        is_private: bool | None = None
        is_public: bool | None = None
        findings: list[str] = []

        if ip_value:
            try:
                parsed = ipaddress.ip_address(ip_value)
                is_private = parsed.is_private
                is_public = parsed.is_global
                if parsed.is_private:
                    classification = "Private"
                    findings.append("IP classification: private address space.")
                elif parsed.is_global:
                    classification = "Public"
                    findings.append("IP classification: publicly routable.")
                else:
                    classification = "Special/Reserved"
                    findings.append("IP classification: special or reserved range.")
            except ValueError:
                findings.append("Input IP is invalid and could not be classified.")

        text_parts = [
            reverse_dns or "",
            external_info.organization if external_info else "",
            external_info.isp if external_info else "",
            whois_result.organization if whois_result else "",
            whois_result.isp if whois_result else "",
        ]
        lowered_text = " ".join(part.lower() for part in text_parts if part)

        suspected_vpn = bool(external_info and external_info.vpn_detected)
        suspected_proxy = bool(external_info and external_info.proxy_detected)

        if any(keyword in lowered_text for keyword in VPN_KEYWORDS + HOSTING_KEYWORDS):
            suspected_vpn = True
        if any(keyword in lowered_text for keyword in PROXY_KEYWORDS):
            suspected_proxy = True

        if suspected_vpn:
            findings.append("VPN/hosting indicator found in network metadata.")
        if suspected_proxy:
            findings.append("Proxy/TOR indicator found in metadata.")

        open_port_list = sorted(set(int(port) for port in (open_ports or [])))
        risky_open_ports = sorted(port for port in open_port_list if port in self.risky_ports)
        if risky_open_ports:
            findings.append(f"Risky open ports detected: {', '.join(str(port) for port in risky_open_ports)}.")
        else:
            findings.append("No risky open ports detected from scanned set.")

        firewall = self.detect_firewall(port_scan=port_scan, traceroute=traceroute)
        if firewall.likely_firewall:
            findings.append(f"Likely firewall detected: {firewall.reason or 'traffic filtering patterns observed'}")

        risk_score = 0
        if classification == "Public":
            risk_score += 1
        if suspected_vpn:
            risk_score += 2
        if suspected_proxy:
            risk_score += 2
        risk_score += min(3, len(risky_open_ports))
        if firewall.likely_firewall:
            risk_score += 1
        if classification == "Private":
            risk_score = max(0, risk_score - 1)

        if risk_score <= 1:
            risk_level = "Low"
        elif risk_score <= 3:
            risk_level = "Medium"
        elif risk_score <= 5:
            risk_level = "High"
        else:
            risk_level = "Critical"

        return SecurityCheckResult(
            input_ip=ip_value,
            classification=classification,
            is_private=is_private,
            is_public=is_public,
            suspected_vpn=suspected_vpn,
            suspected_proxy=suspected_proxy,
            risky_open_ports=risky_open_ports,
            risk_level=risk_level,
            findings=findings,
            firewall=firewall,
        )

    @staticmethod
    def detect_firewall(
        *,
        port_scan: PortScanResult | None = None,
        traceroute: TracerouteResult | None = None,
    ) -> FirewallDetectionResult:
        """Infer firewall existence based on filtering and route behavior."""
        icmp_blocked = False
        filtered_ratio = 0.0
        likely_firewall = False
        reason: str | None = None

        if port_scan and port_scan.scanned_ports:
            filtered_ratio = len(port_scan.filtered_ports) / len(port_scan.scanned_ports)
            if filtered_ratio >= 0.5:
                likely_firewall = True
                reason = "High filtered-port ratio."
            elif len(port_scan.open_ports) == 0 and len(port_scan.filtered_ports) > 0:
                likely_firewall = True
                reason = "No open ports but filtered responses present."

        if traceroute and traceroute.hops:
            unknown_hops = sum(1 for hop in traceroute.hops if hop.ip is None)
            ratio = unknown_hops / len(traceroute.hops)
            if ratio >= 0.4:
                icmp_blocked = True
                likely_firewall = True
                reason = reason or "Traceroute contains many unknown hops."

        return FirewallDetectionResult(
            likely_firewall=likely_firewall,
            icmp_blocked=icmp_blocked,
            filtered_ratio=round(filtered_ratio, 2),
            reason=reason,
        )
