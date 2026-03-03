import unittest

from netrecon.models import ExternalIPInfo, PortScanResult, TracerouteResult, WhoisResult
from netrecon.security_checks import SecurityChecker


class SecurityCheckerTests(unittest.TestCase):
    def test_firewall_and_risk_level(self):
        checker = SecurityChecker(risky_ports=[23, 445])
        port_scan = PortScanResult(
            target="8.8.8.8",
            scanned_ports=[23, 80, 445, 3389],
            open_ports=[23],
            closed_ports=[80],
            filtered_ports=[445, 3389],
            risky_open_ports=[23],
        )
        traceroute = TracerouteResult(target="8.8.8.8", method="test", hops=[])
        external = ExternalIPInfo(ip="8.8.8.8", organization="VPN Hosting")
        whois = WhoisResult(query="8.8.8.8", organization="Proxy Org")
        result = checker.evaluate(
            ip_value="8.8.8.8",
            external_info=external,
            whois_result=whois,
            open_ports=port_scan.open_ports,
            port_scan=port_scan,
            traceroute=traceroute,
        )
        self.assertTrue(result.suspected_vpn)
        self.assertTrue(result.suspected_proxy)
        self.assertTrue(result.firewall.likely_firewall)


if __name__ == "__main__":
    unittest.main()
