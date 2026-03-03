"""
Legacy compatibility wrapper for the old `ip_finder.py` entrypoint.

For full features, use:
    python main.py --help
"""

from __future__ import annotations

from netrecon.ip_scanner import IPScanner


def get_all_ip_info() -> None:
    """Print basic local and external IP details."""
    scanner = IPScanner()

    local_ips = scanner.collect_local_ips()
    print("Hostname/Local IP Information")
    print("-" * 40)
    if local_ips:
        for ip_value in local_ips:
            print(f"  - {ip_value}")
    else:
        print("  No local IPs found.")

    external_info, warnings = scanner.lookup_external_ip()
    if external_info:
        print("\nExternal IP Information")
        print("-" * 40)
        print(f"IP: {external_info.ip}")
        print(f"Location: {external_info.city}, {external_info.region}, {external_info.country}")
        print(f"Coordinates: {external_info.coordinates}")
        print(f"Organization: {external_info.organization}")

        reverse_dns, reverse_warning = scanner.reverse_dns_lookup(external_info.ip)
        if reverse_dns:
            print(f"Reverse DNS: {reverse_dns}")
        if reverse_warning:
            warnings.append(reverse_warning)
    else:
        print("\nExternal IP lookup failed.")

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"  - {warning}")


if __name__ == "__main__":
    get_all_ip_info()
