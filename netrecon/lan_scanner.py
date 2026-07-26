from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
import time

from .async_utils import run_async
from .models import LanHost, LanScanResult

MAC_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

_VENDOR_MAP: dict[str, str] = {
    "00005e": "VMware",
    "000c29": "VMware",
    "005056": "VMware",
    "001c14": "VMware",
    "001c42": "VMware",
    "0003ff": "Microsoft",
    "0015d1": "Microsoft",
    "002248": "Microsoft",
    "0050f2": "Microsoft",
    "00037f": "Intel",
    "001111": "Intel",
    "0016ea": "Intel",
    "001b21": "Intel",
    "001cbf": "Intel",
    "002219": "Intel",
    "020000": "Intel",
    "04ea56": "Intel",
    "000cf1": "Dell",
    "00188b": "Dell",
    "0021cc": "Dell",
    "b8ca3a": "Dell",
    "002590": "Dell",
    "0015c5": "Cisco",
    "001646": "Cisco",
    "001a2f": "Cisco",
    "001e7a": "Cisco",
    "0021a0": "Cisco",
    "0026cb": "Cisco",
    "0050e0": "Cisco",
    "0050f2": "Cisco",
    "00906f": "Cisco",
    "00e014": "Cisco",
    "0c75bd": "Cisco",
    "18a99b": "Cisco",
    "1cc04f": "Cisco",
    "244cec": "Cisco",
    "38c87c": "Cisco",
    "4025c2": "Cisco",
    "48b8d8": "Cisco",
    "54a050": "Cisco",
    "588d09": "Cisco",
    "6476ba": "Cisco",
    "6c9ced": "Cisco",
    "7081eb": "Cisco",
    "74a722": "Cisco",
    "78baf9": "Cisco",
    "84b807": "Cisco",
    "8cbebe": "Cisco",
    "acf11e": "Cisco",
    "b0faeb": "Cisco",
    "ccd9ac": "Cisco",
    "002128": "Hewlett Packard",
    "0030c1": "Hewlett Packard",
    "0050a5": "Hewlett Packard",
    "083fbc": "Hewlett Packard",
    "38229d": "Hewlett Packard",
    "5866ba": "Hewlett Packard",
    "64006a": "Hewlett Packard",
    "9cd917": "Hewlett Packard",
    "c8d5fe": "Hewlett Packard",
    "0015c6": "Huawei",
    "00259e": "Huawei",
    "00605e": "Huawei",
    "0c1da2": "Huawei",
    "0cd2b5": "Huawei",
    "1062c9": "Huawei",
    "14d64d": "Huawei",
    "180373": "Huawei",
    "2008ed": "Huawei",
    "24e9b3": "Huawei",
    "2829cc": "Huawei",
    "30b4b3": "Huawei",
    "342919": "Huawei",
    "3c2c30": "Huawei",
    "3cd0f8": "Huawei",
    "48022a": "Huawei",
    "4c77cb": "Huawei",
    "58a76f": "Huawei",
    "60f277": "Huawei",
    "64a65c": "Huawei",
    "681ab7": "Huawei",
    "6cb989": "Huawei",
    "803be2": "Huawei",
    "885396": "Huawei",
    "90e7c0": "Huawei",
    "9870e8": "Huawei",
    "a4e319": "Huawei",
    "ac48d7": "Huawei",
    "bcee7b": "Huawei",
    "c0f8da": "Huawei",
    "d469ea": "Huawei",
    "e0e751": "Huawei",
    "e8b748": "Huawei",
    "f84a7f": "Huawei",
    "fcb86a": "Huawei",
    "00aa01": "Xerox",
    "0017f2": "Apple",
    "00261c": "Apple",
    "04f13e": "Apple",
    "049a5e": "Apple",
    "080007": "Apple",
    "0c3e6e": "Apple",
    "0c3f41": "Apple",
    "100e7e": "Apple",
    "14c0cc": "Apple",
    "18ee6c": "Apple",
    "1c9e46": "Apple",
    "1cfcbb": "Apple",
    "24a074": "Apple",
    "28cfda": "Apple",
    "2c200b": "Apple",
    "303255": "Apple",
    "340086": "Apple",
    "34a395": "Apple",
    "34c059": "Apple",
    "382c4a": "Apple",
    "3cd16e": "Apple",
    "40aad0": "Apple",
    "44d884": "Apple",
    "48e1e9": "Apple",
    "5045f4": "Apple",
    "54e43a": "Apple",
    "5cf938": "Apple",
    "6010e6": "Apple",
    "64a3c3": "Apple",
    "681b6e": "Apple",
    "6c7ae5": "Apple",
    "6c96cf": "Apple",
    "704db3": "Apple",
    "74e1b6": "Apple",
    "78a351": "Apple",
    "78c6bb": "Apple",
    "7c04d0": "Apple",
    "7c6b52": "Apple",
    "7cca7e": "Apple",
    "808cf1": "Apple",
    "84969d": "Apple",
    "84ad54": "Apple",
    "88aede": "Apple",
    "8ced5c": "Apple",
    "8cf57d": "Apple",
    "94321b": "Apple",
    "98f0ab": "Apple",
    "9a8e8f": "Apple",
    "9cf387": "Apple",
    "a020b4": "Apple",
    "a08869": "Apple",
    "a42b8c": "Apple",
    "a4d1d1": "Apple",
    "a8b84e": "Apple",
    "ac29c9": "Apple",
    "acec80": "Apple",
    "b0481a": "Apple",
    "b0e235": "Apple",
    "b4527d": "Apple",
    "b4f3d4": "Apple",
    "b8960a": "Apple",
    "bc5461": "Apple",
    "bc928a": "Apple",
    "c02d0b": "Apple",
    "c09501": "Apple",
    "c0b29b": "Apple",
    "c4c101": "Apple",
    "c8665d": "Apple",
    "cc25ef": "Apple",
    "d023db": "Apple",
    "d4d749": "Apple",
    "d893e0": "Apple",
    "dc2b2a": "Apple",
    "dc8111": "Apple",
    "e02987": "Apple",
    "e0c753": "Apple",
    "e865d4": "Apple",
    "e89120": "Apple",
    "ecadd8": "Apple",
    "f0061c": "Apple",
    "f02329": "Apple",
    "f08c50": "Apple",
    "f0b0e7": "Apple",
    "f0bf97": "Apple",
    "f0d1b8": "Apple",
    "f4b164": "Apple",
    "f4f5d8": "Apple",
    "f8a45f": "Apple",
    "fcfadd": "Apple",
    "001d0f": "Google",
    "0026b0": "Google",
    "08606e": "Google",
    "0c204e": "Google",
    "14a64b": "Google",
    "246941": "Google",
    "28a0d6": "Google",
    "2c2264": "Google",
    "38b1db": "Google",
    "3c224b": "Google",
    "44a1bb": "Google",
    "54a10e": "Google",
    "60a4b7": "Google",
    "70405b": "Google",
    "78eb14": "Google",
    "7cc3a1": "Google",
    "843a4b": "Google",
    "88ed1c": "Google",
    "8caa3f": "Google",
    "a4badb": "Google",
    "a88792": "Google",
    "bce33d": "Google",
    "c0eee1": "Google",
    "c8d7b5": "Google",
    "ccb762": "Google",
    "d099d5": "Google",
    "d4f0b4": "Google",
    "d80eb6": "Google",
    "dc4415": "Google",
    "e0a30e": "Google",
    "e48c22": "Google",
    "f8b599": "Google",
    "fcc234": "Google",
    "0011a0": "Samsung",
    "001e4e": "Samsung",
    "002511": "Samsung",
    "002618": "Samsung",
    "044245": "Samsung",
    "04cb1d": "Samsung",
    "0c5a02": "Samsung",
    "0cb951": "Samsung",
    "1c4a36": "Samsung",
    "241451": "Samsung",
    "245af2": "Samsung",
    "2c0614": "Samsung",
    "2c5a05": "Samsung",
    "30cdb0": "Samsung",
    "30d6c9": "Samsung",
    "380a8a": "Samsung",
    "3c5c0c": "Samsung",
    "3e8a12": "Samsung",
    "48691e": "Samsung",
    "487a33": "Samsung",
    "58a023": "Samsung",
    "5c4919": "Samsung",
    "5e6b8a": "Samsung",
    "6045e3": "Samsung",
    "64653d": "Samsung",
    "6c2e0b": "Samsung",
    "6c8969": "Samsung",
    "70ccc0": "Samsung",
    "7479ba": "Samsung",
    "802b43": "Samsung",
    "843f4e": "Samsung",
    "848f2b": "Samsung",
    "887679": "Samsung",
    "8cbeea": "Samsung",
    "8cfdf0": "Samsung",
    "90341c": "Samsung",
    "9880a3": "Samsung",
    "a4767a": "Samsung",
    "ac5e8c": "Samsung",
    "b072bf": "Samsung",
    "b47714": "Samsung",
    "b8b94e": "Samsung",
    "c0894d": "Samsung",
    "c82a14": "Samsung",
    "c8a30d": "Samsung",
    "cccc6f": "Samsung",
    "ccf940": "Samsung",
    "d006c0": "Samsung",
    "dc68eb": "Samsung",
    "e0040b": "Samsung",
    "e80624": "Samsung",
    "ec1f72": "Samsung",
    "f04931": "Samsung",
    "f4c03b": "Samsung",
    "f8c796": "Samsung",
    "fc034a": "Samsung",
    "10c37b": "TP-Link",
    "14cf92": "TP-Link",
    "1c3e84": "TP-Link",
    "20dce0": "TP-Link",
    "2cb43d": "TP-Link",
    "30b49e": "TP-Link",
    "34e894": "TP-Link",
    "3cce73": "TP-Link",
    "3cd16d": "TP-Link",
    "4ce677": "TP-Link",
    "50c7bf": "TP-Link",
    "54cf92": "TP-Link",
    "58238c": "TP-Link",
    "5c6a7d": "TP-Link",
    "609b37": "TP-Link",
    "64e682": "TP-Link",
    "68a86d": "TP-Link",
    "6c3a84": "TP-Link",
    "704f57": "TP-Link",
    "74da38": "TP-Link",
    "7c48d9": "TP-Link",
    "84a8e4": "TP-Link",
    "8cade8": "TP-Link",
    "90a42a": "TP-Link",
    "94d9b3": "TP-Link",
    "a0f3c1": "TP-Link",
    "a4a112": "TP-Link",
    "a4da3f": "TP-Link",
    "b0abe1": "TP-Link",
    "b0bed4": "TP-Link",
    "b0e2e5": "TP-Link",
    "b0f893": "TP-Link",
    "bcd094": "TP-Link",
    "bcff0c": "TP-Link",
    "c0c962": "TP-Link",
    "c48a7d": "TP-Link",
    "c822f7": "TP-Link",
    "cc32e5": "TP-Link",
    "d00790": "TP-Link",
    "d4258b": "TP-Link",
    "d48cb5": "TP-Link",
    "d847ae": "TP-Link",
    "dc094c": "TP-Link",
    "e0508b": "TP-Link",
    "e8de27": "TP-Link",
    "ec6dfa": "TP-Link",
    "f08e80": "TP-Link",
    "f40b93": "TP-Link",
    "f81a67": "TP-Link",
    "fc589c": "TP-Link",
    "fc7516": "TP-Link",
    "000b5f": "Netgear",
    "001c12": "Netgear",
    "0022b0": "Netgear",
    "0050f0": "Netgear",
    "008037": "Netgear",
    "080010": "Netgear",
    "0c394d": "Netgear",
    "20e564": "Netgear",
    "28c2dd": "Netgear",
    "2c3308": "Netgear",
    "2c36f8": "Netgear",
    "3822d6": "Netgear",
    "3c2ef3": "Netgear",
    "3cdcbc": "Netgear",
    "3ce5a6": "Netgear",
    "4487fc": "Netgear",
    "4c9bb5": "Netgear",
    "4cb4ea": "Netgear",
    "503ee1": "Netgear",
    "5c4ca9": "Netgear",
    "5cf438": "Netgear",
    "643839": "Netgear",
    "6c37ce": "Netgear",
    "6c5a34": "Netgear",
    "6cd48f": "Netgear",
    "705a0e": "Netgear",
    "70b1a0": "Netgear",
    "78d6dc": "Netgear",
    "801f02": "Netgear",
    "846b15": "Netgear",
    "88a25e": "Netgear",
    "8c1b5b": "Netgear",
    "8c3c07": "Netgear",
    "905f8c": "Netgear",
    "942eb2": "Netgear",
    "980d6f": "Netgear",
    "98da34": "Netgear",
    "a0a230": "Netgear",
    "a0b37a": "Netgear",
    "a43717": "Netgear",
    "a4516f": "Netgear",
    "a46619": "Netgear",
    "a85b78": "Netgear",
    "b8c6a7": "Netgear",
    "c4035e": "Netgear",
    "c41d71": "Netgear",
    "c6a345": "Netgear",
    "c8d15e": "Netgear",
    "cc7d37": "Netgear",
    "d02148": "Netgear",
    "d067e5": "Netgear",
    "d44a44": "Netgear",
    "d8d5b9": "Netgear",
    "d8e600": "Netgear",
    "dc9fdb": "Netgear",
    "e0899d": "Netgear",
    "e0aeed": "Netgear",
    "e0d748": "Netgear",
    "e42987": "Netgear",
    "e44f29": "Netgear",
    "e4f3e2": "Netgear",
    "f03e90": "Netgear",
    "f082e9": "Netgear",
    "f4c714": "Netgear",
    "f4f2e8": "Netgear",
    "f84acc": "Netgear",
    "fc2a32": "Netgear",
    "fc3d93": "Netgear",
    "fcb08a": "Netgear",
    "001377": "Asus",
    "0022b0": "Asus",
    "089f92": "Asus",
    "0c6e03": "Asus",
    "10f95c": "Asus",
    "1ab0c3": "Asus",
    "207021": "Asus",
    "24ae74": "Asus",
    "2c56dc": "Asus",
    "3085a9": "Asus",
    "3cf01c": "Asus",
    "40b7f3": "Asus",
    "447c7f": "Asus",
    "48d539": "Asus",
    "4c0289": "Asus",
    "5026a6": "Asus",
    "54a953": "Asus",
    "5842e4": "Asus",
    "5c4964": "Asus",
    "645d92": "Asus",
    "7054d2": "Asus",
    "74d02b": "Asus",
    "807b1e": "Asus",
    "845f69": "Asus",
    "8c8590": "Asus",
    "94c6d1": "Asus",
    "9892fb": "Asus",
    "a0999b": "Asus",
    "a4c361": "Asus",
    "ac220b": "Asus",
    "b0c745": "Asus",
    "b4f908": "Asus",
    "b8ef41": "Asus",
    "bc9fef": "Asus",
    "c80e77": "Asus",
    "ccce1e": "Asus",
    "cceb2d": "Asus",
    "d02788": "Asus",
    "d4c91e": "Asus",
    "da6c37": "Asus",
    "dc4f22": "Asus",
    "dcb4c4": "Asus",
    "e06c83": "Asus",
    "e85a9a": "Asus",
    "ec26ca": "Asus",
    "f07816": "Asus",
    "f09e63": "Asus",
    "f4c700": "Asus",
    "f8c091": "Asus",
    "000423": "Raspberry Pi",
    "b827eb": "Raspberry Pi",
    "d83add": "Raspberry Pi",
    "e45f01": "Raspberry Pi",
    "000c6e": "Aruba",
    "002197": "Aruba",
    "005b06": "Fortinet",
    "001a4b": "Juniper",
    "001b8c": "Juniper",
    "002338": "Juniper",
    "002469": "Juniper",
    "00e04c": "Juniper",
    "0cc47d": "Ubiquiti",
    "18e8df": "Ubiquiti",
    "24a43c": "Ubiquiti",
    "44d9e7": "Ubiquiti",
    "64d1a3": "Ubiquiti",
    "74acb9": "Ubiquiti",
    "78acc0": "Ubiquiti",
    "7cf050": "Ubiquiti",
    "803f5d": "Ubiquiti",
    "849ca6": "Ubiquiti",
    "a020a6": "Ubiquiti",
    "c08b6f": "Ubiquiti",
    "d487d8": "Ubiquiti",
    "e063e1": "Ubiquiti",
    "ec609b": "Ubiquiti",
    "f093c3": "Ubiquiti",
    "00155d": "Citrix",
    "00e07c": "Oracle",
    "00147f": "IBM",
    "005043": "IBM",
    "08005a": "IBM",
    "fc4a30": "Zyxel",
    "000277": "LG Electronics",
    "00265f": "LG Electronics",
    "3c5244": "LG Electronics",
    "44d2ca": "LG Electronics",
    "7cf429": "LG Electronics",
    "8ccfa7": "LG Electronics",
    "902b34": "LG Electronics",
    "bc6c21": "LG Electronics",
    "c08a7b": "LG Electronics",
    "f4a2b6": "LG Electronics",
    "00177c": "Motorola",
    "001f6a": "Motorola",
    "0024f0": "Motorola",
    "2c2d48": "Motorola",
    "3cdfa9": "Motorola",
    "508cda": "Motorola",
    "64789c": "Motorola",
    "705af5": "Motorola",
    "7ce044": "Motorola",
    "a0cbbc": "Motorola",
    "b4b5af": "Motorola",
    "c4d987": "Motorola",
    "d87a75": "Motorola",
    "e4699c": "Motorola",
    "ec5b67": "Motorola",
    "f42ac6": "Motorola",
    "001c7e": "Nokia",
    "4cf06f": "Nokia",
    "5cf962": "Nokia",
    "64166d": "Nokia",
    "98f170": "Nokia",
    "fcecda": "Nokia",
}


def _oui_lookup(mac: str | None) -> str | None:
    if not mac:
        return None
    normalized = mac.lower().replace("-", ":").replace(".", "")
    parts = normalized.split(":")
    if len(parts) < 3:
        return None
    oui = "".join(parts[:3])
    return _VENDOR_MAP.get(oui)


class LANScanner:
    """Local network scanner for active host discovery."""

    def __init__(self, timeout_ms: int = 800, max_workers: int = 256) -> None:
        self.timeout_ms = max(100, timeout_ms)
        self.max_workers = max(1, max_workers)

    async def scan_async(self, cidr: str) -> LanScanResult:
        started = time.perf_counter()
        warnings: list[str] = []

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            return LanScanResult(cidr=cidr, warnings=[f"Invalid CIDR: {exc}"])

        hosts = [str(host) for host in network.hosts()]
        if not hosts:
            return LanScanResult(cidr=cidr, warnings=["No host addresses found in CIDR."])

        if len(hosts) > 1024:
            warnings.append("Large network detected; limiting to first 1024 hosts for safety.")
            hosts = hosts[:1024]

        semaphore = asyncio.Semaphore(self.max_workers)

        async def _probe(ip_value: str) -> str | None:
            async with semaphore:
                alive = await self._ping_host(ip_value)
                return ip_value if alive else None

        tasks = [asyncio.create_task(_probe(host)) for host in hosts]
        active_ips: list[str] = []
        for task in asyncio.as_completed(tasks):
            active = await task
            if active:
                active_ips.append(active)
        active_ips.sort(key=lambda item: tuple(int(part) for part in item.split(".")))

        mac_map = await asyncio.to_thread(self._read_arp_table)
        lan_hosts: list[LanHost] = []
        for ip_value in active_ips:
            hostname = await asyncio.to_thread(self._reverse_lookup, ip_value)
            mac = mac_map.get(ip_value)
            lan_hosts.append(
                LanHost(
                    ip=ip_value,
                    hostname=hostname,
                    mac_address=mac,
                    vendor=_oui_lookup(mac),
                )
            )

        duration = round(time.perf_counter() - started, 4)
        return LanScanResult(cidr=cidr, active_hosts=lan_hosts, duration_seconds=duration, warnings=warnings)

    def scan(self, cidr: str) -> LanScanResult:
        """Synchronous wrapper for async LAN scan."""
        return run_async(self.scan_async(cidr))

    async def _ping_host(self, ip_value: str) -> bool:
        system_name = platform.system()
        if system_name == "Windows":
            command = ["ping", "-n", "1", "-w", str(self.timeout_ms), ip_value]
        elif system_name == "Darwin":
            command = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout_ms / 1000))), ip_value]
        else:
            command = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout_ms / 1000))), ip_value]

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=max(2, int(self.timeout_ms / 1000) + 1))
            return proc.returncode == 0
        except (OSError, asyncio.TimeoutError):
            return False

    @staticmethod
    def _read_arp_table() -> dict[str, str]:
        system_name = platform.system()
        command = ["arp", "-a"] if system_name == "Windows" else ["arp", "-an"]
        output = ""
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
            output = proc.stdout or ""
        except (OSError, subprocess.TimeoutExpired):
            return {}

        mapping: dict[str, str] = {}
        for line in output.splitlines():
            ip_match = IP_PATTERN.search(line)
            mac_match = MAC_PATTERN.search(line)
            if not ip_match or not mac_match:
                continue
            mapping[ip_match.group(1)] = mac_match.group(0).lower().replace("-", ":")
        return mapping

    @staticmethod
    def _reverse_lookup(ip_value: str) -> str | None:
        try:
            host, _, _ = socket.gethostbyaddr(ip_value)
            return host
        except (socket.herror, socket.gaierror, OSError):
            return None



