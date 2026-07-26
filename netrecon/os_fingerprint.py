from __future__ import annotations

import asyncio
import logging
import platform
import re
import struct
import subprocess
import time

from .models import OsFingerprintResult

LOGGER = logging.getLogger(__name__)

TTL_SIGNATURES: dict[int, list[str]] = {
    32: ["Solaris", "AIX"],
    60: ["AIX (TCP)"],
    64: ["Linux", "macOS", "FreeBSD", "Android"],
    128: ["Windows", "Solaris (ICMP)"],
    255: ["Cisco IOS", "Solaris"],
}

WINDOW_SIGNATURES: dict[int, list[str]] = {
    5840: ["Linux (old kernel)"],
    65535: ["FreeBSD", "macOS", "Windows XP"],
    8192: ["Windows Vista/7"],
    64240: ["Windows 10/11", "Linux (modern)"],
    29200: ["Linux (modern)"],
    32120: ["Linux (modern)"],
    4128: ["Cisco IOS"],
}

MSS_SIGNATURES: dict[int, list[str]] = {
    1460: ["Ethernet (most OSes)"],
    1440: ["PPPoE (DSL)"],
    1452: ["PPTP (VPN)"],
    1380: ["Cisco"],
    1360: ["Some VPNs"],
    536: ["Default RFC"],
}


def _guess_os_from_ttl(ttl: int) -> tuple[str | None, float]:
    observed = ttl
    best_match: tuple[str | None, float] = (None, 0.0)
    for base_ttl, os_list in sorted(TTL_SIGNATURES.items(), reverse=True):
        if observed <= base_ttl and observed > base_ttl - 10:
            confidence = max(0.5, 1.0 - (base_ttl - observed) / 10.0)
            best_match = (os_list[0], round(confidence, 2))
            break
    if best_match[0] is None:
        for base_ttl, os_list in sorted(TTL_SIGNATURES.items(), reverse=True):
            diff = abs(base_ttl - observed)
            if diff <= 15:
                confidence = max(0.3, 1.0 - diff / 20.0)
                candidate = (os_list[0], round(confidence, 2))
                if candidate[1] > best_match[1]:
                    best_match = candidate
    return best_match


def _guess_os_from_window(window: int) -> str | None:
    closest = min(WINDOW_SIGNATURES.keys(), key=lambda k: abs(k - window))
    if abs(closest - window) <= closest * 0.1:
        return WINDOW_SIGNATURES[closest][0]
    return None


def _parse_ping_ttl(output: str) -> int | None:
    for pattern in [r"TTL[=\s]*(\d+)", r"ttl[=\s]*(\d+)", r"time to live[=\s]*(\d+)"]:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return int(match.group(1))

    match = re.search(r"time[=<]\s*[\d.]+.*\s+(\d{1,3})\s", output)
    if match:
        return int(match.group(1))
    return None


async def _ping_with_ttl(host: str, timeout_ms: int = 3000) -> tuple[int | None, float | None]:
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=max(2, int(timeout_ms / 1000) + 1)
        )
        output = stdout.decode("utf-8", errors="replace") if stdout else ""
    except (OSError, asyncio.TimeoutError):
        return None, None

    ttl = _parse_ping_ttl(output)
    if not ttl:
        return None, None

    latency_match = re.search(r"time[=<]\s*([\d.]+)", output, re.IGNORECASE)
    latency = float(latency_match.group(1)) if latency_match else None
    return ttl, latency


def _scapy_fingerprint(host: str) -> tuple[str | None, str | None, int | None, int | None]:
    """Attempt OS fingerprint using Scapy SYN probe (optional dependency)."""
    try:
        from scapy.all import IP, TCP, conf, sr1  # type: ignore[import-not-found]
        conf.verb = 0
        packet = IP(dst=host) / TCP(dport=80, flags="S")
        reply = sr1(packet, timeout=3, verbose=0)
        if reply is None:
            return None, None, None, None
        ttl = reply[IP].ttl if reply.haslayer(IP) else None
        window = reply[TCP].window if reply.haslayer(TCP) else None
        options_raw = reply[TCP].options if reply.haslayer(TCP) else None
        options_str = str(options_raw) if options_raw else None
        return ttl, options_str, window, None
    except ImportError:
        LOGGER.debug("Scapy not available for OS fingerprinting.")
        return None, None, None, None
    except Exception as exc:
        LOGGER.debug("Scapy fingerprint failed: %s", exc)
        return None, None, None, None


async def fingerprint_os(host: str, banner_window: int | None = None) -> OsFingerprintResult:
    ttl_sources: list[tuple[str | None, str | None]] = []
    os_candidates: dict[str, float] = {}
    details: list[str] = []

    ttl, latency = await _ping_with_ttl(host)
    if ttl:
        ttl_sources.append(("ping", str(ttl)))
        os_name, confidence = _guess_os_from_ttl(ttl)
        if os_name:
            os_candidates[os_name] = max(os_candidates.get(os_name, 0), confidence)
            details.append(f"TTL={ttl} suggests {os_name} (confidence {confidence:.0%})")

    if banner_window:
        ttl_sources.append(("banner", str(banner_window)))
        os_name = _guess_os_from_window(banner_window)
        if os_name:
            os_candidates[os_name] = max(os_candidates.get(os_name, 0), 0.5)
            details.append(f"Window={banner_window} suggests {os_name}")

    try:
        s = socket_tcp_window(host, 80)
        if s:
            ttl_sources.append(("socket", str(s)))
    except Exception:
        pass

    scapy_ttl, scapy_options, scapy_window, _ = await asyncio.to_thread(_scapy_fingerprint, host)
    if scapy_ttl:
        ttl_sources.append(("scapy", str(scapy_ttl)))
        os_name, confidence = _guess_os_from_ttl(scapy_ttl)
        if os_name:
            os_candidates[os_name] = max(os_candidates.get(os_name, 0), confidence)
            details.append(f"Scapy TTL={scapy_ttl} suggests {os_name}")
    if scapy_options:
        details.append(f"TCP options: {scapy_options[:60]}...")

    best_os = max(os_candidates, key=os_candidates.get) if os_candidates else None
    best_confidence = os_candidates[best_os] if best_os else 0.0

    return OsFingerprintResult(
        host=host,
        guessed_os=best_os,
        confidence=best_confidence,
        ttl_observed=ttl or scapy_ttl,
        latency_ms=latency,
        details=details,
        raw_sources=ttl_sources,
    )


def socket_tcp_window(host: str, port: int) -> int | None:
    import socket
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(3)
            sock.sendall(b"\x00")
            try:
                data = sock.recv(1024)
                if len(data) >= 14:
                    _, window_raw = struct.unpack_from("!H", data, 0)
                    return window_raw
            except (OSError, struct.error):
                pass
        return None
    except (OSError, socket.gaierror):
        return None


async def fingerprint_os_async(host: str, banner_window: int | None = None) -> OsFingerprintResult:
    return await fingerprint_os(host, banner_window)
