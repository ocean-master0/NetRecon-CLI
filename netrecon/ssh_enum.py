from __future__ import annotations

import logging
import re
import socket
import struct
from typing import Any

from .models import SshEnumResult

LOGGER = logging.getLogger(__name__)


class SshEnumerator:
    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def enumerate(self, host: str, port: int = 22) -> SshEnumResult:
        result = SshEnumResult(target=host, port=port)
        try:
            addr = socket.getaddrinfo(host, port)[0][4][0]
            with socket.create_connection((addr, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                banner = sock.recv(4096)
                if banner:
                    banner_str = banner.split(b"\r\n")[0].split(b"\n")[0].decode("utf-8", errors="replace")
                    result.banner = banner_str
                    ver_match = re.search(r"SSH-\d\.\d-([^\s]+)", banner_str)
                    if ver_match:
                        result.software_version = ver_match.group(1)
                    sock.sendall(banner[:16])
                    try:
                        kex_data = sock.recv(65535)
                        result = self._parse_kex_init(result, kex_data)
                    except socket.timeout:
                        result.warnings.append("KEX exchange timed out")
        except socket.timeout:
            result.warnings.append(f"Connection timed out to {host}:{port}")
        except ConnectionRefusedError:
            result.warnings.append(f"Connection refused on {host}:{port}")
        except OSError as exc:
            result.warnings.append(f"SSH connection failed: {exc}")
        return result

    @staticmethod
    def _parse_kex_init(result: SshEnumResult, data: bytes) -> SshEnumResult:
        try:
            idx = data.find(b"\x14")
            if idx < 0:
                return result
            payload = data[idx + 1:]
            if len(payload) < 16:
                return result
            cookie = payload[:16]
            offset = 16
            def read_name_list() -> tuple[list[str], int]:
                nonlocal offset
                if offset + 4 > len(payload):
                    return [], offset
                length = struct.unpack(">I", payload[offset:offset + 4])[0]
                offset += 4
                if offset + length > len(payload):
                    return [], offset
                raw = payload[offset:offset + length]
                offset += length
                if not raw:
                    return [], offset
                return [s.decode("utf-8", errors="replace") for s in raw.split(b",") if s], offset
            result.kex_algorithms, offset = read_name_list()
            result.host_key_algorithms, offset = read_name_list()
            result.encryption_algorithms, offset = read_name_list()
            _tmp, offset = read_name_list()
            result.mac_algorithms, offset = read_name_list()
            _tmp, offset = read_name_list()
            result.compression_algorithms, offset = read_name_list()
        except Exception:
            pass
        return result
