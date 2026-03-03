from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

DEFAULT_COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
DEFAULT_RISKY_PORTS = [21, 23, 25, 445, 3389, 5900]
DEFAULT_SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "beta",
    "admin",
    "portal",
    "vpn",
    "docs",
    "blog",
    "m",
    "ftp",
    "cpanel",
    "webmail",
]


@dataclass
class AppConfig:
    """Configuration values loaded from `config.json` with safe defaults."""

    mode: str = "active"
    external_lookup: bool = True
    interfaces: bool = False
    default_port_range: str = "1-1024"
    security_mode: bool = False
    threat_check: bool = False
    connect_timeout: float = 0.5
    request_timeout_seconds: float = 8.0
    external_workers: int = 3
    port_scan_workers: int = 300
    subdomain_workers: int = 200
    common_ports: list[int] = field(default_factory=lambda: list(DEFAULT_COMMON_PORTS))
    risky_ports: list[int] = field(default_factory=lambda: list(DEFAULT_RISKY_PORTS))
    subdomain_wordlist: list[str] = field(default_factory=lambda: list(DEFAULT_SUBDOMAIN_WORDLIST))
    traceroute_max_hops: int = 30
    traceroute_timeout_ms: int = 2000
    lan_scan_timeout_ms: int = 800
    sniff_default_limit: int = 200
    sniff_default_timeout: int = 15
    html_report_default: str = "report.html"
    log_level: str = "INFO"
    log_file: str = "logs/netrecon.log"
    api_keys: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ConfigLoader:
    """Load and validate runtime configuration from a JSON file."""

    def __init__(self, path: str | Path = "config.json") -> None:
        self.path = Path(path)

    def load(self) -> AppConfig:
        config = AppConfig()
        if not self.path.exists():
            LOGGER.info("Config file not found at %s. Using defaults.", self.path)
            return config

        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Failed to read config file %s: %s", self.path, exc)
            return config

        if not isinstance(payload, dict):
            LOGGER.warning("Config file %s is not a JSON object. Using defaults.", self.path)
            return config

        config.mode = self._mode(payload.get("mode"), config.mode)
        config.external_lookup = self._bool(payload.get("external_lookup"), config.external_lookup)
        config.interfaces = self._bool(payload.get("interfaces"), config.interfaces)
        config.security_mode = self._bool(payload.get("security_mode"), config.security_mode)
        config.threat_check = self._bool(payload.get("threat_check"), config.threat_check)

        config.default_port_range = self._str(payload.get("default_port_range"), config.default_port_range)
        config.connect_timeout = self._positive_float(payload.get("connect_timeout"), config.connect_timeout)
        config.request_timeout_seconds = self._positive_float(
            payload.get("request_timeout_seconds"),
            config.request_timeout_seconds,
        )
        config.external_workers = self._positive_int(payload.get("external_workers"), config.external_workers)
        config.port_scan_workers = self._positive_int(payload.get("port_scan_workers"), config.port_scan_workers)
        config.subdomain_workers = self._positive_int(payload.get("subdomain_workers"), config.subdomain_workers)
        config.traceroute_max_hops = self._positive_int(payload.get("traceroute_max_hops"), config.traceroute_max_hops)
        config.traceroute_timeout_ms = self._positive_int(
            payload.get("traceroute_timeout_ms"),
            config.traceroute_timeout_ms,
        )
        config.lan_scan_timeout_ms = self._positive_int(payload.get("lan_scan_timeout_ms"), config.lan_scan_timeout_ms)
        config.sniff_default_limit = self._positive_int(payload.get("sniff_default_limit"), config.sniff_default_limit)
        config.sniff_default_timeout = self._positive_int(
            payload.get("sniff_default_timeout"),
            config.sniff_default_timeout,
        )
        config.html_report_default = self._str(payload.get("html_report_default"), config.html_report_default)

        config.common_ports = self._ports_list(payload.get("common_ports"), config.common_ports)
        config.risky_ports = self._ports_list(payload.get("risky_ports"), config.risky_ports)
        config.subdomain_wordlist = self._wordlist(payload.get("subdomain_wordlist"), config.subdomain_wordlist)

        config.log_level = self._str(payload.get("log_level"), config.log_level).upper()
        config.log_file = self._str(payload.get("log_file"), config.log_file)
        config.api_keys = self._api_keys(payload.get("api_keys"), config.api_keys)
        return config

    @staticmethod
    def _mode(value: Any, default: str) -> str:
        if isinstance(value, str) and value.lower() in {"active", "passive"}:
            return value.lower()
        return default

    @staticmethod
    def _bool(value: Any, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        return default

    @staticmethod
    def _str(value: Any, default: str) -> str:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return default

    @staticmethod
    def _positive_float(value: Any, default: float) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        return number if number > 0 else default

    @staticmethod
    def _positive_int(value: Any, default: int) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            return default
        return number if number > 0 else default

    @staticmethod
    def _ports_list(value: Any, default: list[int]) -> list[int]:
        if not isinstance(value, list):
            return list(default)

        ports: list[int] = []
        for item in value:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                ports.append(port)

        return sorted(set(ports)) if ports else list(default)

    @staticmethod
    def _wordlist(value: Any, default: list[str]) -> list[str]:
        if not isinstance(value, list):
            return list(default)
        words = [item.strip().lower() for item in value if isinstance(item, str) and item.strip()]
        return sorted(set(words)) if words else list(default)

    @staticmethod
    def _api_keys(value: Any, default: dict[str, str]) -> dict[str, str]:
        if not isinstance(value, dict):
            return dict(default)
        keys: dict[str, str] = {}
        for key, item in value.items():
            if isinstance(key, str) and isinstance(item, str) and item.strip():
                keys[key.strip().lower()] = item.strip()
        return keys
