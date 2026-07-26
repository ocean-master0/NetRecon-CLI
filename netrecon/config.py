from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

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

    def __init__(self, path: str | Path = "config.json", secrets_path: str | Path = "secrets.json") -> None:
        self.path = Path(path)
        self.secrets_path = Path(secrets_path)

    def load(self) -> AppConfig:
        config = AppConfig()

        payload = self._load_json_file(self.path)
        if payload is not None:
            config = self._apply_payload(config, payload)

        secrets_payload = self._load_json_file(self.secrets_path)
        if secrets_payload is not None and isinstance(secrets_payload, dict):
            secrets_keys = self._api_keys(secrets_payload.get("api_keys"), {})
            if secrets_keys:
                config.api_keys.update(secrets_keys)

        load_dotenv()
        env_nvd = os.environ.get("NVD_API_KEY", "").strip()
        if env_nvd:
            config.api_keys["nvd"] = env_nvd

        return config

    @staticmethod
    def _load_json_file(path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Failed to read config file %s: %s", path, exc)
            return None
        if not isinstance(payload, dict):
            LOGGER.warning("Config file %s is not a JSON object. Using defaults.", path)
            return None
        return payload

    @staticmethod
    def _apply_payload(config: AppConfig, payload: dict) -> AppConfig:
        config.mode = ConfigLoader._mode(payload.get("mode"), config.mode)
        config.external_lookup = ConfigLoader._bool(payload.get("external_lookup"), config.external_lookup)
        config.interfaces = ConfigLoader._bool(payload.get("interfaces"), config.interfaces)
        config.security_mode = ConfigLoader._bool(payload.get("security_mode"), config.security_mode)
        config.threat_check = ConfigLoader._bool(payload.get("threat_check"), config.threat_check)

        config.default_port_range = ConfigLoader._str(payload.get("default_port_range"), config.default_port_range)
        config.connect_timeout = ConfigLoader._positive_float(payload.get("connect_timeout"), config.connect_timeout)
        config.request_timeout_seconds = ConfigLoader._positive_float(
            payload.get("request_timeout_seconds"),
            config.request_timeout_seconds,
        )
        config.external_workers = ConfigLoader._positive_int(payload.get("external_workers"), config.external_workers)
        config.port_scan_workers = ConfigLoader._positive_int(payload.get("port_scan_workers"), config.port_scan_workers)
        config.subdomain_workers = ConfigLoader._positive_int(payload.get("subdomain_workers"), config.subdomain_workers)
        config.traceroute_max_hops = ConfigLoader._positive_int(payload.get("traceroute_max_hops"), config.traceroute_max_hops)
        config.traceroute_timeout_ms = ConfigLoader._positive_int(
            payload.get("traceroute_timeout_ms"),
            config.traceroute_timeout_ms,
        )
        config.lan_scan_timeout_ms = ConfigLoader._positive_int(payload.get("lan_scan_timeout_ms"), config.lan_scan_timeout_ms)
        config.sniff_default_limit = ConfigLoader._positive_int(payload.get("sniff_default_limit"), config.sniff_default_limit)
        config.sniff_default_timeout = ConfigLoader._positive_int(
            payload.get("sniff_default_timeout"),
            config.sniff_default_timeout,
        )
        config.html_report_default = ConfigLoader._str(payload.get("html_report_default"), config.html_report_default)

        config.common_ports = ConfigLoader._ports_list(payload.get("common_ports"), config.common_ports)
        config.risky_ports = ConfigLoader._ports_list(payload.get("risky_ports"), config.risky_ports)
        config.subdomain_wordlist = ConfigLoader._wordlist(payload.get("subdomain_wordlist"), config.subdomain_wordlist)

        config.log_level = ConfigLoader._str(payload.get("log_level"), config.log_level).upper()
        config.log_file = ConfigLoader._str(payload.get("log_file"), config.log_file)
        config.api_keys = ConfigLoader._api_keys(payload.get("api_keys"), config.api_keys)
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
