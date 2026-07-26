from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

from .models import ReconResult, ScanOptions

LOGGER = logging.getLogger(__name__)


def compute_deltas(old: ReconResult, new: ReconResult) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    if old.port_scan and new.port_scan:
        old_ports = set(old.port_scan.open_ports)
        new_ports = set(new.port_scan.open_ports)
        added = new_ports - old_ports
        removed = old_ports - new_ports
        if added:
            changes["ports_opened"] = sorted(added)
        if removed:
            changes["ports_closed"] = sorted(removed)
    if old.lan_scan and new.lan_scan:
        old_ips = {h.ip for h in old.lan_scan.active_hosts}
        new_ips = {h.ip for h in new.lan_scan.active_hosts}
        added_hosts = new_ips - old_ips
        removed_hosts = old_ips - new_ips
        if added_hosts:
            changes["lan_hosts_added"] = sorted(added_hosts)
        if removed_hosts:
            changes["lan_hosts_removed"] = sorted(removed_hosts)
    if old.external_info and new.external_info:
        if old.external_info.ip != new.external_info.ip:
            changes["external_ip_changed"] = {"from": old.external_info.ip, "to": new.external_info.ip}
    return changes


def has_changes(changes: dict[str, Any]) -> bool:
    return bool(changes)


def format_deltas(changes: dict[str, Any]) -> str:
    lines: list[str] = []
    if "ports_opened" in changes:
        lines.append(f"  New open ports: {changes['ports_opened']}")
    if "ports_closed" in changes:
        lines.append(f"  Ports closed: {changes['ports_closed']}")
    if "lan_hosts_added" in changes:
        lines.append(f"  New LAN hosts: {changes['lan_hosts_added']}")
    if "lan_hosts_removed" in changes:
        lines.append(f"  LAN hosts gone: {changes['lan_hosts_removed']}")
    if "external_ip_changed" in changes:
        e = changes["external_ip_changed"]
        lines.append(f"  External IP changed: {e['from']} -> {e['to']}")
    return "\n".join(lines)


class ContinuousMonitor:
    def __init__(
        self,
        orchestrator: Any,
        options: ScanOptions,
        interval_seconds: int = 60,
        on_result: Any = None,
        on_delta: Any = None,
    ):
        self.orchestrator = orchestrator
        self.options = options
        self.interval = interval_seconds
        self.on_result = on_result
        self.on_delta = on_delta
        self._last_result: ReconResult | None = None
        self._cycle = 0

    async def run_async(self) -> None:
        LOGGER.info("Continuous monitoring started (interval=%ss)", self.interval)
        try:
            while True:
                self._cycle += 1
                LOGGER.info("Monitor cycle #%s starting...", self._cycle)
                result = await self.orchestrator.run_async(self.options)
                if self._last_result is not None:
                    deltas = compute_deltas(self._last_result, result)
                    if has_changes(deltas):
                        LOGGER.info("Changes detected in cycle #%s:\n%s", self._cycle, format_deltas(deltas))
                        if self.on_delta:
                            self.on_delta(self._cycle, deltas)
                    else:
                        LOGGER.info("No changes detected in cycle #%s.", self._cycle)
                self._last_result = result
                if self.on_result:
                    self.on_result(self._cycle, result)
                LOGGER.info("Sleeping for %ss...", self.interval)
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            LOGGER.info("Continuous monitoring cancelled after %s cycles.", self._cycle)

    def run(self) -> None:
        try:
            asyncio.run(self.run_async())
        except KeyboardInterrupt:
            LOGGER.info("Monitoring interrupted by user after %s cycles.", self._cycle)
