from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .models import GeoIpResult

LOGGER = logging.getLogger(__name__)


class GeoIpLookup:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else None
        self._reader: Any = None
        self._asn_reader: Any = None

    def _try_load(self) -> None:
        if self._reader is not None:
            return
        try:
            import geoip2.database
        except ModuleNotFoundError:
            return
        if self.db_path and self.db_path.is_file():
            try:
                self._reader = geoip2.database.Reader(str(self.db_path))
                city_dir = self.db_path.parent / "GeoLite2-City.mmdb"
                asn_dir = self.db_path.parent / "GeoLite2-ASN.mmdb"
                if city_dir.is_file():
                    self._reader.close()
                    self._reader = geoip2.database.Reader(str(city_dir))
                asn_path = self.db_path.parent / "GeoLite2-ASN.mmdb"
                if asn_path.is_file():
                    self._asn_reader = geoip2.database.Reader(str(asn_path))
            except Exception as exc:
                LOGGER.warning("Failed to load GeoIP database '%s': %s", self.db_path, exc)

    def lookup(self, ip: str) -> GeoIpResult:
        self._try_load()
        if self._reader is None:
            return GeoIpResult(ip=ip, source="unavailable")
        try:
            city = self._reader.city(ip)
            asn_org = None
            asn_num = None
            if self._asn_reader:
                try:
                    asn_resp = self._asn_reader.asn(ip)
                    asn_num = str(asn_resp.autonomous_system_number)
                    asn_org = asn_resp.autonomous_system_organization
                except Exception as exc:
                    LOGGER.debug("GeoIP ASN lookup failed for %s: %s", ip, exc)
            return GeoIpResult(
                ip=ip,
                country=city.country.name,
                city=city.city.name,
                latitude=city.location.latitude,
                longitude=city.location.longitude,
                asn=f"AS{asn_num}" if asn_num else None,
                organization=asn_org,
                source="geoip2",
            )
        except Exception as exc:
            LOGGER.debug("GeoIP lookup failed for %s: %s", ip, exc)
            return GeoIpResult(ip=ip, source="error")
