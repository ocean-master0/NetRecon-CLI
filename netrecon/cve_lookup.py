from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from .models import CveLookupResult, CveRecord

LOGGER = logging.getLogger(__name__)

CVE_CACHE_TTL_SECONDS = 86400


class CveCache:
    def __init__(self, db_path: str | Path = "cve_cache.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            has_cache_key = any(
                col[1] == "cache_key"
                for col in conn.execute("PRAGMA table_info(cve_cache)")
            )
        except sqlite3.OperationalError:
            has_cache_key = False
        if not has_cache_key:
            conn.execute("DROP TABLE IF EXISTS cve_cache")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT,
                cache_key TEXT NOT NULL,
                base_score REAL,
                severity TEXT,
                description TEXT,
                cvss_vector TEXT,
                raw_json TEXT,
                fetched_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (cve_id, cache_key)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_key ON cve_cache(cache_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fetched ON cve_cache(fetched_at)")
        conn.commit()
        conn.close()

    def get(self, cache_key: str) -> list[dict] | None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute(
                "SELECT raw_json, fetched_at FROM cve_cache WHERE cache_key = ? ORDER BY fetched_at DESC",
                (cache_key,),
            ).fetchall()
        finally:
            conn.close()
        if not rows:
            return None
        _raw, fetched_at = rows[0]
        try:
            fetched = datetime.fromisoformat(fetched_at)
            if (datetime.now(timezone.utc) - fetched).total_seconds() > CVE_CACHE_TTL_SECONDS:
                return None
        except (ValueError, TypeError):
            pass
        results = []
        for row in rows:
            rj = row[0]
            if rj:
                results.append(json.loads(rj))
        return results

    def set(self, cache_key: str, cves: list[dict]) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute("DELETE FROM cve_cache WHERE cache_key = ?", (cache_key,))
            for cve in cves:
                conn.execute(
                    """INSERT OR REPLACE INTO cve_cache
                       (cve_id, cache_key, base_score, severity, description, cvss_vector, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        cve.get("id", ""),
                        cache_key,
                        cve.get("base_score"),
                        cve.get("severity"),
                        cve.get("description"),
                        cve.get("cvss_vector"),
                        json.dumps(cve),
                    ),
                )
            conn.commit()
        finally:
            conn.close()


def _version_in_description(version: str, description: str) -> bool:
    escaped = re.escape(version)
    pattern = re.compile(
        r"(?<![a-zA-Z0-9.])" + escaped + r"(?![a-zA-Z0-9]|\.\d)"
    )
    return bool(pattern.search(description))


def _parse_nvd_response(data: dict) -> list[dict]:
    cves: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        metrics = cve_data.get("metrics", {})
        base_score: float | None = None
        severity: str | None = None
        vector: str | None = None
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                base_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                vector = cvss_data.get("vectorString")
                break
        cves.append({
            "id": cve_id,
            "base_score": base_score,
            "severity": severity,
            "description": description,
            "cvss_vector": vector,
        })
    cves.sort(key=lambda c: c.get("base_score") or 0, reverse=True)
    return cves


class NvdApi:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None, delay: float = 6.0):
        self.api_key = api_key
        self.delay = delay
        self._last_request = 0.0

    async def search_by_keyword(self, keyword: str, max_results: int = 200) -> dict | None:
        all_vulns: list[dict] = []
        start_index = 0
        page_size = min(max_results, 200)
        for _ in range(10):
            self._rate_limit()
            encoded = urllib.parse.quote(keyword, safe="")
            url = f"{self.BASE_URL}?keywordSearch={encoded}&resultsPerPage={page_size}&startIndex={start_index}&noRejected"
            data = await self._fetch(url)
            if data is None:
                break
            vulns = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)
            total = data.get("totalResults", 0)
            start_index += page_size
            if start_index >= total or len(all_vulns) >= max_results:
                break
        return {"vulnerabilities": all_vulns, "totalResults": len(all_vulns)}

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.time()

    async def _fetch(self, url: str) -> dict | None:
        try:
            import aiohttp
        except ImportError:
            LOGGER.warning("aiohttp is required for NVD API lookups.")
            return None
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        max_retries = 3
        for attempt in range(max_retries):
            try:
                async with aiohttp.ClientSession(headers=headers) as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        if resp.status == 404 and attempt < max_retries - 1:
                            wait = 6 * (attempt + 1)
                            LOGGER.info("NVD API 404 (rate limit?), retrying in %ds...", wait)
                            await asyncio.sleep(wait)
                            continue
                        LOGGER.warning("NVD API returned status %s", resp.status)
                        return None
            except asyncio.TimeoutError:
                if attempt < max_retries - 1:
                    await asyncio.sleep(6)
                    continue
                LOGGER.warning("NVD API request timed out after %d retries", max_retries)
                return None
            except Exception as exc:
                LOGGER.warning("NVD API request failed: %s", exc)
                return None
        return None


class CveLookup:
    def __init__(self, api_key: str | None = None, db_path: str | Path = "cve_cache.db"):
        self.api = NvdApi(api_key=api_key) if api_key else NvdApi()
        self.cache = CveCache(db_path)

    @staticmethod
    def _dict_to_record(c: dict) -> CveRecord:
        return CveRecord(
            cve_id=c.get("id", ""),
            base_score=c.get("base_score"),
            severity=c.get("severity"),
            description=c.get("description"),
            cvss_vector=c.get("cvss_vector"),
        )

    async def lookup(self, product: str, version: str | None = None) -> CveLookupResult:
        cache_key = f"{product.lower().strip()}|{version or '*'}"
        result = CveLookupResult(software=product, version=version)

        cached = self.cache.get(cache_key)
        if cached is not None:
            result.cves = [self._dict_to_record(c) for c in cached]
            result.total_found = len(result.cves)
            return result

        first_word = product.split()[0]
        keyword = f"{first_word} {version}" if version else product
        raw = await self.api.search_by_keyword(keyword)
        if raw is None:
            result.warnings.append("NVD API unavailable; no CVE data.")
            return result

        parsed = _parse_nvd_response(raw)

        if version:
            filtered = [
                c for c in parsed
                if _version_in_description(version, c.get("description", ""))
            ]
        else:
            filtered = parsed

        if not filtered:
            result.warnings.append(f"No CVEs found for {product} {version or '*'}")
            return result

        self.cache.set(cache_key, filtered)
        result.cves = [self._dict_to_record(c) for c in filtered]
        result.total_found = len(result.cves)
        return result

    def lookup_without_api(self, product: str, version: str | None = None) -> CveLookupResult:
        result = CveLookupResult(software=product, version=version)
        cache_key = f"{product.lower().strip()}|{version or '*'}"
        cached = self.cache.get(cache_key)
        if cached:
            result.cves = [self._dict_to_record(c) for c in cached]
            result.total_found = len(result.cves)
        else:
            result.warnings.append("No cached data; NVD API key required for live lookup.")
        return result
