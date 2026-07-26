from __future__ import annotations

import asyncio
import re

from .models import BannerResult

HTTP_PORTS = {80, 81, 443, 8000, 8080, 8443, 8888}

SERVICE_PROBES: dict[int, bytes] = {
    25: b"EHLO netrecon.local\r\n",
    110: b"EHLO netrecon.local\r\n",
    143: b"EHLO netrecon.local\r\n",
    587: b"EHLO netrecon.local\r\n",
    21: b"USER anonymous\r\n",
    220: b"EHLO netrecon.local\r\n",
    554: b"OPTIONS rtsp:// RTSP/1.0\r\n\r\n",
}

VERSION_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"OpenSSH[_-](\S+)"), "ssh", 1),
    (re.compile(r"SSH[-\s]*(\d+\.\d+)[-\s]*(\S+)"), "ssh", 2),
    (re.compile(r"(Apache[^/\s]*)/([\d.]+)", re.I), "http", 0),
    (re.compile(r"nginx/([\d.]+)", re.I), "http", 1),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "http", 1),
    (re.compile(r"lighttpd/([\d.]+)", re.I), "http", 1),
    (re.compile(r"([\d.]+)(?:-|\s+)(?:MySQL|mariadb)", re.I), "mysql", 1),
    (re.compile(r"(MySQL|mariadb)\s+([\d.]+)", re.I), "mysql", 2),
    (re.compile(r"PostgreSQL[^\d]*([\d.]+)", re.I), "postgresql", 1),
    (re.compile(r"Redis[^\d]*([\d.]+)", re.I), "redis", 1),
    (re.compile(r"OpenSSL[^\d]*([\d.]+[a-z]*)", re.I), "ssl", 1),
    (re.compile(r"pure-?ftpd", re.I), "ftp", 0),
    (re.compile(r"ProFTPD", re.I), "ftp", 0),
    (re.compile(r"vs?ftpd", re.I), "ftp", 0),
    (re.compile(r"ESMTP[^\r\n]*", re.I), "smtp", 0),
    (re.compile(r"Microsoft ESMTP", re.I), "smtp", 0),
    (re.compile(r"Postfix[^\r\n]*", re.I), "smtp", 0),
    (re.compile(r"OpenSMTPD", re.I), "smtp", 0),
    (re.compile(r"(MongoDB|mongos)", re.I), "mongodb", 0),
    (re.compile(r"RabbitMQ", re.I), "rabbitmq", 0),
]


class BannerGrabber:
    def __init__(self, timeout: float = 1.5) -> None:
        self.timeout = timeout

    async def grab_banner_async(self, host: str, port: int) -> BannerResult:
        if port in HTTP_PORTS:
            return await self._grab_http_banner(host, port)

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=self.timeout)
        except (asyncio.TimeoutError, OSError) as exc:
            return BannerResult(port=port, service=self._guess_service(port), status=f"failed:{exc}")

        try:
            probe = SERVICE_PROBES.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()

            data = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            banner_text = data.decode("utf-8", errors="ignore").strip() if data else None
            service, version = self._infer_service(port, banner_text)
            return BannerResult(
                port=port,
                service=service,
                banner=banner_text,
                status="open" if banner_text else "open-no-banner",
                version=version,
            )
        except (asyncio.TimeoutError, OSError):
            return BannerResult(port=port, service=self._guess_service(port), status="open-no-banner")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _grab_http_banner(self, host: str, port: int) -> BannerResult:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=self.timeout)
        except (asyncio.TimeoutError, OSError) as exc:
            return BannerResult(port=port, service="http", status=f"failed:{exc}")

        try:
            request = (
                f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                "User-Agent: NetRecon/2.0\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", errors="ignore"))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            text = data.decode("utf-8", errors="ignore")

            headers: dict[str, str] = {}
            server = None
            powered_by = None
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", maxsplit=1)[1].strip()
                    headers["server"] = server
                elif line.lower().startswith("x-powered-by:"):
                    powered_by = line.split(":", maxsplit=1)[1].strip()
                    headers["x-powered-by"] = powered_by
                elif line.lower().startswith("x-frame-options:"):
                    headers["x-frame-options"] = line.split(":", maxsplit=1)[1].strip()
                elif line.lower().startswith("strict-transport-security:"):
                    headers["strict-transport-security"] = line.split(":", maxsplit=1)[1].strip()
                elif line.lower().startswith("content-security-policy:"):
                    headers["content-security-policy"] = line.split(":", maxsplit=1)[1].strip()
                elif line.lower().startswith("x-content-type-options:"):
                    headers["x-content-type-options"] = line.split(":", maxsplit=1)[1].strip()

            service = "http"
            if server and "nginx" in server.lower():
                service = "nginx"
            elif server and "apache" in server.lower():
                service = "apache"
            elif server and "iis" in server.lower():
                service = "iis"
            elif server and "cloudflare" in server.lower():
                service = "cloudflare"
            elif server:
                service = server.split("/")[0].lower()

            _, version = self._infer_service(port, server or text)
            banner = server or text.splitlines()[0].strip() if text else None
            return BannerResult(
                port=port, service=service, banner=banner, status="open", version=version
            )
        except (asyncio.TimeoutError, OSError):
            return BannerResult(port=port, service="http", status="open-no-banner")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    @staticmethod
    def _guess_service(port: int) -> str:
        return {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 465: "smtps", 587: "smtp-submission",
            993: "imaps", 995: "pop3s", 1433: "mssql",
            1521: "oracle-db", 2049: "nfs", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc",
            6379: "redis", 8080: "http-alt", 8443: "https-alt",
            9090: "http-alt", 11211: "memcached",
            27017: "mongodb", 28017: "mongodb-http",
            5000: "docker-registry", 8086: "influxdb",
        }.get(port, "unknown")

    @staticmethod
    def _infer_service(port: int, banner: str | None) -> tuple[str, str | None]:
        version = None
        if not banner:
            guessed = BannerGrabber._guess_service(port)
            return guessed, None

        lowered = banner.lower()

        for pattern, name, version_group in VERSION_PATTERNS:
            match = pattern.search(banner)
            if not match:
                continue
            if name != "http" or port not in HTTP_PORTS:
                if version_group > 0:
                    version = match.group(version_group)
                return name, version

        if "ssh" in lowered:
            return "ssh", version
        if "mysql" in lowered or "mariadb" in lowered:
            return "mysql", version
        if "smtp" in lowered or "esmtp" in lowered or "postfix" in lowered:
            return "smtp", version
        if "http" in lowered or "server" in lowered:
            return "http", version
        if re.search(r"postgres|postgresql", lowered):
            return "postgresql", version
        if "ftp" in lowered:
            return "ftp", version
        if "redis" in lowered:
            return "redis", version
        if "mongodb" in lowered or "mongos" in lowered:
            return "mongodb", version

        return BannerGrabber._guess_service(port), version
