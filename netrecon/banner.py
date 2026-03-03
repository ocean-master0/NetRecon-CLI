from __future__ import annotations

import asyncio
import re

from .models import BannerResult

HTTP_PORTS = {80, 81, 443, 8000, 8080, 8443}


class BannerGrabber:
    """Mini service/banner detection similar to lightweight nmap version scan."""

    def __init__(self, timeout: float = 1.5) -> None:
        self.timeout = timeout

    async def grab_banner_async(self, host: str, port: int) -> BannerResult:
        """Attempt to identify service banner for an open port."""
        if port in HTTP_PORTS:
            return await self._grab_http_banner(host, port)

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=self.timeout)
        except (asyncio.TimeoutError, OSError) as exc:
            return BannerResult(port=port, service=self._guess_service(port), status=f"failed:{exc}")

        try:
            # Prompt banner for services that expect client hello.
            if port in {25, 110, 143, 587}:
                writer.write(b"EHLO netrecon.local\r\n")
                await writer.drain()
            elif port in {21}:
                writer.write(b"USER anonymous\r\n")
                await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            banner_text = data.decode("utf-8", errors="ignore").strip() if data else None
            service = self._infer_service(port, banner_text)
            return BannerResult(
                port=port,
                service=service,
                banner=banner_text,
                status="open" if banner_text else "open-no-banner",
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
                "User-Agent: NetRecon\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", errors="ignore"))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            text = data.decode("utf-8", errors="ignore")

            server = None
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", maxsplit=1)[1].strip()
                    break
            banner = server or text.splitlines()[0].strip() if text else None
            return BannerResult(port=port, service="http", banner=banner, status="open")
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
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http-alt",
        }.get(port, "unknown")

    def _infer_service(self, port: int, banner: str | None) -> str:
        if banner:
            lowered = banner.lower()
            if "ssh" in lowered:
                return "ssh"
            if "mysql" in lowered:
                return "mysql"
            if "smtp" in lowered:
                return "smtp"
            if "http" in lowered:
                return "http"
            if re.search(r"postgres|postgresql", lowered):
                return "postgresql"
        return self._guess_service(port)
