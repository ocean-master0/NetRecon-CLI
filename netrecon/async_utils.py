from __future__ import annotations

import asyncio
import logging
import sys
import threading
from collections.abc import Awaitable, Callable, Iterable
from typing import Any, TypeVar

LOGGER = logging.getLogger(__name__)

T = TypeVar("T")


def _install_windows_exception_filter(loop: asyncio.AbstractEventLoop) -> None:
    """Suppress known benign Windows connection-reset callbacks from asyncio internals."""
    if sys.platform != "win32":
        return

    if getattr(loop, "_netrecon_exception_filter_installed", False):
        return

    previous_handler = loop.get_exception_handler()

    def _handler(current_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exception = context.get("exception")
        handle = context.get("handle")
        handle_repr = repr(handle) if handle is not None else ""
        if isinstance(exception, ConnectionResetError) and "_call_connection_lost" in handle_repr:
            LOGGER.debug("Suppressed Windows Proactor connection reset during transport shutdown.")
            return

        if previous_handler is not None:
            previous_handler(current_loop, context)
        else:
            current_loop.default_exception_handler(context)

    loop.set_exception_handler(_handler)
    try:
        setattr(loop, "_netrecon_exception_filter_installed", True)
    except Exception:  # noqa: BLE001 - event loop implementations may restrict dynamic attrs.
        pass


def run_async(coro: Awaitable[T]) -> T:
    """Run a coroutine in a fresh event loop."""

    async def _runner_wrapper() -> T:
        _install_windows_exception_filter(asyncio.get_running_loop())
        return await coro

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Fallback for environments that already own the loop (e.g. notebooks/tests).
        result_holder: dict[str, T] = {}
        error_holder: dict[str, Exception] = {}

        def _runner() -> None:
            try:
                result_holder["result"] = asyncio.run(_runner_wrapper())
            except Exception as exc:  # noqa: BLE001
                error_holder["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()
        if "error" in error_holder:
            raise error_holder["error"]
        return result_holder["result"]
    return asyncio.run(_runner_wrapper())


async def gather_limited(
    jobs: Iterable[Callable[[], Awaitable[T]]],
    concurrency: int,
) -> list[T]:
    """Run coroutine factories with a concurrency limit."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: list[T] = []

    async def _wrapped(job_factory: Callable[[], Awaitable[T]]) -> T:
        async with semaphore:
            return await job_factory()

    tasks = [asyncio.create_task(_wrapped(job)) for job in jobs]
    for task in asyncio.as_completed(tasks):
        results.append(await task)
    return results


async def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 8.0,
) -> dict[str, Any]:
    """Fetch JSON using aiohttp and return dictionary response."""
    try:
        import aiohttp
    except ModuleNotFoundError as exc:  # pragma: no cover - guarded by dependency install
        raise RuntimeError("aiohttp is required for async HTTP operations.") from exc

    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    connector = aiohttp.TCPConnector(ssl=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        async with session.get(url, headers=headers or {}) as response:
            response.raise_for_status()
            payload = await response.json()
            if not isinstance(payload, dict):
                raise ValueError("Response JSON payload must be an object.")
            return payload
