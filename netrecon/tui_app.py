from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from .models import ReconResult, ScanOptions

LOGGER = logging.getLogger(__name__)

_AVAILABLE = True
try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.reactive import reactive
    from textual.widgets import Button, Footer, Header, Label, ListItem, ListView, RichLog, Static
    from rich.text import Text
except ModuleNotFoundError:
    _AVAILABLE = False


class NetReconTuiApp:
    def __init__(self, orchestrator: Any, options: ScanOptions) -> None:
        self.orchestrator = orchestrator
        self.options = options

    def run(self) -> None:
        if not _AVAILABLE:
            print("TUI mode requires 'textual'. Install with: pip install textual")
            return
        app = _TuiApp(self.orchestrator, self.options)
        app.run()


if _AVAILABLE:

    class _TuiApp(App):
        TITLE = "NetRecon CLI"
        CSS = """
        Screen { layout: grid; grid-size: 2 3; grid-gutter: 1; }
        #summary { column-span: 2; height: 3; background: $primary; }
        #scanlog { row-span: 2; }
        #actions { height: 5; }
        #results { row-span: 2; }
        Button { width: 100%; }
        """

        def __init__(self, orchestrator: Any, options: ScanOptions) -> None:
            super().__init__()
            self._orchestrator = orchestrator
            self._options = options
            self._results: ReconResult | None = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Static("Ready. Press 'Scan' to start.", id="summary")
            yield RichLog(id="scanlog", markup=True, highlight=True)
            with Vertical(id="actions"):
                yield Button("Run Scan", id="scan", variant="primary")
                yield Button("Quit", id="quit", variant="error")
            yield RichLog(id="results", markup=True)
            yield Footer()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "quit":
                self.exit()
            elif event.button.id == "scan":
                self.run_scan()

        def run_scan(self) -> None:
            log = self.query_one("#scanlog", RichLog)
            summary = self.query_one("#summary", Static)
            results = self.query_one("#results", RichLog)
            log.clear()
            results.clear()
            summary.update("Scanning...")
            self.call_from_thread(self._do_scan, log, summary, results)

        def _do_scan(
            self, log: RichLog, summary: Static, results: RichLog
        ) -> None:
            try:
                result = self._orchestrator.run(self._options)
                self._results = result
                summary.update(f"Scan complete — {len(result.warnings)} warnings, {len(result.errors)} errors")
                log.write("[green]Scan completed successfully[/green]")

                from .renderer import to_json
                import json
                data = json.loads(to_json(result, pretty=False))

                def _write(path: str, value: Any, depth: int = 0) -> None:
                    indent = "  " * depth
                    if isinstance(value, dict):
                        results.write(f"{indent}[bold]{path}[/bold]")
                        for k, v in value.items():
                            _write(f"{k}", v, depth + 1)
                    elif isinstance(value, list):
                        if len(value) > 10:
                            results.write(f"{indent}[bold]{path}[/bold]: [{len(value)} items]")
                        else:
                            results.write(f"{indent}[bold]{path}[/bold]")
                            for item in value:
                                _write("-", item, depth + 1)
                    elif value is not None:
                        results.write(f"{indent}[bold]{path}:[/bold] {value}")

                for section, value in data.items():
                    if value is not None and value != [] and value != {}:
                        _write(section.replace("_", " ").title(), value)

            except Exception as exc:
                summary.update(f"[red]Scan failed: {exc}[/red]")
                log.write(f"[red]Error: {exc}[/red]")
