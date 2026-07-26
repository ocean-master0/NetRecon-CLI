from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import ReconResult, ScanOptions


class NetReconPlugin(ABC):
    name: str = "unnamed"
    description: str = ""
    version: str = "0.1.0"

    @abstractmethod
    def run(self, options: ScanOptions, result: ReconResult) -> ReconResult:
        ...

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "version": self.version}
