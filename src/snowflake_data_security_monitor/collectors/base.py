"""Collector base skeleton."""

from __future__ import annotations

from typing import Protocol


class Collector(Protocol):
    """Protocol for future metadata collectors."""

    def collect(self) -> list[dict[str, object]]:
        """Collect normalized records from a metadata source."""
        ...
