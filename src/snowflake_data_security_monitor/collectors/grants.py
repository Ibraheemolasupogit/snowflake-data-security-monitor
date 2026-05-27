"""Grant collection placeholder."""

from __future__ import annotations


class GrantCollector:
    """Future collector for Snowflake grants."""

    def collect(self) -> list[dict[str, object]]:
        """Collect grants when Snowflake connectivity is implemented."""
        raise NotImplementedError("Grant collection is not implemented yet.")
