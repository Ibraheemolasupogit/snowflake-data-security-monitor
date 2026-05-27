"""User collection placeholder."""

from __future__ import annotations


class UserCollector:
    """Future collector for Snowflake users."""

    def collect(self) -> list[dict[str, object]]:
        """Collect users when Snowflake connectivity is implemented."""
        raise NotImplementedError("User collection is not implemented yet.")
