"""Authentication provider placeholder."""

from __future__ import annotations


class SnowflakeAuthProvider:
    """Future provider for environment or secret-manager backed credentials."""

    def build_connection_parameters(self) -> dict[str, str]:
        """Return Snowflake connector parameters when implemented."""
        raise NotImplementedError("Snowflake authentication is not implemented yet.")
