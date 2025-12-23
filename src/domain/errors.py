from __future__ import annotations


class ShodanError(Exception):
    """Base error for Shodan integration failures."""


class ShodanNotFoundError(ShodanError):
    """Raised when the target is not found on Shodan."""


class ShodanRateLimitError(ShodanError):
    """Raised when the Shodan API rate limit is hit."""

    def __init__(self, status_code: int | None = None, message: str | None = None) -> None:
        self.status_code = status_code
        super().__init__(message or "rate limit")


class ShodanTimeoutError(ShodanError):
    """Raised when a Shodan request times out."""


class ShodanNetworkError(ShodanError):
    """Raised when a Shodan request fails due to network issues."""


class ShodanHTTPError(ShodanError):
    """Raised for unexpected HTTP responses from Shodan."""

    def __init__(self, status_code: int | None = None, message: str | None = None) -> None:
        self.status_code = status_code
        super().__init__(message or (f"HTTP {status_code}" if status_code else "HTTP error"))
