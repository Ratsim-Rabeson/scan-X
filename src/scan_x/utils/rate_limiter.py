"""Async token-bucket rate limiter."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Token-bucket rate limiter for async code.

    Tokens refill linearly: one token every ``window_seconds / requests_per_window``
    seconds, up to *requests_per_window* tokens.
    """

    def __init__(self, requests_per_window: int, window_seconds: float) -> None:
        self._max_tokens = requests_per_window
        self._window = window_seconds
        self._refill_interval = window_seconds / requests_per_window

        self._tokens = float(requests_per_window)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        new_tokens = elapsed / self._refill_interval
        self._tokens = min(self._max_tokens, self._tokens + new_tokens)
        self._last_refill = now

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait = self._refill_interval * (1 - self._tokens)
            await asyncio.sleep(wait)

    async def try_acquire(self) -> bool:
        """Try to consume a token without blocking.

        Returns *True* if a token was consumed, *False* otherwise.
        """
        async with self._lock:
            self._refill()
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False

    @property
    def remaining(self) -> int:
        """Tokens currently available (approximate, no lock)."""
        self._refill()
        return int(self._tokens)


class RateLimiterRegistry:
    """Registry of named :class:`RateLimiter` instances."""

    _DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        "nvd": (5, 30),
        "nvd_keyed": (50, 30),
        "osv": (100, 60),
        "github": (30, 60),
        "snyk": (20, 60),
    }

    def __init__(self) -> None:
        self._limiters: dict[str, RateLimiter] = {}
        for name, (rpm, window) in self._DEFAULT_LIMITS.items():
            self._limiters[name] = RateLimiter(rpm, window)

    def register(
        self, source: str, requests_per_window: int, window_seconds: float
    ) -> None:
        """Register (or replace) a rate limiter for *source*."""
        self._limiters[source] = RateLimiter(requests_per_window, window_seconds)

    def get(self, source: str) -> RateLimiter:
        """Return the limiter for *source*.

        Raises :class:`KeyError` if the source has not been registered.
        """
        return self._limiters[source]
