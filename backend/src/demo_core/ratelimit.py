"""Smooth (non-bursty) pacing, plus a virtual clock for dry runs and tests."""
from __future__ import annotations

import threading
import time
from typing import Callable


class Pacer:
    """Hands out evenly spaced time slots. ``rate <= 0`` means unlimited."""

    def __init__(
        self,
        rate: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.rate = rate
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next = clock()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        with self._lock:
            now = self._clock()
            slot = max(self._next, now)
            self._next = slot + 1.0 / self.rate
            wait = slot - now
        if wait > 0:
            self._sleep(wait)


class VirtualClock:
    """Deterministic clock: ``sleep`` advances time instantly. Used by --dry-run and tests."""

    def __init__(self, start: float = 0.0):
        self._t = start
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._t

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self._t += max(0.0, seconds)
