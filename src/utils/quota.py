"""Thread-safe, per-run request budgeting for external providers."""

from __future__ import annotations

from collections import Counter
from threading import Lock


class RequestBudget:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.used = Counter()
        self._lock = Lock()

    @property
    def total_used(self) -> int:
        return sum(self.used.values())

    def acquire(self, provider: str) -> bool:
        with self._lock:
            if self.total_used >= self.maximum:
                return False
            self.used[provider] += 1
            return True
