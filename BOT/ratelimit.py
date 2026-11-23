from __future__ import annotations

import time
from dataclasses import dataclass, field

WINDOW = 60.0
MAX_ENTRIES = 1024
DEFAULT_LIMIT = 40
CLAIM_LIMIT = 3
MESSAGE_LIMIT = 60
CALLBACK_LIMIT = 90
INLINE_LIMIT = 30
EXPENSIVE_LIMIT = 30


@dataclass
class _Bucket:
    window: float = 0.0
    count: int = 0
    seen: float = 0.0


@dataclass
class Limiter:
    limit: int = DEFAULT_LIMIT
    window: float = WINDOW
    max_entries: int = MAX_ENTRIES
    buckets: dict[tuple[str, str], _Bucket] = field(default_factory=dict)

    def allow(self, key: str, scope: str = "any", limit: int = 0, window: float = 0.0) -> bool:
        now = time.monotonic()
        cap = int(limit or self.limit)
        span = float(window or self.window)
        name = (str(scope), str(key))
        bucket = self.buckets.get(name)
        if bucket is None:
            bucket = _Bucket(window=now, count=0, seen=now)
            self.buckets[name] = bucket
        bucket.seen = now
        if now - bucket.window >= span:
            bucket.window = now
            bucket.count = 0
        bucket.count += 1
        self.sweep(now)
        return bucket.count <= cap

    def sweep(self, now: float) -> None:
        stale = [key for key, value in self.buckets.items() if now - value.seen > self.window * 2]
        for key in stale:
            self.buckets.pop(key, None)
        if len(self.buckets) > self.max_entries:
            ordered = sorted(self.buckets.items(), key=lambda pair: pair[1].seen)
            for key, _value in ordered[: len(self.buckets) - self.max_entries]:
                self.buckets.pop(key, None)
