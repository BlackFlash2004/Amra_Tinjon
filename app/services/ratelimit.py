"""Per-user rolling-window rate limiting for booking creation."""
import threading
import time

from ..errors import AppError

_WINDOW_SECONDS = 60
_MAX_REQUESTS = 20

_buckets: dict[int, list[float]] = {}
_lock = threading.Lock()


def record_and_check(user_id: int) -> None:
    now = time.time()
    with _lock:
        bucket = _buckets.get(user_id, [])
        bucket = [t for t in bucket if t > now - _WINDOW_SECONDS]
        bucket.append(now)
        _buckets[user_id] = bucket
        if len(bucket) > _MAX_REQUESTS:
            raise AppError(429, "RATE_LIMITED", "Too many booking requests")
