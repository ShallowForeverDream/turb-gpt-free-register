"""A live concurrency limit; resizing never interrupts admitted work."""
import threading
import time


class ConcurrencyLimit:
    def __init__(self, limit):
        self._condition = threading.Condition()
        self._limit = int(limit)
        self._active = 0

    def set_limit(self, limit):
        if not 1 <= int(limit) <= 16:
            raise ValueError("workers must be between 1 and 16")
        with self._condition:
            self._limit = int(limit)
            self._condition.notify_all()

    def acquire(self, timeout=None):
        end = None if timeout is None else time.monotonic() + max(0, timeout)
        with self._condition:
            while self._active >= self._limit:
                left = None if end is None else end - time.monotonic()
                if left is not None and left <= 0:
                    return False
                self._condition.wait(left)
            self._active += 1
            return True

    def release(self):
        with self._condition:
            if not self._active:
                raise ValueError("concurrency limit released without acquire")
            self._active -= 1
            self._condition.notify_all()

    def snapshot(self):
        with self._condition:
            return {"workers": self._limit, "running": self._active}

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_args):
        self.release()
