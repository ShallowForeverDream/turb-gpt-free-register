"""One saved account-page limit, independent of the registration-page limit."""
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

from config.env_loader import env_int
from core.concurrency_limit import ConcurrencyLimit


_LIMIT = ConcurrencyLimit(max(1, min(16, env_int("ACCOUNT_WORKERS", 3))))
_LOCAL = threading.local()
_REGISTRATION = ContextVar("registration_concurrency_owner", default=False)


def configure_workers(workers):
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 16:
        raise ValueError("账号页并发必须是 1-16 的整数")
    _LIMIT.set_limit(workers)


def queue_settings():
    return _LIMIT.snapshot()


def in_registration_scope():
    return _REGISTRATION.get()


@contextmanager
def registration_scope():
    # Registration already owns its page's admission slot. Inline post-steps
    # must not acquire the independent account-page slot or deadlock at N=1.
    token = _REGISTRATION.set(True)
    try:
        yield
    finally:
        _REGISTRATION.reset(token)


class _TaskSlots:
    def acquire(self, timeout=None):
        depth = getattr(_LOCAL, "depth", 0)
        if depth:
            _LOCAL.depth = depth + 1
            return True
        owned = not _REGISTRATION.get()
        if owned and not _LIMIT.acquire(timeout=timeout):
            return False
        _LOCAL.depth, _LOCAL.owned = 1, owned
        return True

    def release(self):
        depth = getattr(_LOCAL, "depth", 0)
        if not depth:
            raise ValueError("account concurrency released without acquire")
        _LOCAL.depth = depth - 1
        if depth == 1:
            owned, _LOCAL.owned = _LOCAL.owned, False
            if owned:
                _LIMIT.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_args):
        self.release()


SLOTS = _TaskSlots()


def limited(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        with SLOTS:
            return fn(*args, **kwargs)
    return wrapped
