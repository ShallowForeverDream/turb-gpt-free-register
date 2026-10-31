"""Absolute deadlines for IMAP DNS, connect, TLS and blocking reads."""
from __future__ import annotations

import imaplib
import queue
import socket
import ssl
import threading
import time

_DNS_SLOTS = threading.BoundedSemaphore(8)


class ImapDeadlineExpired(TimeoutError):
    pass


class ImapDeadline:
    def __init__(self, seconds: float):
        self.expires_at = time.monotonic() + max(0.0, seconds)
        self._lock = threading.Lock()
        self._socket = None
        self._timer = threading.Timer(max(0.0, seconds), self.close_socket)
        self._timer.daemon = True
        self._timer.name = "imap-deadline"

    def __enter__(self):
        self._timer.start()
        return self

    def __exit__(self, *_args):
        self._timer.cancel()
        self.close_socket()

    def remaining(self):
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise ImapDeadlineExpired("IMAP 查询已到截止时间")
        return remaining

    def bind_socket(self, sock):
        with self._lock:
            expired = time.monotonic() >= self.expires_at
            if not expired:
                self._socket = sock
        if expired:
            sock.close()
            raise ImapDeadlineExpired("IMAP 查询已到截止时间")
        sock.settimeout(self.remaining())
        return sock

    def close_socket(self):
        with self._lock:
            sock, self._socket = self._socket, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                sock.close()

    def release_socket(self, sock):
        """Return a healthy socket to its shared owner, not to this timer."""
        with self._lock:
            if self._socket is not sock:
                return False
            self._socket = None
            return True

    def cancel(self):
        with self._lock:
            self.expires_at = min(self.expires_at, time.monotonic())
        self.close_socket()

    def connect(self, host, port):
        # socket's connect timeout does not cover getaddrinfo. A timed-out DNS
        # worker can finish resolving, but is never allowed to open a socket.
        result = queue.Queue(maxsize=1)
        if not _DNS_SLOTS.acquire(timeout=self.remaining()):
            raise ImapDeadlineExpired("IMAP DNS 解析队列等待超时")

        def resolve():
            try:
                result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
            except Exception as exc:
                result.put(exc)
            finally:
                _DNS_SLOTS.release()

        try:
            threading.Thread(target=resolve, daemon=True, name="imap-dns").start()
        except Exception:
            _DNS_SLOTS.release()
            raise
        try:
            addresses = result.get(timeout=self.remaining())
        except queue.Empty:
            raise ImapDeadlineExpired("IMAP DNS 查询超时") from None
        if isinstance(addresses, Exception):
            raise addresses
        last_error = OSError("IMAP DNS 未返回地址")
        for family, kind, protocol, _name, address in addresses:
            self.remaining()
            sock = self.bind_socket(socket.socket(family, kind, protocol))
            try:
                sock.connect(address)
                self.remaining()
                return sock
            except OSError as exc:
                last_error = exc
                self.close_socket()
        raise last_error


class _DeadlineIO:
    def __init__(self, host, port, *, deadline: ImapDeadline, **kwargs):
        self._deadline = deadline
        self._read_buffer = bytearray()
        super().__init__(host, port, timeout=deadline.remaining(), **kwargs)

    def _create_socket(self, timeout):
        sock = self._deadline.connect(self.host, self.port)
        context = getattr(self, "ssl_context", None)
        if context is not None:
            sock = context.wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
            self._deadline.bind_socket(sock)
            while True:
                sock.settimeout(min(0.2, self._deadline.remaining()))
                try:
                    sock.do_handshake()
                    break
                except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    self._deadline.remaining()
            self._deadline.remaining()
        return sock

    def read(self, size):
        self._deadline.remaining()
        # Header fetches and partial TEXT reads must not turn into an unlimited
        # literal transfer if the server ignores the requested partial range.
        if size > 64 * 1024:
            self._deadline.close_socket()
            raise imaplib.IMAP4.abort("IMAP 响应 literal 超过读取上限")
        data = bytearray()
        while len(data) < size:
            if self._read_buffer:
                take = min(size - len(data), len(self._read_buffer))
                data.extend(self._read_buffer[:take])
                del self._read_buffer[:take]
            else:
                chunk = self._recv()
                if not chunk:
                    break
                self._read_buffer.extend(chunk)
        self._deadline.remaining()
        return bytes(data)

    def _recv(self):
        # Windows buffered file reads are not reliably interrupted by another
        # thread closing the socket. Use bounded recv calls without poisoning a
        # makefile reader on timeout; keep partial protocol data in our buffer.
        while True:
            self.sock.settimeout(min(0.2, self._deadline.remaining()))
            try:
                return self.sock.recv(65536)
            except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                self._deadline.remaining()

    def readline(self):
        self._deadline.remaining()
        while True:
            end = self._read_buffer.find(b"\n")
            if end >= 0:
                data = bytes(self._read_buffer[:end + 1])
                del self._read_buffer[:end + 1]
                if len(data) > imaplib._MAXLINE:
                    raise self.error("IMAP response line exceeds limit")
                self._deadline.remaining()
                return data
            if len(self._read_buffer) > imaplib._MAXLINE:
                raise self.error("IMAP response line exceeds limit")
            chunk = self._recv()
            if not chunk:
                data = bytes(self._read_buffer)
                self._read_buffer.clear()
                self._deadline.remaining()
                return data
            self._read_buffer.extend(chunk)

    def send(self, data):
        self.sock.settimeout(self._deadline.remaining())
        return super().send(data)


class DeadlineIMAP4(_DeadlineIO, imaplib.IMAP4):
    pass


class DeadlineIMAP4SSL(_DeadlineIO, imaplib.IMAP4_SSL):
    pass
