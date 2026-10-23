# -*- coding: utf-8 -*-
import socket
import socketserver
import threading
import time
import unittest

from core.proxy_chain import ProxyChainRelay


class ProxyChainTrafficTests(unittest.TestCase):
    def test_direct_gateway_relay_preserves_auth_and_measures_tunnel_payload(self):
        authenticated = []

        class Gateway(socketserver.BaseRequestHandler):
            def handle(self):
                headers = bytearray()
                while b"\r\n\r\n" not in headers:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    headers.extend(chunk)
                authenticated.append(b"Proxy-Authorization: Basic dXNlcjpwYXNz" in headers)
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                body = bytearray()
                while len(body) < 6:
                    chunk = self.request.recv(6 - len(body))
                    if not chunk:
                        return
                    body.extend(chunk)
                if body == b"upload":
                    self.request.sendall(b"download")

        gateway = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Gateway)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        relay = ProxyChainRelay(f"http://user:pass@127.0.0.1:{gateway.server_address[1]}").start()
        try:
            proxy_port = int(relay.proxy_url.rsplit(":", 1)[1])
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
                client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
                headers = bytearray()
                while b"\r\n\r\n" not in headers:
                    headers.extend(client.recv(4096))
                self.assertIn(b"200 Connection Established", headers)
                client.sendall(b"upload")
                self.assertEqual(client.recv(8), b"download")
                deadline = time.monotonic() + 1
                while relay.traffic_snapshot()["total_bytes"] < 14 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(relay.traffic_snapshot()["total_bytes"], 14)
            self.assertEqual(authenticated, [True])
        finally:
            relay.close()
            gateway.shutdown()
            gateway.server_close()
            thread.join(timeout=2)

    def test_relay_counts_both_directions(self):
        relay = object.__new__(ProxyChainRelay)
        relay._stop = threading.Event()
        relay._traffic_lock = threading.Lock()
        relay._upload_bytes = 0
        relay._download_bytes = 0

        browser, relay_client = socket.socketpair()
        relay_remote, upstream = socket.socketpair()
        thread = threading.Thread(target=relay._relay, args=(relay_client, relay_remote))
        thread.start()
        try:
            browser.sendall(b"upload")
            self.assertEqual(upstream.recv(6), b"upload")
            upstream.sendall(b"download")
            self.assertEqual(browser.recv(8), b"download")
        finally:
            relay._stop.set()
            browser.close()
            upstream.close()
            thread.join(timeout=2)
            relay_client.close()
            relay_remote.close()

        self.assertEqual(relay.traffic_snapshot(), {
            "available": True,
            "upload_bytes": 6,
            "download_bytes": 8,
            "total_bytes": 14,
        })


if __name__ == "__main__":
    unittest.main()
