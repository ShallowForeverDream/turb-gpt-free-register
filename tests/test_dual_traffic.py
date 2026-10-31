import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core import protocol_traffic as traffic
from core.mail_traffic import record_mail_http, track_imap_connection


class DualTrafficTests(unittest.TestCase):
    def test_local_relay_alias_preserves_dynamic_pool_classification(self):
        meter = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        token = traffic._ACTIVE.set(meter)
        try:
            meter.register_proxy_route("http://127.0.0.1:34567", dynamic_ip=True)
            self.assertTrue(traffic.is_proxy_pool_target("http://127.0.0.1:34567"))
            self.assertFalse(traffic.is_proxy_pool_target("http://127.0.0.1:21483"))
            relay = Mock()
            relay.traffic_snapshot.return_value = {"upload_bytes": 100, "download_bytes": 900}
            meter.attach_proxy(relay, dynamic_ip=traffic.is_proxy_pool_target("http://127.0.0.1:34567"))
            self.assertEqual(meter.snapshot()["dynamic_ip_bytes"], 1000)
            self.assertEqual(meter.snapshot()["proxy_transfer_bytes"], 1000)
        finally:
            traffic._ACTIVE.reset(token)

    def test_total_includes_direct_and_mail_without_double_counting_tunnels(self):
        meter = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        dynamic, fixed = Mock(), Mock()
        dynamic.traffic_snapshot.return_value = {"upload_bytes": 200, "download_bytes": 800}
        fixed.traffic_snapshot.return_value = {"upload_bytes": 50, "download_bytes": 50}
        meter.attach_proxy(dynamic, dynamic_ip=True)
        meter.attach_proxy(fixed, dynamic_ip=False)
        response = SimpleNamespace(upload_size=10, request_size=20, download_size=30, header_size=40,
                                   content=b"x", redirect_count=0)
        meter.record("https://example.test/", response, tunneled=True)
        meter.record("https://direct.test/", response, tunneled=False)
        meter.record_mail_bytes(25, 75, request=True)
        result = meter.snapshot()
        self.assertEqual(result["dynamic_ip_bytes"], 1000)
        self.assertEqual(result["total_bytes"], 1300)
        self.assertEqual(result["mail_transfer_bytes"], 100)
        self.assertFalse(result["total_measurement_complete"])

    def test_unknown_dynamic_role_is_not_reported_as_zero(self):
        meter = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        relay = Mock()
        relay.traffic_snapshot.return_value = {"upload_bytes": 10, "download_bytes": 20}
        meter.attach_proxy(relay)
        self.assertIsNone(meter.snapshot()["dynamic_ip_bytes"])

    def test_imap_counts_commands_and_mail_data_not_credentials(self):
        class Mail:
            def send(self, data): pass
            def read(self, size): return b"body"
            def readline(self): return b"OK\r\n"
        meter = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        token = traffic._ACTIVE.set(meter)
        try:
            mail = track_imap_connection(Mail())
            mail.send(b"private-password")
            mail.read(4)
            mail.readline()
            result = meter.snapshot()
            self.assertEqual(result["mail_transfer_bytes"], 24)
            self.assertNotIn("private-password", str(result))
            self.assertEqual(result["dynamic_ip_bytes"], 0)
        finally:
            traffic._ACTIVE.reset(token)

    def test_http_mail_uses_transfer_sizes_and_cannot_break_the_response(self):
        meter = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        token = traffic._ACTIVE.set(meter)
        try:
            response = SimpleNamespace(upload_size=1, request_size=2, download_size=3, header_size=4)
            self.assertIs(record_mail_http(response), response)
            self.assertEqual(meter.snapshot()["mail_transfer_bytes"], 10)
            broken = Mock()
            self.assertIs(record_mail_http(broken), broken)
        finally:
            traffic._ACTIVE.reset(token)

    def test_reused_imap_connection_charges_current_task_not_closed_creator(self):
        class Mail:
            def send(self, data): pass
            def read(self, size): return b"body"
            def readline(self): return b"OK\r\n"
        first = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        token = traffic._ACTIVE.set(first)
        try:
            mail = track_imap_connection(Mail())
            mail.read(4)
        finally:
            traffic._ACTIVE.reset(token)
        first.closed = True
        second = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        token = traffic._ACTIVE.set(second)
        try:
            self.assertIs(track_imap_connection(mail), mail)
            mail.send(b"xx")
            mail.read(4)
        finally:
            traffic._ACTIVE.reset(token)
        self.assertEqual(first.snapshot()["mail_transfer_bytes"], 4)
        self.assertEqual(second.snapshot()["mail_transfer_bytes"], 6)
        self.assertEqual(second.snapshot()["mail_request_count"], 0)
        self.assertIn("邮箱 HTTP/IMAP", second.snapshot()["note"])

    def test_connection_created_without_meter_can_count_a_later_task(self):
        class Mail:
            def send(self, data): pass
            def read(self, size): return b"body"
            def readline(self): return b"OK\r\n"
        mail = track_imap_connection(Mail())
        meter = traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
        token = traffic._ACTIVE.set(meter)
        try:
            mail.read(4)
        finally:
            traffic._ACTIVE.reset(token)
        self.assertEqual(meter.snapshot()["mail_transfer_bytes"], 4)
