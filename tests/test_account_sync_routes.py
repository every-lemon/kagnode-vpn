"""Real web/RPC boundaries with enrolled fixture sessions and a fake issuer."""

import io
import json
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from auth_fixture import enroll
import vpn_web as web
from vpn_account_sync import ProfileLinks


class AccountRouteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = web.Store(self.root / "access.db")
        _, self.session, self.csrf, _ = enroll(self.store)
        config = {
            "lan": "192.168.0.8",
            "lan_net": "192.168.0.0/24",
            "public": "203.0.113.8",
            "endpoint": "vpn.example.test",
        }
        backend = SimpleNamespace(
            m=SimpleNamespace(load=lambda: config),
            repo=SimpleNamespace(path=self.store.path),
        )
        self.controller = web.Controller(backend, self.store)
        self.delay = 0
        self.issuer_requests = []

        def issuer(method, endpoint, data=None, token=None):
            self.issuer_requests.append(endpoint)
            if endpoint == "device":
                return {
                    "device_code": "D" * 43,
                    "user_code": "ABCDE-12345",
                    "verification_uri_complete": "https://nebulacoder.com/account/apps/device?code=ABCDE12345",
                }
            if endpoint == "token":
                time.sleep(self.delay)
                return {"access_token": "A" * 43, "refresh_token": "R" * 43}
            if endpoint.startswith("profile?"):
                return {
                    "issuer": "https://nebulacoder.com",
                    "subject": "route-fixture",
                    "name": "Linked route fixture",
                    "photo": "",
                }
            assert endpoint == "revoke"
            return {}

        self.controller._profile_links = ProfileLinks(
            self.root / "account-sync", "kagnode-vpn", transport=issuer
        )
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                value = json.loads(self.rfile.readline(65537))
                try:
                    result = {"ok": True, "result": owner.controller.handle(value, 0)}
                except Exception as error:
                    # Exercise the production serializer once available; preserve
                    # the old wire shape when reproducing the pre-fix behavior.
                    result = (
                        web.rpc_failure(error)
                        if hasattr(web, "rpc_failure")
                        else {"ok": False, "error": str(error)}
                    )
                try:
                    self.wfile.write(json.dumps(result).encode() + b"\n")
                except BrokenPipeError:
                    pass

        self.server = socketserver.UnixStreamServer(
            str(self.root / "rpc.sock"), Handler
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join, 7)
        self.addCleanup(self.server.shutdown)
        self.app = web.Application(
            config,
            "management",
            rpc_call=lambda request: web.rpc(request, path=self.root / "rpc.sock"),
        )

    def request(self, action=None, csrf=True, session=None, origin=None):
        body = json.dumps({"action": action}).encode() if action else b""
        env = {
            "REQUEST_METHOD": "POST" if action else "GET",
            "PATH_INFO": "/manage/kagnode-account",
            "QUERY_STRING": "",
            "HTTP_HOST": "192.168.0.8:9001",
            "REMOTE_ADDR": "192.168.0.22",
            "HTTP_ORIGIN": origin or "http://192.168.0.8:9001",
            "HTTP_COOKIE": "vpn_session="
            + (self.session if session is None else session),
            "HTTP_X_CSRF_TOKEN": self.csrf if csrf else "wrong",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        result = []
        payload = b"".join(self.app(env, lambda status, headers: result.append(status)))
        return int(result[0].split()[0]), json.loads(payload)

    def test_missing_and_expired_sessions_are_unauthorized_without_issuer_requests(
        self,
    ):
        for session in ["", "not-a-session"]:
            status, body = self.request(session=session)
            self.assertEqual(status, 401, body)
            self.assertEqual(body, {"error": "Session expired. Sign in again."})
        with self.store.connect() as db:
            db.execute("UPDATE admin_sessions SET created=created-28801")
        self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.issuer_requests, [])

    def test_invalid_csrf_and_cross_origin_requests_are_forbidden(self):
        for options in [{"csrf": False}, {"origin": "https://untrusted.example"}]:
            status, body = self.request("start", **options)
            self.assertEqual(status, 403, body)
        self.assertEqual(self.issuer_requests, [])

    def test_profile_expiry_crosses_the_real_socket_as_a_typed_http_error(self):
        status, body = self.request("poll")
        self.assertEqual(status, 410, body)
        self.assertIn("expired", body["error"])
        self.assertEqual(self.request()[0], 200)
        self.assertNotEqual(self.request("start", csrf=False)[0], 200)

    def test_unavailable_account_api_returns_retryable_json_instead_of_html(self):
        def unavailable(_request):
            raise ConnectionError("private broker unavailable")

        self.app.rpc = unavailable
        status, body = self.request()
        self.assertEqual(status, 503)
        self.assertIn("Try again", body["error"])
        self.assertNotIn("private broker", body["error"])

    def test_a_valid_slow_approval_finishes_instead_of_timing_out_at_five_seconds(self):
        self.assertEqual(self.request("start")[0], 200)
        self.delay = 5.2
        status, body = self.request("poll")
        self.assertEqual(status, 200, body)
        self.assertTrue(body["connected"])
        self.assertEqual(body["profile"]["name"], "Linked route fixture")


if __name__ == "__main__":
    unittest.main()
