"""Provider sign-in is bound to approved local VPN identity and still needs MFA."""

import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import vpn_web as web
from vpn_account_sync import ProfileLinks
from auth_fixture import enroll


class ProviderRoutes(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.store = web.Store(self.root / "auth.sqlite3")
        self.uid, _, _, self.codes = enroll(self.store)
        self.config = {
            "lan": "192.168.0.8",
            "lan_net": "192.168.0.0/24",
            "public": "203.0.113.8",
            "endpoint": "vpn.example.test",
        }
        backend = SimpleNamespace(
            m=SimpleNamespace(load=lambda: self.config),
            repo=SimpleNamespace(path=self.store.path),
        )
        self.controller = web.Controller(backend, self.store)
        self.device = {}
        self.subject = "provider-owner"
        self.links = ProfileLinks(
            self.root / "profiles", "kagnode-vpn", transport=self.transport
        )
        self.controller._profile_links = self.links
        self.app = web.Application(
            self.config,
            "management",
            rpc_call=lambda data: self.controller.handle(data, 0),
        )
        self.cookie = ""
        self.csrf = ""

    def transport(self, method, endpoint, data=None, token=None):
        if endpoint == "device":
            self.device = data
            return {
                "device_code": "D" * 43,
                "user_code": "ABCDE-12345",
                "verification_uri_complete": "https://nebulacoder.com/account/apps/device?code=ABCDE12345",
            }
        if endpoint == "token":
            now = time.time()
            return {
                "scope": "profile.read email.read",
                "access_token": "A" * 43,
                "refresh_token": "R" * 43,
                "authorization": {
                    "issuer": self.links.issuer,
                    "subject": self.subject,
                    "client_id": "kagnode-vpn",
                    "installation": self.device["installation"],
                    "purpose": "sign_in",
                    "nonce": self.device["nonce"],
                    "auth_time": now - 1,
                    "approved_at": now,
                    "issued_at": now,
                    "expires_at": now + 120,
                },
            }
        if endpoint.startswith("profile?"):
            return {
                "issuer": self.links.issuer,
                "subject": self.subject,
                "name": "Fixture owner",
                "photo": "",
            }
        return {}

    def request(self, data=None, csrf=True, origin=None):
        raw = json.dumps(data).encode() if data else b""
        result = []
        env = {
            "REQUEST_METHOD": "POST" if data else "GET",
            "PATH_INFO": "/manage/kagnode-login",
            "QUERY_STRING": "",
            "HTTP_HOST": "192.168.0.8:9001",
            "REMOTE_ADDR": "192.168.0.22",
            "HTTP_ORIGIN": origin or "http://192.168.0.8:9001",
            "HTTP_COOKIE": self.cookie,
            "HTTP_X_CSRF_TOKEN": self.csrf if csrf else "wrong",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }
        body = b"".join(
            self.app(env, lambda status, headers: result.append((status, headers)))
        )
        headers = dict(result[0][1])
        payload = json.loads(body)
        if not data:
            self.cookie = headers["Set-Cookie"].split(";")[0]
            self.csrf = payload["csrf"]
        return int(result[0][0].split()[0]), headers, payload

    def link(self):
        with self.links.db() as db:
            db.execute(
                "INSERT INTO links VALUES(?,?,?,?,?,0)",
                (
                    self.uid,
                    self.subject,
                    json.dumps(
                        {
                            "issuer": self.links.issuer,
                            "subject": self.subject,
                            "name": "Owner",
                            "photo": "",
                        }
                    ),
                    "O" * 43,
                    time.time(),
                ),
            )

    def confirm(self):
        self.request()
        status, _, start = self.request({"action": "start"})
        self.assertEqual(status, 200, start)
        status, _, ready = self.request(
            {"action": "status", "attempt_id": start["attempt_id"]}
        )
        return status, ready, start["attempt_id"]

    def test_prelinked_identity_requires_mfa_and_keeps_local_role(self):
        self.link()
        status, ready, attempt = self.confirm()
        self.assertEqual(status, 200, ready)
        self.assertEqual(ready["continuation"], "mfa")
        status, _, _ = self.request(
            {"action": "complete", "attempt_id": attempt, "code": "incorrect"}
        )
        self.assertEqual(status, 403)
        status, headers, body = self.request(
            {"action": "complete", "attempt_id": attempt, "code": self.codes[1]}
        )
        self.assertEqual(status, 200, body)
        self.assertNotIn("session", body)
        self.assertNotIn("csrf", body)
        session = headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
        identity = self.store.identity(session)
        self.assertEqual(identity["id"], self.uid)
        self.assertEqual(identity["role"], "owner")
        self.assertNotEqual(
            self.request(
                {"action": "complete", "attempt_id": attempt, "code": self.codes[2]}
            )[0],
            200,
        )

    def test_unlinked_provider_never_creates_administrator(self):
        status, ready, _ = self.confirm()
        self.assertEqual(status, 403, ready)
        with self.store.connect() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM administrators").fetchone()[0], 1
            )

    def test_policy_disable_keeps_local_password_mfa_usable(self):
        self.link()
        self.links.handle(self.uid, "Owner", True, "policy", {"enabled": False})
        self.assertFalse(self.request()[2]["enabled"])
        self.assertEqual(self.request({"action": "start"})[0], 403)
        session, _ = self.store.login(
            "test-management-password", "test", "owner", self.codes[1]
        )
        self.assertEqual(self.store.identity(session)["id"], self.uid)

    def test_anonymous_provider_request_requires_csrf_and_origin(self):
        self.request()
        self.assertEqual(self.request({"action": "start"}, csrf=False)[0], 403)
        self.assertEqual(
            self.request({"action": "start"}, origin="https://evil.test")[0], 403
        )

    def test_disconnected_owner_cannot_be_restored_by_an_old_continuation(self):
        from vpn_account_login import AccountSignIns
        from vpn_account_sync import AccountLinkError

        self.link()
        signins = AccountSignIns(self.links)
        browser = "B" * 43
        attempt = signins.start(browser, "https://console.example.test")["attempt_id"]
        signins.status(browser, attempt)
        self.links.handle(self.uid, "Owner", False, "disconnect")
        with self.links.db() as db:
            db.execute(
                "UPDATE sign_in_attempts SET link_stamp=? WHERE id=?",
                (self.links.stamp(self.uid), attempt),
            )
        with self.assertRaises(AccountLinkError):
            signins.finish(browser, attempt, self.uid)
        self.assertFalse(
            self.links.state(self.uid, "Owner", refresh=False)["connected"]
        )


if __name__ == "__main__":
    unittest.main()
