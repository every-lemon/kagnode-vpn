"""Local update notices preserve management authentication and role boundaries."""

import sys
from pathlib import Path
from unittest.mock import patch
import unittest
import test_account_login_routes as fixtures
from auth_fixture import enroll
import vpn_web as web

EVENT = {
    "available": True,
    "notice": {
        "id": "a" * 64,
        "version": "5.0.6",
        "title": "Interface updated",
        "items": ["Improved shared controls."],
    },
}


class CoreNotices(unittest.TestCase):
    setUp = fixtures.ProviderRoutes.setUp
    transport = fixtures.ProviderRoutes.transport

    def test_auditor_can_dismiss_only_own_notice_with_valid_csrf(self):
        _, session, csrf, _ = enroll(
            self.store, "notice-auditor", role="auditor", actor=self.uid
        )
        context = {
            "op": "core-notice",
            "action": "read",
            "peer": "192.168.0.22",
            "host": "192.168.0.8:9001",
            "session": session,
        }
        with patch.object(web.kagnode_core, "manager_request", return_value=EVENT):
            self.assertEqual(self.controller.handle(context, 0), EVENT)
            with self.assertRaises(web.WebError):
                self.controller.handle({**context, "session": "invalid"}, 0)
            with self.assertRaises(web.WebError):
                self.controller.handle(
                    {
                        **context,
                        "action": "dismiss",
                        "notice_id": "a" * 64,
                        "csrf": "bad",
                    },
                    0,
                )
            self.assertEqual(
                self.controller.handle(
                    {
                        **context,
                        "action": "dismiss",
                        "notice_id": "a" * 64,
                        "csrf": csrf,
                    },
                    0,
                ),
                {"dismissed": True},
            )
            self.assertIsNone(self.controller.handle(context, 0)["notice"])
            self.assertFalse(self.links.notice_is_dismissed(self.uid, "a" * 64))
            with self.assertRaises(web.WebError):
                self.controller.handle({**context, "action": "policy"}, 0)


if __name__ == "__main__":
    unittest.main()
