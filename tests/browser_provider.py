"""Disposable VPN/HTTP Boot web acceptance, no native backend operations."""

import argparse, json, os, sys, threading, time
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from wsgiref.simple_server import make_server

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument(
    "--engine", default=os.environ.get("KAGNODE_BROWSER_ENGINE", "chromium")
)
args = parser.parse_args()
args.product = "vpn"
source = ROOT
sys.path[:0] = [
    str(source / "src" if args.product == "vpn" else source / "httpboot"),
    str(source / "tests"),
]
import kagnode_core

if args.product == "vpn":
    from test_account_login_routes import ProviderRoutes

    case = ProviderRoutes()
    case.setUp()
    case.link()
    original = case.transport
    flags = {"pending": True, "offline": False}
    from vpn_account_sync import AccountLinkError

    def transport(method, endpoint, data=None, token=None):
        if flags["offline"]:
            raise AccountLinkError("Fixture issuer unavailable", 502)
        if (
            endpoint == "token"
            and data.get("grant_type") != "refresh_token"
            and flags["pending"]
        ):
            return {"error": "authorization_pending"}
        return original(method, endpoint, data, token)

    case.links.transport = transport

    def rpc(data):
        if data["op"] == "view":
            case.controller.authorize(data)
            return {
                "registry": {"users": {}, "devices": {}},
                "csrf": case.store.identity(data["session"])["csrf"],
                "identity": case.store.identity(data["session"]),
                "remaining": 1700,
                "jobs": [],
                "batches": [],
                "pagination": {},
            }
        if data["op"] == "dashboard":
            case.controller.authorize(data)
            return {
                "remaining": 1700,
                "revision": "fixture",
                "health": {
                    "memory": {"MemAvailable": 100, "MemTotal": 200},
                    "services": {},
                    "sampled_at": time.time(),
                },
                "jobs": [],
                "batches": [],
                "links": [],
            }
        return case.controller.handle(data, 0)

    case.app.rpc = rpc
    server = make_server("127.0.0.1", 9001, case.app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = "http://127.0.0.1:9001"
    path = "/manage"
else:
    from test_web_provider_login import WebProviderTests

    case = WebProviderTests()
    case.setUp()
    case.link()
    server = case.server
    original = case.transport
    flags = {"pending": True, "offline": False}
    from account_sync import AccountLinkError

    def transport(method, endpoint, data=None, token=None):
        if flags["offline"]:
            raise AccountLinkError("Fixture issuer unavailable", 502)
        if (
            endpoint == "token"
            and data.get("grant_type") != "refresh_token"
            and flags["pending"]
        ):
            return {"error": "authorization_pending"}
        return original(method, endpoint, data, token)

    case.links.transport = transport
    origin = f"http://127.0.0.1:{server.server_port}"
    path = "/overview"
output = Path(os.environ.get("KAGNODE_SCREENSHOT_DIR", ROOT / ".build/provider-login"))
output.mkdir(parents=True, exist_ok=True)
report = []
try:
    with sync_playwright() as pw:
        browser = getattr(pw, args.engine).launch(
            headless=True,
            **(
                {"executable_path": os.environ["KAGNODE_BROWSER_EXECUTABLE"]}
                if os.environ.get("KAGNODE_BROWSER_EXECUTABLE")
                else {}
            ),
        )
        for index, width in enumerate([390, 820, 1440]):
            context = browser.new_context(
                viewport={"width": width, "height": 950}, color_scheme="dark"
            )
            external = []
            errors = []
            context.route(
                "**/*",
                lambda route: route.continue_()
                if route.request.url.startswith(origin)
                else (external.append(route.request.url), route.abort()),
            )
            page = context.new_page()
            page.bring_to_front()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(origin + path)
            expect(page.locator("[data-core-login]")).to_be_visible(timeout=40000)
            provider = page.locator("[data-core-login-provider]")
            expect(provider).to_be_enabled(timeout=40000)
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
            box = page.locator(".kn-core-login-card").bounding_box()
            assert box and box["width"] >= min(width - 48, 400), box
            page.screenshot(path=str(output / f"{args.engine}-{width}-login.png"))
            # Real local credentials and second factors remain independently usable.
            if args.product == "vpn":
                form = page.locator('form[action="/manage/login"]')
                form.locator("[name=username]").fill("owner")
                form.locator("[name=password]").fill("test-management-password")
                form.locator("[name=code]").fill(case.codes[1 + index * 2])
                form.locator("button").click()
                expect(page.locator(".app-shell")).to_be_visible(timeout=40000)
            else:
                page.locator("#console-token").fill(case.token)
                page.locator("#connect-form button[type=submit]").click()
                expect(page.locator("#workspace")).to_be_visible(timeout=40000)
            context.close()
            context = browser.new_context(
                viewport={"width": width, "height": 950}, color_scheme="dark"
            )
            context.route(
                "**/*",
                lambda route: route.continue_()
                if route.request.url.startswith(origin)
                else (external.append(route.request.url), route.abort()),
            )
            page = context.new_page()
            page.bring_to_front()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(origin + path)
            provider = page.locator("[data-core-login-provider]")
            flags.update(pending=True, offline=False)
            provider.click()
            expect(page.get_by_text("ABCDE-12345", exact=True)).to_be_visible(
                timeout=40000
            )
            page.get_by_role("button", name="Cancel connection").click()
            expect(provider).to_be_enabled()
            expect(page.locator("[data-core-login-status]")).to_contain_text(
                "cancelled"
            )
            flags["offline"] = True
            provider.click()
            expect(page.locator("[data-core-login-status]")).to_contain_text(
                "Unable to connect", timeout=40000
            )
            flags.update(offline=False, pending=False)
            provider.click()
            if args.product == "vpn":
                expect(page.locator("#provider-mfa")).to_be_visible(timeout=40000)
                page.screenshot(
                    path=str(output / f"{args.engine}-{width}-continuation.png")
                )
                page.locator("#provider-mfa [name=code]").fill(
                    case.codes[2 + index * 2]
                )
                page.locator("#provider-mfa button").click()
                expect(page.locator(".app-shell")).to_be_visible(timeout=40000)
            else:
                expect(page.locator("#workspace")).to_be_visible(timeout=40000)
            assert not external, external
            assert not errors, errors
            context.close()
            report.append(
                {
                    "engine": args.engine,
                    "width": width,
                    "local_login": True,
                    "cancel": True,
                    "issuer_failure": True,
                    "linked_provider": True,
                    "external_requests": 0,
                    "page_errors": 0,
                }
            )
        # Turning the installation policy off suppresses provider login on a fresh page.
        case.links.handle(
            case.uid if args.product == "vpn" else "console-owner",
            "Owner",
            True,
            "policy",
            {"enabled": False},
        )
        context = browser.new_context()
        page = context.new_page()
        page.bring_to_front()
        page.goto(origin + path)
        expect(page.locator("[data-core-login-provider]")).to_be_hidden(timeout=40000)
        context.close()
        browser.close()
    (output / f"{args.engine}-report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report))
finally:
    if args.product == "vpn":
        server.shutdown()
        case.doCleanups()
    else:
        case.tearDown()
        case.doCleanups()
