"""A `browser.PageDriver` backed by Playwright.

Isolated in its own module and imported only by `browser.playwright_driver_factory`, so
`import tpihunter` never needs Playwright — the same rule `anthropic` and `mcp` follow.

One instance is one independent browsing context: its own cookie jar, its own storage.
The adapter builds one per principal, which is what makes the oracle's independence
control mean anything.
"""
from __future__ import annotations

from typing import Optional


class PlaywrightDriver:
    def __init__(self, headless: bool = False, settle_ms: int = 5000, **context_kw) -> None:
        from playwright.sync_api import sync_playwright
        self._settle = settle_ms
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=headless)
        self._ctx = self._browser.new_context(**({"locale": "en-US"} | context_kw))
        self._page = self._ctx.new_page()

    # -- navigation -----------------------------------------------------------
    def goto(self, url: str) -> None:
        self._page.goto(url, wait_until="domcontentloaded", timeout=60000)
        self._page.wait_for_timeout(self._settle)

    def url(self) -> str:
        return self._page.url

    def text(self) -> str:
        try:
            return " ".join((self._page.inner_text("body") or "").split())
        except Exception:
            return ""

    # -- interaction ----------------------------------------------------------
    def fill(self, selector: str, value: str) -> bool:
        el = self._page.query_selector(selector)
        if el is None or not el.is_visible():
            return False
        el.click()
        el.type(value, delay=25)
        return True

    def click(self, target: str) -> bool:
        """`target` is a CSS selector, or the visible label of a control.

        Label-clicking matters: real flows are driven by buttons reading "Register New
        Passkey" or "Sign out", and a modal's confirm button is reachable no other way.
        """
        el = self._page.query_selector(target)
        if el is not None and el.is_visible():
            return self._click(el)
        want = target.strip().lower()
        for el in self._page.query_selector_all("a, button, [role=button], input[type=submit]"):
            try:
                label = " ".join((el.inner_text() or el.get_attribute("value") or "").split())
            except Exception:
                continue
            if label.strip().lower() == want and el.is_visible():
                return self._click(el)
        return False

    def _click(self, el) -> bool:
        try:
            el.click(timeout=9000)
        except Exception:
            try:
                self._page.evaluate("(e) => e.click()", el)      # past a modal overlay
            except Exception:
                return False
        self._page.wait_for_timeout(self._settle)
        return True

    def has(self, selector: str) -> bool:
        el = self._page.query_selector(selector)
        return el is not None and el.is_visible()

    # -- state ----------------------------------------------------------------
    def cookies(self) -> dict:
        return {c["name"]: c["value"] for c in self._ctx.cookies()}

    def set_cookies(self, cookies: dict, domain: Optional[str] = None) -> None:
        from urllib.parse import urlsplit
        host = domain or urlsplit(self._page.url).hostname or ""
        self._ctx.add_cookies([{"name": k, "value": v, "domain": host, "path": "/"}
                               for k, v in cookies.items() if host])

    def close(self) -> None:
        for shut in (self._ctx.close, self._browser.close, self._pw.stop):
            try: shut()
            except Exception: pass
