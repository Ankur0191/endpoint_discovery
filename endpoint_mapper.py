#!/usr/bin/env python3
"""Passive Playwright endpoint inventory for authorized targets.

Records observed request metadata and candidate API paths from loaded JavaScript.
It deliberately does not save secrets, request/response bodies, or query values.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from playwright.async_api import (
    async_playwright,
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
)

class BrowserSessionClosedError(RuntimeError):
    """Raised when Playwright reports that a page, context, or browser closed."""


def is_target_closed_error(exc: BaseException) -> bool:
    """Recognize Playwright target-closed errors across package versions.

    TargetClosedError is not exported by every Playwright version, so avoid
    importing that optional symbol and inspect the exception safely instead.
    """
    class_name = type(exc).__name__.lower()
    message = str(exc).lower()
    return (
        "targetclosed" in class_name
        or "target page, context or browser has been closed" in message
        or "target page, context or browser was closed" in message
        or "browser has been closed" in message
        or "context has been closed" in message
    )


SENSITIVE_QUERY_KEYS = re.compile(
    r"(token|access_token|refresh_token|auth|authorization|session|key|secret|password|code|jwt|sig|signature)",
    re.I,
)
API_HINT = re.compile(
    r"""(?:"|')((?:https?://[^"'\s]+)?/(?:api|apis|v[0-9]+|graphql|rest|auth|oauth|admin|internal|rpc|trpc)(?:/[^"'\s]*)?)(?:"|')""",
    re.I,
)
SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webm", ".mp3", ".css", ".map",
)
SENSITIVE_PATH = re.compile(r"/(logout|signout|delete|remove|destroy)(?:/|$)", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_url(url: str, redact_query: bool = True) -> str:
    """Remove fragments and redact common secret-bearing query values."""
    try:
        p = urlsplit(url)
        if p.scheme not in ("http", "https", "ws", "wss"):
            return url
        query = p.query
        if redact_query and query:
            safe = []
            for key, value in parse_qsl(query, keep_blank_values=True):
                safe.append((key, "[REDACTED]" if SENSITIVE_QUERY_KEYS.search(key) else value))
            query = urlencode(safe, doseq=True)
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", query, ""))
    except Exception:
        return url.split("#", 1)[0]


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme.lower()}://{p.netloc.lower()}"


def classify(url: str, resource_type: str = "") -> str:
    path = urlsplit(url).path.lower()
    if resource_type == "websocket" or url.startswith(("ws://", "wss://")):
        return "websocket"
    if "graphql" in path:
        return "graphql"
    if path.endswith(("openapi.json", "swagger.json")) or "/openapi" in path or "/swagger" in path:
        return "api_schema"
    if any(part in path for part in ("/auth", "/oauth", "/session", "/login", "/logout")):
        return "authentication"
    if any(part in path for part in ("/admin", "/internal", "/manage")):
        return "administrative_or_internal_candidate"
    if re.search(r"/(?:api|apis|v[0-9]+|rest|rpc|trpc)(?:/|$)", path):
        return "api"
    if resource_type in ("xhr", "fetch"):
        return "xhr_or_fetch"
    if resource_type == "document":
        return "page"
    return "static_or_other"


def is_http(url: str) -> bool:
    return urlsplit(url).scheme in ("http", "https")


class EndpointMapper:
    def __init__(
        self,
        start_url: str,
        max_pages: int,
        max_depth: int,
        delay: float,
        manual_seconds: int,
        headed: bool,
        storage_state: str | None,
        allow_origins: list[str],
        inspect_js: bool,
        max_browser_restarts: int,
        concurrency: int,
    ):
        self.start_url = start_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.manual_seconds = manual_seconds
        self.headed = headed
        self.storage_state = storage_state
        self.allowed_origins = set(allow_origins)
        self.inspect_js = inspect_js
        self.max_browser_restarts = max_browser_restarts
        self.concurrency = concurrency

        self.endpoints: dict[tuple[str, str], dict[str, Any]] = {}
        self.pages: dict[str, dict[str, Any]] = {}
        self.assets: dict[str, dict[str, Any]] = {}
        self.errors: list[dict[str, str]] = []
        self.visited: set[str] = set()
        self.browser_restarts = 0
        self._closing = False
        self._restarting = False

    def allowed(self, url: str) -> bool:
        return is_http(url) and origin_of(url) in self.allowed_origins

    def _note_browser_disconnect(self) -> None:
        if not self._closing and not self._restarting:
            self.errors.append({
                "url": self.start_url,
                "error": "Chromium disconnected unexpectedly; scanner will attempt recovery.",
            })

    def _note_context_close(self) -> None:
        if not self._closing and not self._restarting:
            self.errors.append({
                "url": self.start_url,
                "error": "Browser context closed unexpectedly; scanner will attempt recovery.",
            })

    def record_request(self, request: Request) -> None:
        url = request.url
        if not is_http(url):
            return
        key = (request.method.upper(), normalize_url(url))
        rec = self.endpoints.setdefault(key, {
            "method": request.method.upper(),
            "url": normalize_url(url),
            "category": classify(url, request.resource_type),
            "resource_type": request.resource_type,
            "status_codes": [],
            "content_types": [],
            "referring_pages": [],
            "discovered_by": [],
            "authentication_material_present": False,
            "first_seen": utc_now(),
            "last_seen": utc_now(),
            "occurrences": 0,
        })
        rec["occurrences"] += 1
        rec["last_seen"] = utc_now()
        try:
            frame_url = request.frame.url
            if frame_url:
                clean_frame = normalize_url(frame_url)
                if clean_frame not in rec["referring_pages"]:
                    rec["referring_pages"].append(clean_frame)
        except Exception:
            pass
        if "browser_network_observation" not in rec["discovered_by"]:
            rec["discovered_by"].append("browser_network_observation")
        try:
            headers = {k.lower(): v for k, v in request.headers.items()}
            if any(k in headers for k in ("authorization", "cookie", "x-api-key")):
                rec["authentication_material_present"] = True
        except Exception:
            pass

    async def record_response(self, response: Response) -> None:
        req = response.request
        key = (req.method.upper(), normalize_url(req.url))
        rec = self.endpoints.get(key)
        if not rec:
            self.record_request(req)
            rec = self.endpoints.get(key)
        if not rec:
            return
        if response.status not in rec["status_codes"]:
            rec["status_codes"].append(response.status)
        try:
            content_type = response.headers.get("content-type", "")
            if content_type and content_type not in rec["content_types"]:
                rec["content_types"].append(content_type)
        except Exception:
            pass
        if self.inspect_js and req.resource_type == "script" and response.status < 400:
            content_type = ""
            try:
                content_type = response.headers.get("content-type", "")
            except Exception:
                pass
            if "javascript" in content_type or urlsplit(req.url).path.endswith(".js"):
                await self.inspect_script(response)

    async def inspect_script(self, response: Response) -> None:
        asset_url = normalize_url(response.url)
        self.assets.setdefault(asset_url, {
            "url": asset_url,
            "status": response.status,
            "candidate_paths": [],
            "inspection": "loaded JavaScript text; content not retained",
        })
        try:
            source = await response.text()
        except Exception:
            return
        if len(source) > 5_000_000:
            return
        for candidate in set(API_HINT.findall(source)):
            absolute = urljoin(response.url, candidate)
            if not is_http(absolute):
                continue
            normalized = normalize_url(absolute)
            self.add_candidate(normalized, "javascript_route_extraction", response.url)
            if normalized not in self.assets[asset_url]["candidate_paths"]:
                self.assets[asset_url]["candidate_paths"].append(normalized)

    def add_candidate(self, url: str, source: str, referring_asset: str | None = None) -> None:
        if not url.startswith(("http://", "https://", "ws://", "wss://")):
            return
        key = ("UNKNOWN", normalize_url(url))
        rec = self.endpoints.setdefault(key, {
            "method": "UNKNOWN",
            "url": normalize_url(url),
            "category": classify(url),
            "resource_type": "unobserved_candidate",
            "status_codes": [],
            "content_types": [],
            "referring_pages": [],
            "discovered_by": [],
            "authentication_material_present": None,
            "first_seen": utc_now(),
            "last_seen": utc_now(),
            "occurrences": 0,
        })
        if source not in rec["discovered_by"]:
            rec["discovered_by"].append(source)
        if referring_asset:
            asset = normalize_url(referring_asset)
            if asset not in rec["referring_pages"]:
                rec["referring_pages"].append(asset)

    async def attach_observers(self, page: Page) -> None:
        page.on("request", self.record_request)
        page.on(
            "response",
            lambda response: asyncio.create_task(self.record_response(response)),
        )
        page.on(
            "websocket",
            lambda websocket: self.add_candidate(websocket.url, "websocket_observation"),
        )

    async def crawl_one(
        self, context: BrowserContext, url: str, depth: int, parent: str | None
    ) -> list[str]:
        """Open this URL in its own tab, observe it, then close the tab."""
        clean_url = normalize_url(url)
        if clean_url in self.visited or len(self.visited) >= self.max_pages or not self.allowed(url):
            return []
        if SENSITIVE_PATH.search(urlsplit(url).path):
            self.pages[clean_url] = {
                "url": clean_url,
                "status": None,
                "depth": depth,
                "parent": normalize_url(parent) if parent else None,
                "skipped": "potentially state-changing path",
            }
            return []

        # Reserve the page before the first await so parallel workers cannot
        # exceed max_pages by all passing the limit check at the same time.
        self.visited.add(clean_url)
        page: Page | None = None
        outgoing: list[str] = []
        title = ""
        status = None
        error = None
        try:
            page = await context.new_page()
            await self.attach_observers(page)
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            status = response.status if response else None
            try:
                await page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass
            title = await page.title()
            if depth < self.max_depth:
                hrefs = await page.locator("a[href]").evaluate_all(
                    "(els) => els.map(a => a.href).filter(Boolean)"
                )
                for href in hrefs:
                    if not self.allowed(href):
                        continue
                    clean = normalize_url(href)
                    if clean in self.visited or clean in outgoing:
                        continue
                    path = urlsplit(clean).path.lower()
                    if path.endswith(SKIP_EXTENSIONS) or SENSITIVE_PATH.search(path):
                        continue
                    outgoing.append(clean)
        except Exception as exc:
            if is_target_closed_error(exc):
                # Convert to our own stable exception; the concrete Playwright
                # exception is not exported by all installed versions.
                raise BrowserSessionClosedError(str(exc)) from exc
            error = str(exc)[:500]
            self.errors.append({"url": clean_url, "error": error})
        finally:
            self.pages[clean_url] = {
                "url": clean_url,
                "title": title,
                "status": status,
                "depth": depth,
                "parent": normalize_url(parent) if parent else None,
                "outgoing_same_origin_links": len(outgoing),
                "error": error,
            }
            if page is not None:
                try:
                    if not page.is_closed():
                        await page.close()
                except Exception:
                    pass

        if self.delay:
            await asyncio.sleep(self.delay)
        return outgoing

    async def run(self) -> dict[str, Any]:
        async with async_playwright() as playwright:
            browser: Browser | None = None
            context: BrowserContext | None = None
            recovery_lock = asyncio.Lock()

            async def start_session() -> None:
                nonlocal browser, context
                browser = await playwright.chromium.launch(headless=not self.headed)
                browser.on("disconnected", lambda *_args: self._note_browser_disconnect())

                context_args: dict[str, Any] = {}
                if self.storage_state:
                    context_args["storage_state"] = self.storage_state
                context = await browser.new_context(**context_args)
                context.on("close", lambda *_args: self._note_context_close())

            async def recover_session(reason: str) -> None:
                nonlocal browser, context
                async with recovery_lock:
                    # Another worker may already have recovered the shared session.
                    if (
                        browser is not None
                        and browser.is_connected()
                        and context is not None
                        and not context.is_closed()
                    ):
                        return
                    if self.browser_restarts >= self.max_browser_restarts:
                        raise RuntimeError(
                            f"Browser recovery limit reached ({self.max_browser_restarts}). "
                            f"Last failure: {reason}"
                        )
                    self.browser_restarts += 1
                    self._restarting = True
                    try:
                        if browser is not None and browser.is_connected():
                            try:
                                await browser.close()
                            except Exception:
                                pass
                    finally:
                        self._restarting = False
                    browser = None
                    context = None
                    await start_session()

            await start_session()

            queue: asyncio.Queue[tuple[str, int, str | None] | None] = asyncio.Queue()
            await queue.put((self.start_url, 0, None))

            async def worker(worker_number: int) -> None:
                while True:
                    item = await queue.get()
                    if item is None:
                        queue.task_done()
                        return

                    url, depth, parent = item
                    clean_url = normalize_url(url)
                    try:
                        if clean_url in self.visited or len(self.visited) >= self.max_pages:
                            continue

                        discovered: list[str] = []
                        completed = False
                        # A tab can close independently; retry it once. If the
                        # browser/context itself died, one worker restarts it
                        # and the others reuse the recovered context.
                        for attempt in range(2):
                            try:
                                if (
                                    browser is None
                                    or not browser.is_connected()
                                    or context is None
                                    or context.is_closed()
                                ):
                                    await recover_session("browser/context unavailable before navigation")
                                if context is None:
                                    raise BrowserSessionClosedError("No active browser context")
                                discovered = await self.crawl_one(context, url, depth, parent)
                                completed = True
                                break
                            except BrowserSessionClosedError as exc:
                                self.visited.discard(clean_url)
                                if attempt == 1:
                                    self.errors.append({
                                        "url": clean_url,
                                        "error": f"Page/context closed twice; skipped after retry: {str(exc)[:350]}",
                                    })
                                    break
                                try:
                                    await recover_session(str(exc))
                                except Exception as recovery_error:
                                    self.errors.append({
                                        "url": clean_url,
                                        "error": f"Browser recovery failed: {str(recovery_error)[:350]}",
                                    })
                                    break

                        if completed:
                            for candidate in discovered:
                                await queue.put((candidate, depth + 1, url))
                    except Exception as exc:
                        self.visited.discard(clean_url)
                        self.errors.append({
                            "url": clean_url,
                            "error": f"Worker {worker_number} failed: {str(exc)[:400]}",
                        })
                    finally:
                        queue.task_done()

            workers = [
                asyncio.create_task(worker(index + 1))
                for index in range(self.concurrency)
            ]
            await queue.join()
            for _ in workers:
                await queue.put(None)
            await asyncio.gather(*workers, return_exceptions=True)

            if self.manual_seconds:
                try:
                    if (
                        browser is None
                        or not browser.is_connected()
                        or context is None
                        or context.is_closed()
                    ):
                        await recover_session("browser/context unavailable before manual exploration")
                    if context is None:
                        raise BrowserSessionClosedError("No active browser context for manual exploration")
                    page = await context.new_page()
                    await self.attach_observers(page)
                    try:
                        await page.goto(self.start_url, wait_until="domcontentloaded", timeout=30000)
                        print(f"\nManual exploration is open for {self.manual_seconds} seconds.")
                        print("Use the visible browser tabs to visit app areas and exercise normal, authorized workflows.")
                        await asyncio.sleep(self.manual_seconds)
                    finally:
                        if not page.is_closed():
                            await page.close()
                except Exception as exc:
                    self.errors.append({
                        "url": self.start_url,
                        "error": f"manual exploration session: {str(exc)[:400]}",
                    })

            self._closing = True
            try:
                if context is not None and not context.is_closed():
                    await context.close()
            except Exception:
                pass
            try:
                if browser is not None and browser.is_connected():
                    await browser.close()
            except Exception:
                pass

        endpoints = sorted(
            self.endpoints.values(),
            key=lambda item: (item["category"], item["url"], item["method"]),
        )
        return {
            "schema_version": "1.2",
            "scan": {
                "target": self.start_url,
                "completed_at": utc_now(),
                "allowed_origins": sorted(self.allowed_origins),
                "pages_visited": len(self.visited),
                "page_limit": self.max_pages,
                "max_depth": self.max_depth,
                "concurrency": self.concurrency,
                "manual_exploration_seconds": self.manual_seconds,
                "browser_restarts": self.browser_restarts,
                "coverage_note": (
                    "Not a guarantee of 100% endpoint coverage. Results are limited to observed browser "
                    "traffic and paths extracted from loaded JavaScript during this run."
                ),
                "mode": "passive endpoint inventory; no brute force or exploit testing",
            },
            "summary": {
                "total_endpoint_records": len(endpoints),
                "observed_requests": sum(1 for item in endpoints if item["method"] != "UNKNOWN"),
                "unverified_candidates": sum(1 for item in endpoints if item["method"] == "UNKNOWN"),
                "pages": len(self.pages),
                "javascript_assets": len(self.assets),
                "errors": len(self.errors),
                "browser_restarts": self.browser_restarts,
                "by_category": dict(Counter(item["category"] for item in endpoints)),
                "by_method": dict(Counter(item["method"] for item in endpoints)),
                "by_status": dict(Counter(str(code) for item in endpoints for code in item["status_codes"])),
            },
            "endpoints": endpoints,
            "pages": list(self.pages.values()),
            "assets": list(self.assets.values()),
            "errors": self.errors,
        }

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Passive Playwright endpoint discovery")
    parser.add_argument("url", help="Authorized site URL, e.g. https://example.com")
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=15, help="Parallel tabs (1-15; default: 15)")
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--manual-seconds", type=int, default=0)
    parser.add_argument(
        "--storage-state",
        help="Playwright storage-state file for a dedicated test account",
    )
    parser.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="Additional explicitly authorized origin; repeat for multiple origins",
    )
    parser.add_argument("--no-js-inspection", action="store_true")
    parser.add_argument(
        "--browser-restarts",
        type=int,
        default=2,
        help="Automatic Chromium restarts if the browser/context crashes (default: 2)",
    )
    parser.add_argument("--output", "-o", default="endpoint_map.json")
    args = parser.parse_args()
    if not args.url.startswith(("http://", "https://")):
        parser.error("URL must start with http:// or https://")
    if (
        args.max_pages < 1
        or args.max_depth < 0
        or args.delay < 0
        or args.manual_seconds < 0
        or args.browser_restarts < 0
        or args.concurrency < 1
        or args.concurrency > 15
    ):
        parser.error("Invalid limit: concurrency must be 1-15; other limits must be non-negative")
    return args


async def main() -> int:
    args = parse_args()
    allowed_origins = [origin_of(args.url)] + [
        origin.rstrip("/") for origin in args.allow_origin
    ]
    mapper = EndpointMapper(
        start_url=args.url,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        delay=args.delay,
        manual_seconds=args.manual_seconds,
        headed=args.headed or args.manual_seconds > 0,
        storage_state=args.storage_state,
        allow_origins=allowed_origins,
        inspect_js=not args.no_js_inspection,
        max_browser_restarts=args.browser_restarts,
        concurrency=args.concurrency,
    )
    report = await mapper.run()
    output = Path(args.output)
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps(report["summary"], indent=2))
    print(f"\nReport written to: {output.resolve()}")
    if report["errors"]:
        print(f"Completed with {len(report['errors'])} warning/error record(s). Check the JSON errors array.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        raise SystemExit(130)
