from __future__ import annotations

import random
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from proxy_traffic_lab.controller.errors import ConfigurationError


@dataclass(frozen=True)
class WebTrafficResult:
    attempted_pages: int
    successful_pages: int
    events: tuple[dict[str, Any], ...]


def generate_web_traffic(
    *,
    proxy_server: str,
    urls: Sequence[str],
    seed: int,
    max_duration_seconds: int,
    max_pages: int,
) -> WebTrafficResult:
    """Drive a real Chromium process through the experiment SOCKS proxy."""
    if not urls:
        raise ConfigurationError("at least one --url is required")
    if max_duration_seconds < 10:
        raise ConfigurationError("web traffic duration must be at least 10 seconds")
    if max_pages < 1:
        raise ConfigurationError("max_pages must be positive")

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ConfigurationError(
            "Playwright is not installed; install the pinned traffic extra and browser"
        ) from exc

    rng = random.Random(seed)
    queue = list(urls)
    rng.shuffle(queue)
    deadline = time.monotonic() + max_duration_seconds
    events: list[dict[str, Any]] = []
    successes = 0

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chromium", headless=True)
        context = browser.new_context(
            proxy={"server": proxy_server},
            viewport={"width": 1366, "height": 768},
            locale="zh-CN",
        )
        page = context.new_page()
        try:
            for index in range(max_pages):
                if time.monotonic() >= deadline:
                    break
                url = queue[index % len(queue)]
                started = time.monotonic()
                event: dict[str, Any] = {"index": index + 1, "url": url}
                try:
                    response = page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=min(30_000, max(1, int((deadline - time.monotonic()) * 1000))),
                    )
                    page.wait_for_timeout(rng.randint(800, 1800))
                    for _ in range(rng.randint(1, 4)):
                        page.mouse.wheel(0, rng.randint(350, 900))
                        page.wait_for_timeout(rng.randint(250, 900))
                    event.update(
                        {
                            "status": "ok",
                            "http_status": response.status if response else None,
                            "title": page.title()[:200],
                        }
                    )
                    successes += 1
                except (PlaywrightTimeoutError, PlaywrightError) as exc:
                    event.update(
                        {
                            "status": "error",
                            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                        }
                    )
                event["duration_seconds"] = round(time.monotonic() - started, 3)
                events.append(event)
                if time.monotonic() < deadline:
                    page.wait_for_timeout(rng.randint(500, 1600))
        finally:
            context.close()
            browser.close()

    return WebTrafficResult(
        attempted_pages=len(events),
        successful_pages=successes,
        events=tuple(events),
    )
