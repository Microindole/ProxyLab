from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch a visible Chromium dedicated to proxy traffic capture."
    )
    parser.add_argument("--proxy", default="socks5://127.0.0.1:10808")
    parser.add_argument("--start-url", default="https://example.com/")
    parser.add_argument(
        "--display-backend",
        choices=("auto", "wayland", "x11"),
        default="wayland" if os.environ.get("WAYLAND_DISPLAY") else "auto",
        help="Chromium display backend; WSLg defaults to native Wayland.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    os.environ.setdefault(
        "PLAYWRIGHT_BROWSERS_PATH",
        str(Path.home() / ".cache" / "ms-playwright"),
    )
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError:
        print(
            "error: Playwright is not installed in the active Python environment",
            file=sys.stderr,
        )
        return 2

    with sync_playwright() as playwright:
        browser = None
        try:
            chromium_args = [
                "--disable-quic",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--no-first-run",
            ]
            if args.display_backend != "auto":
                chromium_args.append(f"--ozone-platform={args.display_backend}")

            browser = playwright.chromium.launch(
                channel="chromium",
                headless=False,
                args=chromium_args,
            )
            context = browser.new_context(
                proxy={"server": args.proxy},
                accept_downloads=True,
                viewport={"width": 1366, "height": 768},
                locale="zh-CN",
            )
            page = context.new_page()
            try:
                page.goto(
                    args.start_url,
                    wait_until="domcontentloaded",
                    timeout=30_000,
                )
                print(f"Start page opened: {args.start_url}", flush=True)
            except Error as exc:
                print(
                    f"warning: start page failed, but Chromium will stay open: {exc}",
                    file=sys.stderr,
                    flush=True,
                )

            print(
                f"Chromium READY through {args.proxy}.\n"
                "Closing one tab will not close the launcher while another tab exists.\n"
                "Close the browser window or press Ctrl+C here when all captures finish.",
                flush=True,
            )
            while browser.is_connected():
                pages = context.pages
                if not pages:
                    break
                try:
                    pages[0].wait_for_timeout(1000)
                except Error:
                    if not browser.is_connected():
                        break
                    continue
        except KeyboardInterrupt:
            print("\nClosing Chromium on user request...", flush=True)
        except Exception as exc:
            print(f"error: Chromium launcher failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        finally:
            if browser is not None and browser.is_connected():
                browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
