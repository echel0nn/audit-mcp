"""Headless browser test runner for PoC validation.

Executes HTML/JavaScript in headless Chrome or Firefox with proper
security headers (COOP/COEP for SharedArrayBuffer support) and
returns console output, crash status, and timing.

This is the #1 tool gap identified during variant hunting — every
manual test cycle was 5-10 minutes. This reduces it to seconds.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any

__all__ = ["BrowserTestRunner", "BrowserTestResult"]

_log = logging.getLogger(__name__)

_CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
]

_FIREFOX_PATHS = [
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Mozilla Firefox\firefox.exe"),
    "/Applications/Firefox.app/Contents/MacOS/firefox",
    "/usr/bin/firefox",
    "/usr/bin/firefox-esr",
]


def _find_browser(preference: str = "auto") -> tuple[str | None, str]:
    """Find a browser binary. Returns ``(path, browser_type)``."""
    if preference in ("chrome", "auto"):
        for p in _CHROME_PATHS:
            if os.path.isfile(p):
                return p, "chrome"
        found = shutil.which("chrome") or shutil.which("google-chrome") or shutil.which("chromium")
        if found:
            return found, "chrome"
        if preference == "chrome":
            return None, "chrome"

    if preference in ("firefox", "auto"):
        for p in _FIREFOX_PATHS:
            if os.path.isfile(p):
                return p, "firefox"
        found = shutil.which("firefox") or shutil.which("firefox-esr")
        if found:
            return found, "firefox"

    return None, "none"


class _COOPHandler(SimpleHTTPRequestHandler):
    """HTTP handler with COOP/COEP headers for SharedArrayBuffer."""

    def end_headers(self) -> None:
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        super().end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


class BrowserTestResult:
    """Result of a browser test execution."""

    __slots__ = ("console", "errors", "crashed", "crash_reason", "exit_code",
                 "elapsed_seconds", "browser_version", "browser_type", "timed_out")

    def __init__(self) -> None:
        self.console: list[str] = []
        self.errors: list[str] = []
        self.crashed: bool = False
        self.crash_reason: str = ""
        self.exit_code: int = 0
        self.elapsed_seconds: float = 0.0
        self.browser_version: str = ""
        self.browser_type: str = ""
        self.timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "console": self.console,
            "errors": self.errors,
            "crashed": self.crashed,
            "crash_reason": self.crash_reason,
            "exit_code": self.exit_code,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "browser_type": self.browser_type,
            "browser_version": self.browser_version,
            "timed_out": self.timed_out,
        }


class BrowserTestRunner:
    """Run HTML/JS in headless Chrome or Firefox and capture output."""

    def __init__(self, browser: str = "auto", port: int = 0) -> None:
        self._browser_path, self._browser_type = _find_browser(browser)
        self._port = port

    def available(self) -> bool:
        """Check if a supported browser is available."""
        return self._browser_path is not None and os.path.isfile(self._browser_path)

    def info(self) -> dict[str, Any]:
        """Return browser detection status."""
        return {
            "available": self.available(),
            "browser_type": self._browser_type,
            "browser_path": self._browser_path,
        }

    def run(
        self,
        html: str,
        timeout_seconds: int = 30,
        browser: str | None = None,
    ) -> BrowserTestResult:
        """Execute HTML in headless browser and return results.

        The HTML is served via a local HTTP server with COOP/COEP headers.
        Console output is captured. Crashes are detected via exit code/stderr.

        ``browser`` overrides the instance default: ``"chrome"``, ``"firefox"``, ``"auto"``.
        """
        result = BrowserTestResult()

        browser_path = self._browser_path
        browser_type = self._browser_type
        if browser is not None:
            browser_path, browser_type = _find_browser(browser)
        result.browser_type = browser_type

        if browser_path is None or not os.path.isfile(browser_path):
            result.errors.append(f"Browser not found (type={browser_type})")
            return result

        tmpdir = tempfile.mkdtemp(prefix="audit-mcp-browser-")
        html_path = os.path.join(tmpdir, "test.html")
        Path(html_path).write_text(_wrap_html(html), encoding="utf-8")

        server = _start_server(tmpdir, self._port)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        url = f"http://127.0.0.1:{port}/test.html"

        try:
            t0 = time.monotonic()

            if browser_type == "firefox":
                args = [
                    browser_path,
                    "--headless",
                    "--screenshot", os.path.join(tmpdir, "shot.png"),
                    "--window-size=1280,720",
                    url,
                ]
            else:
                args = [
                    browser_path,
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-default-apps",
                    "--disable-sync",
                    "--no-first-run",
                    "--enable-features=SharedArrayBuffer",
                    "--dump-dom",
                    url,
                ]

            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            result.elapsed_seconds = time.monotonic() - t0
            result.exit_code = proc.returncode

            _parse_output(proc.stdout or "", proc.stderr or "", result)

            if proc.returncode != 0:
                stderr = proc.stderr or ""
                if "STATUS_BREAKPOINT" in stderr or "SIGILL" in stderr:
                    result.crashed = True
                    result.crash_reason = "STATUS_BREAKPOINT (V8 CHECK failure)"
                elif "STATUS_ACCESS_VIOLATION" in stderr or "SIGSEGV" in stderr:
                    result.crashed = True
                    result.crash_reason = "ACCESS_VIOLATION (memory corruption)"
                elif "SIGABRT" in stderr or "SIGIOT" in stderr:
                    result.crashed = True
                    result.crash_reason = "SIGABRT (assertion failure)"
                elif proc.returncode != 0:
                    result.crashed = True
                    result.crash_reason = f"exit_code={proc.returncode}"

        except subprocess.TimeoutExpired:
            result.timed_out = True
            result.elapsed_seconds = float(timeout_seconds)
            result.errors.append(f"Timed out after {timeout_seconds}s")
        except (OSError, ValueError) as exc:
            result.errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            server.shutdown()
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except OSError:
                pass

        return result


def _wrap_html(html: str) -> str:
    """Inject console capture script into HTML."""
    capture = """
<div id="__audit_mcp_output__" style="display:none"></div>
<script>
(function() {
    var out = document.getElementById('__audit_mcp_output__');
    var lines = [];
    function capture(prefix, origFn, args) {
        var msg = Array.prototype.slice.call(args).map(function(a) {
            return typeof a === 'object' ? JSON.stringify(a) : String(a);
        }).join(' ');
        lines.push(prefix + msg);
        if (out) out.textContent = lines.join('\\n');
        origFn.apply(console, args);
    }
    var _log = console.log, _err = console.error, _warn = console.warn;
    console.log = function() { capture('LOG:', _log, arguments); };
    console.error = function() { capture('ERR:', _err, arguments); };
    console.warn = function() { capture('WARN:', _warn, arguments); };
})();
</script>
"""
    lower = html.lower()
    if "<body" in lower:
        idx = html.find(">", lower.find("<body")) + 1
        return html[:idx] + capture + html[idx:]
    if "<html" in lower:
        idx = html.find(">", lower.find("<html")) + 1
        return html[:idx] + "<body>" + capture + html[idx:]
    return f"<!DOCTYPE html><html><body>{capture}{html}</body></html>"


def _start_server(directory: str, port: int) -> HTTPServer:
    """Start a local HTTP server with COOP/COEP headers."""

    class Handler(_COOPHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=directory, **kwargs)

    return HTTPServer(("127.0.0.1", port), Handler)


def _parse_output(stdout: str, stderr: str, result: BrowserTestResult) -> None:
    """Extract console lines from Chrome's --dump-dom output."""
    for line in stdout.splitlines():
        s = re.sub(r"<[^>]+>", "", line).strip()
        if not s:
            continue
        if s.startswith("LOG:"):
            result.console.append(s[4:])
        elif s.startswith("ERR:"):
            result.errors.append(s[4:])
        elif s.startswith("WARN:"):
            result.console.append("[WARN] " + s[5:])
        elif s.startswith("[*]") or s.startswith("[!!!]"):
            result.console.append(s)
        elif s.startswith("[CATCH]") or s.startswith("[FATAL]"):
            result.errors.append(s)

    for line in stderr.splitlines():
        m = re.search(r"Chrome/([\d.]+)", line)
        if m:
            result.browser_version = m.group(1)
            break
        m = re.search(r"Firefox/([\d.]+)", line)
        if m:
            result.browser_version = m.group(1)
            break
