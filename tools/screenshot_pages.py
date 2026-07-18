#!/usr/bin/env python3
"""Capture screenshots of every KTC Mail admin page for the repo.

Standalone dev tool — not shipped in the .deb. Seeds a throwaway config dir
with a sample profile + admin account, boots the real FastAPI app under
uvicorn, drives headless Chromium (CDP) to log in and screenshot each route,
then writes PNGs to docs/screenshots/.

Deps: python3 (ktc_mail_admin importable), node22 (global WebSocket), and a
Chromium binary (point CHROME_BIN at it; defaults to the cached Playwright one).

Usage: python3 tools/screenshot_pages.py
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

OUT = REPO / "docs" / "screenshots"
PORT = 8899
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASS = "ScreenshotDemo123!"


def main() -> int:
    chrome = os.environ.get("CHROME_BIN") or next(
        (str(p) for p in sorted(
            Path.home().glob(".cache/ms-playwright/chromium-*/chrome-linux64/chrome")
        ) if p.exists()),
        "chrome",
    )
    if not shutil.which(chrome) and not Path(chrome).exists():
        print(f"CHROME_BIN not found ({chrome}); set CHROME_BIN to a Chromium binary")
        return 2

    work = Path(tempfile.mkdtemp(prefix="ktc-shot-"))
    cfg = work / "etc"
    state = work / "state"
    cfg.mkdir(parents=True, exist_ok=True)
    state.mkdir(parents=True, exist_ok=True)
    os.environ["KTC_MAIL_CONFIG_DIR"] = str(cfg)
    os.environ["KTC_MAIL_STATE_DIR"] = str(state)
    # Local screenshot run is plain HTTP over loopback; the app sets the
    # session cookie Secure by default, which Chrome won't send over HTTP.
    # KTC_DEV=1 drops Secure for this throwaway capture only.
    os.environ["KTC_DEV"] = "1"

    # Seed a realistic-looking profile + admin account.
    import ktc_mail_admin.config as C
    from ktc_mail_admin.admin_server import hash_password, save_admin_account, save_admin_hash
    C.save_profile(C.SetupProfile(
        domain="example.com", admin_email=ADMIN_EMAIL,
        dns_provider="cloudflare",
    ))
    C.save_branding(C.Branding(org_name="KTC Mail", accent="#5b67f1"))
    save_admin_hash(hash_password(ADMIN_PASS))
    save_admin_account({
        "email": ADMIN_EMAIL, "role": "admin",
        "password_hash": hash_password(ADMIN_PASS), "session_version": 0,
    })

    import uvicorn
    from ktc_mail_admin.admin_server import create_app

    # Minimal access log; run in a thread so we can drive the browser.
    class _Quiet(uvicorn.logging.DefaultFormatter):
        pass
    config = uvicorn.Config(
        create_app(), host="127.0.0.1", port=PORT, log_level="warning",
    )
    server = uvicorn.Server(config)
    import threading
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    # wait for the port to accept connections
    import socket
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        print("server did not start")
        return 3

    # Launch headless chromium with remote debugging.
    cdp_dir = work / "chrome-profile"
    cdp_dir.mkdir(exist_ok=True)
    proc = subprocess.Popen(
        [chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
         f"--user-data-dir={cdp_dir}", f"--remote-debugging-port=9222",
         f"--window-size=1280,1600", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", 9222), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            print("chrome remote debugging did not come up")
            return 4

        OUT.mkdir(parents=True, exist_ok=True)
        base = f"http://127.0.0.1:{PORT}"
        node = shutil.which("node") or "node"
        r = subprocess.run(
            [node, str(REPO / "tools" / "screenshot_cdp.mjs"),
             base, str(OUT), ADMIN_EMAIL, ADMIN_PASS],
            capture_output=True, text=True,
        )
        print(r.stdout)
        if r.returncode != 0:
            print("NODE ERROR:", r.stderr)
            return 5
        # The logo is a binary asset, not a UI page — ship the real file
        # rather than a browser screenshot of a PNG (more faithful).
        logo_src = REPO / "src" / "ktc_mail_admin" / "static" / "branding" / "logo.png"
        if logo_src.exists():
            shutil.copy(logo_src, OUT / "branding_logo.png")
            print("copied real logo -> branding_logo.png")
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        server.should_exit = True

    shots = sorted(p.name for p in OUT.glob("*.png"))
    print(f"wrote {len(shots)} screenshots to {OUT}")
    for s in shots:
        print("  -", s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
