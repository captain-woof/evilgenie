"""
Browser factory for evilgenie.

Launches a Playwright Firefox browser for the attacker to perform the auth
flow in. Name resolution is entirely up to the system (e.g. /etc/hosts).
"""

import random
import traceback

from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth as PlaywrightStealth

FF_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


def createBrowser(downloadsPath: str):
    """Create (playwright, browser, context)."""
    try:
        pw = sync_playwright().start()
        browser = pw.firefox.launch(
            headless=False,
            downloads_path=downloadsPath,
            timeout=0,
        )
        context = browser.new_context(
            color_scheme="dark",
            geolocation={"latitude": 30.229633483214656, "longitude": -97.74997700334794},
            permissions=["geolocation"],
            has_touch=False,
            is_mobile=False,
            java_script_enabled=True,
            locale="en-US",
            timezone_id="America/Chicago",
            default_browser_type="firefox",
            device_scale_factor=1.0,
            viewport={
                "height": 720 + random.randint(10, 50),
                "width": 1280 + random.randint(10, 50),
            },
            user_agent=FF_UA,
            ignore_https_errors=True,
        )
        PlaywrightStealth().apply_stealth_sync(context)
        return (pw, browser, context)
    except Exception as e:
        traceback.print_exception(e)
        return (None, None, None)
