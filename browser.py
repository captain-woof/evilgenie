from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth as PlaywrightStealth
import random
import traceback

def createBrowser(downloadsPath: str):
    try:
        contextManager = sync_playwright()
        playwright = contextManager.start()
        browser = playwright.firefox.launch(
            headless=False,
            downloads_path=downloadsPath,
            timeout=0
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
                "width": 1280 + random.randint(10, 50)
            },
            user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
        )
        PlaywrightStealth().apply_stealth_sync(context)

        return (contextManager, playwright, browser, context)
    except Exception as e:
        traceback.print_exception(e)
        return (None, None, None, None)