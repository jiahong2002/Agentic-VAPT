import os
import asyncio
from playwright.async_api import async_playwright, Page, Dialog


async def navigate(page: Page, url: str) -> dict:
    """Navigate to a URL and return status + headers."""
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        return {
            "ok": True,
            "status": resp.status if resp else 0,
            "headers": dict(resp.headers) if resp else {},
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def fill_and_submit(page: Page, field_selector: str, value: str, submit_selector: str = None) -> str:
    """Fill a field and optionally click submit, return page content."""
    try:
        await page.fill(field_selector, value)
        if submit_selector:
            await page.click(submit_selector)
            await page.wait_for_load_state("domcontentloaded", timeout=8000)
        return await page.content()
    except Exception as e:
        return f"ERROR: {e}"


async def get_page_content(page: Page) -> str:
    """Get full HTML content of current page."""
    try:
        return await page.content()
    except Exception:
        return ""


async def click_element(page: Page, selector: str) -> bool:
    """Click an element by selector."""
    try:
        await page.click(selector, timeout=5000)
        return True
    except Exception:
        return False


async def take_screenshot(page: Page, scan_id: str, step: int, filename_hint: str = "") -> str:
    """Take a screenshot and return the absolute path.

    Using an absolute path ensures compile_report can locate the file regardless
    of which directory the backend process was launched from.
    """
    folder = os.path.abspath(f"screenshots/{scan_id}")
    os.makedirs(folder, exist_ok=True)
    safe_hint = "".join(c if c.isalnum() or c in "-_" else "_" for c in filename_hint)[:40]
    filename = os.path.join(folder, f"step_{step:02d}_{safe_hint}.png")
    await page.screenshot(path=filename, full_page=False)
    return filename


async def fetch_url(url: str, method: str = "GET", data: dict = None) -> dict:
    """Make a simple HTTP request using httpx and return status + body."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            if method.upper() == "POST":
                resp = await client.post(url, data=data or {})
            else:
                resp = await client.get(url)
            return {
                "ok": True,
                "status": resp.status_code,
                "body": resp.text[:3000],
                "headers": dict(resp.headers),
                "final_url": str(resp.url),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def detect_alert(page: Page) -> tuple[bool, str]:
    """Listen for a JS dialog (alert/confirm/prompt) — evidence of XSS."""
    alert_triggered = False
    alert_text = ""

    def on_dialog(dialog: Dialog):
        nonlocal alert_triggered, alert_text
        alert_triggered = True
        alert_text = dialog.message
        asyncio.create_task(dialog.dismiss())

    page.on("dialog", on_dialog)
    await asyncio.sleep(2)  # wait briefly for any triggered alerts
    page.remove_listener("dialog", on_dialog)
    return alert_triggered, alert_text
