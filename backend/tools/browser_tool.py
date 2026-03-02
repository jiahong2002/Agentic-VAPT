import os
import asyncio
from playwright.async_api import async_playwright, Page


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


async def get_page_content(page: Page) -> str:
    """Get full HTML content of current page."""
    try:
        return await page.content()
    except Exception:
        return ""


async def take_screenshot(page: Page, scan_id: str, step: int, filename_hint: str = "") -> str:
    """Take a screenshot, upload to Supabase Storage, return signed URL.

    Falls back to a local path if Supabase Storage is unavailable.
    """
    import tempfile
    from supabase_client import get_supabase

    safe_hint = "".join(c if c.isalnum() or c in "-_" else "_" for c in filename_hint)[:40]
    filename = f"step_{step:02d}_{safe_hint}.png"
    storage_path = f"{scan_id}/{filename}"
    tmp_path = os.path.join(tempfile.gettempdir(), f"{scan_id}_{filename}")

    await page.screenshot(path=tmp_path, full_page=False)

    try:
        sb = await get_supabase()
        with open(tmp_path, "rb") as f:
            await sb.storage.from_("screenshots").upload(
                storage_path, f.read(), {"content-type": "image/png"}
            )
        signed = await sb.storage.from_("screenshots").create_signed_url(storage_path, 604800)
        signed_url = signed.signed_url if hasattr(signed, "signed_url") else signed.get("signedURL", "")
        if signed_url:
            return signed_url
    except Exception:
        pass
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # Fallback: save locally (relative to backend root)
    folder = os.path.join(os.path.dirname(__file__), "..", "screenshots", scan_id)
    folder = os.path.abspath(folder)
    os.makedirs(folder, exist_ok=True)
    local_path = os.path.join(folder, filename)
    await page.screenshot(path=local_path, full_page=False)
    return local_path
