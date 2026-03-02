import asyncio
import re
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright, Browser, BrowserContext
from models import SurfaceReport


_COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/graphiql",
    "/.well-known/security.txt", "/swagger", "/swagger-ui.html",
    "/swagger/index.html", "/openapi.json", "/api-docs",
    "/admin", "/admin/", "/login", "/register", "/signup",
    "/wp-login.php", "/phpinfo.php", "/.env", "/config.json",
    "/server-status", "/actuator", "/actuator/health",
]


async def crawl(target_url: str, max_depth: int = 2, deep: bool = False) -> SurfaceReport:
    if deep:
        max_depth = 3
    """Crawl the target URL and return a rich surface report."""
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(target_url, 0)]
    discovered_urls: list[str] = []
    forms: list[dict] = []
    cookies_list: list[dict] = []
    headers_captured: dict = {}
    js_endpoints: list[str] = []
    tech_stack: list[str] = []
    notes: list[str] = []

    base_domain = urlparse(target_url).netloc

    async with async_playwright() as p:
        browser: Browser = await p.chromium.launch(headless=True)
        context: BrowserContext = await browser.new_context(
            user_agent="Mozilla/5.0 (compatible; PenTestAgent/1.0)"
        )

        async def process_page(url: str, depth: int):
            nonlocal headers_captured
            if url in visited or depth > max_depth:
                return
            visited.add(url)

            page = await context.new_page()
            try:
                resp = await page.goto(url, wait_until="load", timeout=15000)
                # Give Angular/React/Vue time to bootstrap and render components
                await page.wait_for_timeout(1500)
                if resp and not headers_captured:
                    headers_captured = dict(resp.headers)
                    _detect_tech(headers_captured, tech_stack)

                discovered_urls.append(url)

                # Extract forms
                page_forms = await page.eval_on_selector_all("form", """forms => forms.map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name: i.name, type: i.type, id: i.id, placeholder: i.placeholder
                    }))
                }))""")
                forms.extend([{**f, "source_url": url} for f in page_forms])

                # Extract cookies
                page_cookies = await context.cookies([url])
                for c in page_cookies:
                    if c not in cookies_list:
                        cookies_list.append(dict(c))

                # Extract links
                links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for link in links:
                    parsed = urlparse(link)
                    if parsed.netloc == base_domain and link not in visited:
                        queue.append((link, depth + 1))

                # Extract JS file URLs and API hints
                scripts = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                js_endpoints.extend([s for s in scripts if s not in js_endpoints])

                # Check for inline API references
                page_content = await page.content()
                api_paths = re.findall(r'["\'](/api/[^"\']+)["\']', page_content)
                for ap in api_paths:
                    full = urljoin(target_url, ap)
                    if full not in js_endpoints:
                        js_endpoints.append(full)

                # Page-level notes
                title = await page.title()
                if title:
                    notes.append(f"Page title at {url}: {title}")

            except Exception as e:
                notes.append(f"Error processing {url}: {str(e)[:100]}")
            finally:
                await page.close()

        # BFS crawl
        while queue:
            # Only keep unvisited URLs within max_depth; drop everything else
            batch = [
                (url, depth) for url, depth in queue
                if url not in visited and depth <= max_depth
            ]
            queue = []  # Reset — process_page will repopulate with new discoveries
            if not batch:
                break
            # Process in chunks of 10 concurrent pages
            for i in range(0, len(batch), 10):
                await asyncio.gather(*[process_page(url, depth) for url, depth in batch[i:i + 10]])

        # Deep scan: probe common well-known paths regardless of what the crawler found
        if deep:
            probe_urls = [
                urljoin(target_url, path)
                for path in _COMMON_PATHS
                if urljoin(target_url, path) not in visited
            ]
            for i in range(0, len(probe_urls), 10):
                await asyncio.gather(*[process_page(url, 0) for url in probe_urls[i:i + 10]])

        await browser.close()

    return SurfaceReport(
        target_url=target_url,
        discovered_urls=list(set(discovered_urls)),
        forms=forms,
        cookies=cookies_list,
        headers=headers_captured,
        tech_stack=list(set(tech_stack)),
        js_endpoints=list(set(js_endpoints)),
        notes=notes,
    )


def _detect_tech(headers: dict, tech_stack: list[str]):
    """Fingerprint clean technology names from response headers.

    We only add short, product-level names here (Apache, PHP, …).
    Raw header values like "Server: Apache/2.4.25 (Debian)" are already
    captured as header security findings — repeating them as tech badges
    is redundant and clutters the UI.
    """
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    if "php" in powered_by.lower():
        tech_stack.append("PHP")
    if "express" in powered_by.lower():
        tech_stack.append("Express.js")
    if "asp.net" in powered_by.lower() or "asp.net" in server.lower():
        tech_stack.append("ASP.NET")
    if "nginx" in server.lower():
        tech_stack.append("Nginx")
    if "apache" in server.lower():
        tech_stack.append("Apache")
    if "wordpress" in headers.get("link", "").lower():
        tech_stack.append("WordPress")
