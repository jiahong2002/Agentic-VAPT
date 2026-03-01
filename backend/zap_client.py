import os
import time
import logging
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)

ZAP_HOST = os.getenv("ZAP_HOST", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

POLL_INTERVAL = 5  # seconds between status polls
MAX_WAIT = 600     # max 10 minutes per phase


def get_zap() -> ZAPv2:
    return ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_HOST, "https": ZAP_HOST})


def run_spider(target_url: str) -> str:
    """Run ZAP spider and return spider scan ID."""
    zap = get_zap()
    logger.info("Starting ZAP spider on %s", target_url)
    zap.core.new_session(name="vapt_session", overwrite=True)
    scan_id = zap.spider.scan(target_url)
    return str(scan_id)


def wait_for_spider(spider_id: str, on_progress=None) -> None:
    """Block until spider reaches 100%. Calls on_progress(pct: int) at each 10% milestone."""
    zap = get_zap()
    elapsed = 0
    last_reported = -1
    while elapsed < MAX_WAIT:
        status = zap.spider.status(spider_id)
        if not str(status).lstrip('-').isdigit():
            logger.warning("Spider status returned non-numeric value: %s — assuming complete", status)
            if on_progress:
                on_progress(100)
            return
        progress = int(status)
        logger.info("Spider progress: %d%%", progress)
        if on_progress and progress // 10 != last_reported // 10:
            on_progress(progress)
            last_reported = progress
        if progress >= 100:
            return
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
    logger.warning("Spider timed out after %ds", MAX_WAIT)


def get_passive_alerts(target_url: str) -> list[dict]:
    """Return all passive scan alerts for the target URL."""
    zap = get_zap()
    alerts = zap.core.alerts(baseurl=target_url)
    logger.info("Retrieved %d passive alerts", len(alerts))
    return alerts


def run_active_scan(target_url: str, scan_policy: str = "Default Policy") -> str:
    """Start ZAP active scan and return scan ID."""
    zap = get_zap()
    # Fall back to Default Policy if the requested policy doesn't exist
    try:
        scan_id = zap.ascan.scan(
            url=target_url,
            recurse=True,
            inscopeonly=False,
            scanpolicyname=scan_policy,
        )
        if not str(scan_id).lstrip('-').isdigit():
            logger.warning("Active scan with policy '%s' failed (%s), retrying with default", scan_policy, scan_id)
            scan_id = zap.ascan.scan(url=target_url, recurse=True, inscopeonly=False)
    except Exception:
        scan_id = zap.ascan.scan(url=target_url, recurse=True, inscopeonly=False)

    if not str(scan_id).lstrip('-').isdigit():
        raise RuntimeError(f"ZAP active scan failed to start: {scan_id}")

    logger.info("Active scan started with ID %s on %s", scan_id, target_url)
    return str(scan_id)


def wait_for_active_scan(scan_id: str, on_progress=None) -> None:
    """Block until active scan reaches 100%. Calls on_progress(pct: int) at each 10% milestone."""
    zap = get_zap()
    elapsed = 0
    last_reported = -1
    while elapsed < MAX_WAIT:
        status = zap.ascan.status(scan_id)
        if not str(status).lstrip('-').isdigit():
            logger.warning("Active scan status returned non-numeric value: %s — assuming complete", status)
            if on_progress:
                on_progress(100)
            return
        progress = int(status)
        logger.info("Active scan progress: %d%%", progress)
        if on_progress and progress // 10 != last_reported // 10:
            on_progress(progress)
            last_reported = progress
        if progress >= 100:
            return
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
    logger.warning("Active scan timed out after %ds", MAX_WAIT)


def get_active_alerts(target_url: str) -> list[dict]:
    """Return all alerts after active scan (includes active scan findings)."""
    zap = get_zap()
    alerts = zap.core.alerts(baseurl=target_url)
    return alerts


def check_zap_connection() -> bool:
    """Return True if ZAP is reachable."""
    try:
        zap = get_zap()
        zap.core.version()
        return True
    except Exception as exc:
        logger.error("ZAP connection failed: %s", exc)
        return False
