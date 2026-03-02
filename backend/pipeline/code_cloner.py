import asyncio
import os
import re
import logging

logger = logging.getLogger(__name__)


async def clone_repo(repo_url: str, pat: str | None, dest_dir: str) -> str:
    """Clone a git repo (shallow, depth=1) into dest_dir. Returns the local path."""
    # Inject PAT into HTTPS URL for private repos
    clone_url = repo_url
    if pat and repo_url.startswith("https://"):
        clone_url = re.sub(r"https://", f"https://{pat}@", repo_url, count=1)

    os.makedirs(dest_dir, exist_ok=True)

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth=1", clone_url, dest_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError("git clone timed out after 120s")

    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {stderr.decode()}")

    logger.info(f"Cloned {repo_url} to {dest_dir}")
    return dest_dir
