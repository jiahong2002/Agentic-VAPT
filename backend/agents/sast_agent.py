import asyncio
import base64
import json
import uuid
from typing import Callable
import httpx
from openai import AsyncOpenAI
from dotenv import load_dotenv
from models import SASTFinding, Severity

load_dotenv()

GITHUB_BASE = "https://api.github.com"

# File extensions considered source code (skip binaries, lock files, assets)
_SOURCE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java", ".go",
    ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt", ".scala", ".lua",
    ".sh", ".bash", ".pl", ".r", ".html", ".htm", ".ejs", ".jinja",
    ".jinja2", ".twig", ".erb", ".sql", ".graphql", ".env.example",
}

# Paths to skip
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", "vendor", "bower_components", "coverage",
}

_client: AsyncOpenAI | None = None


def _get_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        _client = AsyncOpenAI(max_retries=6)
    return _client


def _gh_headers(pat: str) -> dict:
    return {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def validate_repo(pat: str, owner: str, repo: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{GITHUB_BASE}/repos/{owner}/{repo}",
            headers=_gh_headers(pat),
        )
        if r.status_code == 401:
            raise ValueError("Invalid GitHub PAT — authentication failed")
        if r.status_code == 404:
            raise ValueError(f"Repository '{owner}/{repo}' not found or not accessible")
        r.raise_for_status()
        return r.json()


async def get_languages(pat: str, owner: str, repo: str) -> dict[str, int]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{GITHUB_BASE}/repos/{owner}/{repo}/languages",
            headers=_gh_headers(pat),
        )
        r.raise_for_status()
        return r.json()


async def get_file_tree(pat: str, owner: str, repo: str) -> list[str]:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{GITHUB_BASE}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
            headers=_gh_headers(pat),
        )
        r.raise_for_status()
        data = r.json()

    paths = []
    for item in data.get("tree", []):
        if item.get("type") != "blob":
            continue
        path: str = item.get("path", "")
        # Skip unwanted directories
        parts = path.split("/")
        if any(p in _SKIP_DIRS for p in parts[:-1]):
            continue
        # Check extension
        dot = path.rfind(".")
        ext = path[dot:].lower() if dot != -1 else ""
        if ext in _SOURCE_EXTS:
            paths.append(path)
    return paths


async def get_file_content(pat: str, owner: str, repo: str, path: str) -> str:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{GITHUB_BASE}/repos/{owner}/{repo}/contents/{path}",
            headers=_gh_headers(pat),
        )
        if r.status_code == 404:
            return ""
        r.raise_for_status()
        data = r.json()

    content_b64 = data.get("content", "")
    content = base64.b64decode(content_b64).decode(errors="replace")
    # Truncate to 8000 chars to stay within token limits
    if len(content) > 8000:
        content = content[:8000] + "\n... [truncated]"
    return content


async def select_files_for_analysis(
    file_tree: list[str],
    languages: dict[str, int],
) -> list[str]:
    lang_list = ", ".join(sorted(languages.keys(), key=lambda k: -languages[k])[:5]) or "unknown"
    tree_str = "\n".join(file_tree[:300])  # cap at 300 paths for the prompt

    response = await _get_client().chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a security engineer performing a code review. "
                    "Your task is to select the most security-sensitive source files to audit."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"This is a {lang_list} project. Here is the file tree:\n\n"
                    f"{tree_str}\n\n"
                    "Select up to 20 files most likely to contain security vulnerabilities "
                    "(authentication, database queries, file handling, HTTP endpoints, template rendering, "
                    "crypto, secrets, user input handling). "
                    "Return ONLY valid JSON: {\"files\": [\"path1\", \"path2\", ...]}"
                ),
            },
        ],
        response_format={"type": "json_object"},
        max_tokens=512,
    )

    data = json.loads(response.choices[0].message.content or "{}")
    selected = data.get("files", [])
    # Ensure returned paths exist in the actual tree
    tree_set = set(file_tree)
    return [p for p in selected if p in tree_set][:20]


async def analyze_file(
    file_path: str,
    content: str,
    languages: dict[str, int],
) -> list[SASTFinding]:
    if not content.strip():
        return []

    lang_list = ", ".join(sorted(languages.keys(), key=lambda k: -languages[k])[:3]) or "unknown"

    response = await _get_client().chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert security auditor performing static analysis. "
                    "Analyze code for real, exploitable security vulnerabilities only. "
                    "Do NOT report style issues or hypothetical problems. "
                    "For each finding, generate a working unified diff patch to fix the issue."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Language(s): {lang_list}\n"
                    f"File: {file_path}\n\n"
                    f"```\n{content}\n```\n\n"
                    "Find all real security vulnerabilities in this file. "
                    "For each one return a JSON object in this array:\n"
                    "[\n"
                    "  {\n"
                    "    \"title\": \"Short vulnerability name\",\n"
                    "    \"line_number\": 42,\n"
                    "    \"technique\": \"SQL Injection\",\n"
                    "    \"severity\": \"HIGH\",\n"
                    "    \"description\": \"Why this is exploitable\",\n"
                    "    \"code_snippet\": \"the vulnerable line(s)\",\n"
                    "    \"patch\": \"--- a/file\\n+++ b/file\\n@@ ... @@\\n-old\\n+new\",\n"
                    "    \"explanation\": \"What the patch does and why it fixes it\"\n"
                    "  }\n"
                    "]\n"
                    "If no real vulnerabilities exist, return an empty array [].\n"
                    "Return ONLY valid JSON (the array, not wrapped in an object)."
                ),
            },
        ],
        max_tokens=2048,
    )

    raw = (response.choices[0].message.content or "").strip()
    # Strip markdown code fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        return []

    if not isinstance(items, list):
        return []

    findings: list[SASTFinding] = []
    for item in items:
        try:
            severity = Severity(item.get("severity", "MEDIUM").upper())
        except ValueError:
            severity = Severity.MEDIUM

        findings.append(SASTFinding(
            id=str(uuid.uuid4()),
            title=item.get("title", "Unknown vulnerability"),
            file_path=file_path,
            line_number=item.get("line_number"),
            technique=item.get("technique", "Unknown"),
            severity=severity,
            description=item.get("description", ""),
            code_snippet=item.get("code_snippet", ""),
            patch=item.get("patch", ""),
            explanation=item.get("explanation", ""),
        ))

    return findings


async def run_sast_agent(
    pat: str,
    owner: str,
    repo: str,
    push_fn: Callable[[str, dict], None],
) -> list[SASTFinding]:
    """
    Full SAST pipeline:
    1. Validate repo
    2. Get languages + file tree
    3. GPT selects files to analyze
    4. Fetch + analyze each file concurrently (max 5 at once)
    5. Stream findings via push_fn
    """
    await validate_repo(pat, owner, repo)

    languages, file_tree = await asyncio.gather(
        get_languages(pat, owner, repo),
        get_file_tree(pat, owner, repo),
    )

    if not file_tree:
        return []

    selected_files = await select_files_for_analysis(file_tree, languages)
    if not selected_files:
        return []

    all_findings: list[SASTFinding] = []
    sem = asyncio.Semaphore(5)

    async def process_file(path: str):
        async with sem:
            content = await get_file_content(pat, owner, repo, path)
            if not content:
                return
            findings = await analyze_file(path, content, languages)
            for f in findings:
                all_findings.append(f)
                push_fn("sast_finding", f.model_dump())

    await asyncio.gather(*[process_file(p) for p in selected_files])
    return all_findings
