import asyncio
from models import Hypothesis, AgentResult, ScanState
from agents.exploit_agent import run_exploit_agent
from typing import Callable, Awaitable

# Limit concurrent Playwright browsers and OpenAI API calls.
# 2 keeps rate-limit pressure manageable.
AGENT_CONCURRENCY = 2


async def run_all_exploit_agents(
    hypotheses: list[Hypothesis],
    scan_state: ScanState,
    progress_callback: Callable[[AgentResult], Awaitable[None]] = None,
) -> list[AgentResult]:
    """Spawn exploit agents with bounded concurrency, one per hypothesis."""

    semaphore = asyncio.Semaphore(AGENT_CONCURRENCY)

    async def run_one(h: Hypothesis) -> AgentResult:
        async with semaphore:
            result = await run_exploit_agent(
                hypothesis=h,
                scan_id=scan_state.scan_id,
                base_url=scan_state.target_url,
            )
        if progress_callback:
            await progress_callback(result)
        return result

    results = await asyncio.gather(
        *[run_one(h) for h in hypotheses],
        return_exceptions=True,
    )

    clean_results = []
    for r in results:
        if isinstance(r, Exception):
            continue
        clean_results.append(r)

    return clean_results
