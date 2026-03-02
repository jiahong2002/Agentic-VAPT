import os
from supabase import AsyncClient, create_async_client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL: str = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_ROLE_KEY: str = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

_client: AsyncClient | None = None


async def get_supabase() -> AsyncClient:
    """Return a lazily-initialised async Supabase client (service role)."""
    global _client
    if _client is None:
        _client = await create_async_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _client
