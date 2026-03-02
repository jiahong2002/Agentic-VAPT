import os
from typing import Optional

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# ── JWKS config ────────────────────────────────────────────────────────────────
# Supabase publishes its public signing keys at /.well-known/jwks.json.
# We fetch them once and cache them in-process.
SUPABASE_URL: str = os.environ["SUPABASE_URL"]
_JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
_jwks_keys: list | None = None


def _get_keys() -> list:
    """Fetch and cache the Supabase JWKS public keys."""
    global _jwks_keys
    if _jwks_keys is None:
        res = httpx.get(_JWKS_URL, timeout=10)
        res.raise_for_status()
        _jwks_keys = res.json().get("keys", [])
    return _jwks_keys


# ── Token verification ─────────────────────────────────────────────────────────
def decode_token(token: str) -> str:
    """Verify a Supabase-issued JWT via JWKS and return the 'sub' claim (user UUID)."""
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg", "RS256")

        keys = _get_keys()
        # Match by key ID; fall back to the first key if no kid match
        key_data = next(
            (k for k in keys if k.get("kid") == kid),
            keys[0] if keys else None,
        )
        if not key_data:
            raise JWTError("No JWKS key available")

        payload = jwt.decode(
            token,
            key_data,
            algorithms=[alg],
            audience="authenticated",   # Supabase sets aud="authenticated"
        )
        sub: Optional[str] = payload.get("sub")
        if sub is None:
            raise ValueError("missing sub")
        return sub
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI dependency ─────────────────────────────────────────────────────────
_bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> str:
    """FastAPI dependency — validates the Supabase Bearer token.
    Returns the user's UUID (the JWT 'sub' claim).
    """
    return decode_token(credentials.credentials)
