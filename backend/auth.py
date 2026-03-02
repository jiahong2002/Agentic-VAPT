import os
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# ── Config ─────────────────────────────────────────────────────────────────────
# Supabase signs its JWTs with this secret — find it in:
# Supabase Dashboard → Settings → API → JWT Settings → JWT Secret
SUPABASE_JWT_SECRET: str = os.environ["SUPABASE_JWT_SECRET"]
ALGORITHM = "HS256"

# ── Token verification ─────────────────────────────────────────────────────────
def decode_token(token: str) -> str:
    """Verify a Supabase-issued JWT and return the 'sub' claim (user UUID)."""
    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=[ALGORITHM],
            audience="authenticated",   # Supabase sets aud="authenticated"
        )
        sub: Optional[str] = payload.get("sub")
        if sub is None:
            raise ValueError("missing sub")
        return sub
    except JWTError:
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
