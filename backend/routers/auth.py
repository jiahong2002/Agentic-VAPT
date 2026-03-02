from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from auth import get_current_user
from supabase_client import get_supabase, SUPABASE_SERVICE_ROLE_KEY

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ── Request / Response models ─────────────────────────────────────────────────
class SignupRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class MeResponse(BaseModel):
    username: str
    email: str


def _reset_postgrest(sb):
    """Restore the shared PostgREST client to service_role.

    sign_up() / sign_in_with_password() mutate supabase-py's internal PostgREST
    auth header to the user's JWT as a side effect. Resetting it ensures all
    subsequent DB calls bypass RLS correctly via the service_role key.
    """
    sb.postgrest.auth(SUPABASE_SERVICE_ROLE_KEY)


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/signup", response_model=TokenResponse, status_code=201)
async def signup(body: SignupRequest):
    sb = await get_supabase()

    try:
        res = await sb.auth.sign_up({"email": body.email, "password": body.password})
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    finally:
        # sign_up() mutates the shared PostgREST auth header to the user's JWT.
        # Reset immediately so the insert below runs as service_role (bypasses RLS).
        _reset_postgrest(sb)

    if res.user is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered or confirmation required",
        )

    if res.session is None:
        # Email confirmation is enabled in Supabase — user must confirm before logging in.
        # Insert the profile row so it exists once they confirm.
        await sb.table("users").insert({
            "id": str(res.user.id),
            "username": body.username,
        }).execute()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please confirm your email before logging in",
        )

    # Insert profile row (service_role — bypasses RLS)
    await sb.table("users").insert({
        "id": str(res.user.id),
        "username": body.username,
    }).execute()

    return TokenResponse(
        access_token=res.session.access_token,
        username=body.username,
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    sb = await get_supabase()
    try:
        res = await sb.auth.sign_in_with_password({
            "email": body.email,
            "password": body.password,
        })
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    finally:
        _reset_postgrest(sb)  # restore service_role after sign_in mutates it

    # Fetch username from public.users (now using service_role again)
    profile = await sb.table("users").select("username").eq("id", str(res.user.id)).maybe_single().execute()
    username = profile.data["username"] if profile.data else body.email

    return TokenResponse(
        access_token=res.session.access_token,
        username=username,
    )


@router.get("/me", response_model=MeResponse)
async def me(current_user_id: str = Depends(get_current_user)):
    sb = await get_supabase()
    profile = await sb.table("users").select("username").eq("id", current_user_id).maybe_single().execute()
    if not profile.data:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        user_res = await sb.auth.admin.get_user_by_id(current_user_id)
        email = user_res.user.email if user_res.user else ""
    except Exception:
        email = ""  # admin API unavailable — return empty email gracefully

    return MeResponse(username=profile.data["username"], email=email)
