from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from auth import get_current_user
from supabase_client import get_supabase

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


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/signup", response_model=TokenResponse, status_code=201)
async def signup(body: SignupRequest):
    sb = await get_supabase()
    try:
        res = await sb.auth.sign_up({"email": body.email, "password": body.password})
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if res.user is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered or confirmation required",
        )

    # Insert profile row into public.users
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

    # Fetch username from public.users
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

    user_res = await sb.auth.admin.get_user_by_id(current_user_id)
    email = user_res.user.email if user_res.user else ""

    return MeResponse(username=profile.data["username"], email=email)
