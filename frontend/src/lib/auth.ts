const API_BASE = 'http://localhost:8000';
const TOKEN_KEY = 'pentest_token';
const USER_KEY = 'pentest_user';

// ── Token helpers ──────────────────────────────────────────────────────────────
export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string, username: string): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, username);
  // Sync to cookie so Next.js middleware (server-side) can read it
  document.cookie = `${TOKEN_KEY}=${token}; path=/; max-age=${60 * 60 * 8}; SameSite=Lax`;
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
}

export function getUsername(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(USER_KEY);
}

export function isLoggedIn(): boolean {
  return Boolean(getToken());
}

// ── Authenticated fetch ────────────────────────────────────────────────────────
/**
 * Drop-in replacement for fetch() that:
 * 1. Prepends API_BASE if path starts with /
 * 2. Injects the Authorization header
 * 3. Redirects to /login on 401
 */
export async function apiFetch(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const token = getToken();
  const url = path.startsWith('/') ? `${API_BASE}${path}` : path;

  const headers = new Headers(options.headers ?? {});
  headers.set('Content-Type', 'application/json');
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(url, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    window.location.href = '/login';
  }

  return res;
}

// ── Logout helper ──────────────────────────────────────────────────────────────
export function logout(): void {
  clearToken();
  window.location.href = '/login';
}
