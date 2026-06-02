"""
Garmin Connect client using curl_cffi (Chrome TLS impersonation) for
Cloudflare bypass + the Garmin mobile SSO/OAuth flow for authentication.

Replaces the previous SeleniumBase / undetected-Chrome implementation:
no browser, no chromedriver, no Xvfb, no on-disk Chrome profile.

How it works
------------
* ``curl_cffi`` reproduces a real Chrome TLS fingerprint (JA3/JA4) so
  Cloudflare lets the plain HTTPS requests through — the same trick the
  browser used to provide, minus the ~400 MB of Chrome.
* Authentication uses Garmin's mobile SSO JSON API
  (``sso.garmin.com/mobile/api/login``) to obtain a service ticket, then
  the standard two-step OAuth exchange (OAuth1 ``preauthorized`` →
  OAuth2 ``exchange``) to mint a bearer token.  This is the same flow the
  ``garth`` library uses.
* All data is fetched from ``connectapi.garmin.com`` — the API host that
  backs the web app's ``/gc-api/`` proxy — with the OAuth2 bearer token.
  Every endpoint returns JSON (REST + GraphQL), so **no page rendering /
  SPA / JS engine is ever required**.

OAuth2 tokens are cached to disk and refreshed automatically from the
long-lived OAuth1 token, so subsequent runs skip the interactive login.
"""

import atexit
import base64
import hashlib
import hmac
import json
import logging
import os as _os
import secrets
import signal
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, parse_qsl, quote, urlparse

from curl_cffi import requests as cffi_requests

from .endpoints import (
    activities_search_url,
    activity_detail_endpoints,
    daily_graphql,
    daily_rest,
    full_range_graphql,
    full_range_rest,
    monthly_graphql,
    monthly_rest,
    profile_endpoints,
    profile_graphql,
)

log = logging.getLogger(__name__)

DEFAULT_PROFILE_DIR = Path.home() / ".garmin-client" / "browser_profile"

# ── Hosts ────────────────────────────────────────────────────────
SSO_BASE = "https://sso.garmin.com"
CONNECTAPI_BASE = "https://connectapi.garmin.com"
GRAPHQL_URL = f"{CONNECTAPI_BASE}/graphql-gateway/graphql"

# ── SSO / OAuth flow constants (mirrors garth) ───────────────────
CLIENT_ID = "GCM_ANDROID_DARK"
SERVICE_URL = "https://mobile.integration.garmin.com/gcm/android"
OAUTH_CONSUMER_URL = "https://thegarth.s3.amazonaws.com/oauth_consumer.json"
# Fallback if the S3 consumer manifest is unreachable. These are the
# long-lived public Garmin Connect Mobile OAuth consumer credentials.
OAUTH_CONSUMER_FALLBACK = {
    "consumer_key": "fc3e99d2-118c-44b8-8ae3-03370dde24c0",
    "consumer_secret": "E08WAR897WEy2knn7aFBrvegVAf0AFdWBBF",
}

SSO_SUCCESSFUL = "SUCCESSFUL"
SSO_MFA_REQUIRED = "MFA_REQUIRED"

# Pinned Chrome impersonation target. curl_cffi's bare "chrome" alias can
# float to whichever version ships with the library; we pin a specific
# version for a stable, predictable TLS fingerprint. Override via the
# GARMIN_IMPERSONATE env var if Garmin ever requires a newer fingerprint.
DEFAULT_IMPERSONATE = "chrome131"

# User-Agents per call class (matches garth's proven choices).
SSO_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
)
OAUTH_USER_AGENT = "com.garmin.android.apps.connectmobile"
API_USER_AGENT = "GCM-iOS-5.22.1.4"

SSO_PAGE_HEADERS = {
    "User-Agent": SSO_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}

# Refresh the OAuth2 token this many seconds before it actually expires so
# a long batch never races the expiry.
TOKEN_REFRESH_BUFFER = 120
# Number of concurrent HTTP requests per batch.
DEFAULT_CONCURRENCY = 10
REQUEST_TIMEOUT = 60
DOWNLOAD_TIMEOUT = 120


# ─── OAuth1 signing (RFC 5849, HMAC-SHA1) ────────────────────────


def _pe(value) -> str:
    """RFC 3986 percent-encoding used by OAuth1."""
    return quote(str(value), safe="~")


def oauth1_authorization_header(
    method: str,
    url: str,
    consumer_key: str,
    consumer_secret: str,
    token: Optional[str] = None,
    token_secret: Optional[str] = None,
    body_params: Optional[dict] = None,
    nonce: Optional[str] = None,
    timestamp: Optional[int] = None,
) -> str:
    """Build an ``Authorization: OAuth ...`` header (HMAC-SHA1).

    Query-string params (parsed from ``url``) and form ``body_params`` are
    both folded into the signature base string, per the spec.  ``nonce`` and
    ``timestamp`` are generated when omitted (overridable for tests).
    """
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    params: dict = {}
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        params[k] = v
    if body_params:
        params.update(body_params)

    oauth = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": nonce or secrets.token_hex(16),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(timestamp if timestamp is not None else int(time.time())),
        "oauth_version": "1.0",
    }
    if token:
        oauth["oauth_token"] = token

    all_params = {**params, **oauth}
    encoded = sorted((_pe(k), _pe(v)) for k, v in all_params.items())
    normalized = "&".join(f"{k}={v}" for k, v in encoded)
    base_string = "&".join([method.upper(), _pe(base_url), _pe(normalized)])
    signing_key = f"{_pe(consumer_secret)}&{_pe(token_secret or '')}"
    signature = base64.b64encode(hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()).decode()
    oauth["oauth_signature"] = signature

    return "OAuth " + ", ".join(f'{_pe(k)}="{_pe(v)}"' for k, v in sorted(oauth.items()))


# ─── Token dataclasses ───────────────────────────────────────────


@dataclass
class OAuth1Token:
    oauth_token: str
    oauth_token_secret: str
    mfa_token: Optional[str] = None


@dataclass
class OAuth2Token:
    access_token: str
    refresh_token: str = ""
    token_type: str = "Bearer"
    expires_in: int = 0
    expires_at: int = 0
    refresh_token_expires_in: int = 0
    refresh_token_expires_at: int = 0
    scope: str = ""
    jti: str = ""

    @property
    def expired(self) -> bool:
        return self.expires_at <= time.time() + TOKEN_REFRESH_BUFFER

    def authorization(self) -> str:
        return f"{(self.token_type or 'Bearer').title()} {self.access_token}"


# ─── Process lifecycle ───────────────────────────────────────────


class _ProcessLifecycle:
    """Ensures clean shutdown (token flush) on SIGHUP, SIGTERM, SIGINT, atexit.

    Kept from the SeleniumBase era because the MCP server still relies on
    cleanup firing when an SSH session drops (SIGHUP) — now it just flushes
    the OAuth token cache and closes the HTTP sessions instead of tearing
    down a Chrome profile.
    """

    def __init__(self, cleanup_fn):
        self._cleanup = cleanup_fn
        self._cleaned = False

    def install(self):
        atexit.register(self._on_exit)
        # signal.signal() can only be called from the main thread. When the
        # MCP server runs sync in a ThreadPoolExecutor worker (server.py),
        # this hits a non-main thread and raises ValueError. Skip signal
        # registration in that case — atexit still fires for cleanup. See #35.
        if threading.current_thread() is not threading.main_thread():
            return
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._on_signal)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._on_signal)

    def _on_signal(self, signum, frame):
        self._on_exit()
        sys.exit(128 + signum)

    def _on_exit(self):
        if self._cleaned:
            return
        self._cleaned = True
        try:
            self._cleanup()
        except Exception:
            pass


# ─── Garmin Client ───────────────────────────────────────────────


class GarminClient:
    def __init__(
        self,
        email: str,
        password: str,
        profile_dir: Optional[Path] = None,
        headless: bool = False,
        session_file: Optional[Path] = None,
        **_kwargs,  # absorb legacy engine=/headless= kwargs
    ):
        self.email = email
        self.password = password
        # profile_dir is retained for backward-compat (callers still pass it)
        # and now holds the OAuth token cache instead of a Chrome profile.
        self.profile_dir = profile_dir or DEFAULT_PROFILE_DIR
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        # headless is a no-op now (no browser) but kept in the signature.
        self.headless = headless
        self.session_file = session_file
        self.token_file = session_file or (self.profile_dir / "oauth_tokens.json")

        self.impersonate = _os.environ.get("GARMIN_IMPERSONATE", DEFAULT_IMPERSONATE)
        self._consumer: Optional[dict] = None
        self._oauth1: Optional[OAuth1Token] = None
        self._oauth2: Optional[OAuth2Token] = None
        self._display_name: Optional[str] = None

        self._session: Optional[cffi_requests.Session] = None  # serial use (login/api_fetch/download)
        self._pool = None  # ThreadPoolExecutor for batch fetches (lazy)
        self._tlocal = threading.local()  # per-thread sessions for the pool
        self._pool_sessions: list = []
        self._pool_sessions_lock = threading.Lock()

        self._lifecycle: Optional[_ProcessLifecycle] = None
        self._save_raw_enabled = False

    # ── Sessions ─────────────────────────────────────────────────

    def _new_session(self) -> "cffi_requests.Session":
        return cffi_requests.Session(impersonate=self.impersonate)

    def _serial_session(self) -> "cffi_requests.Session":
        if self._session is None:
            self._session = self._new_session()
        return self._session

    def _pool_session(self) -> "cffi_requests.Session":
        """Thread-local session so pooled workers reuse connections safely."""
        s = getattr(self._tlocal, "session", None)
        if s is None:
            s = self._new_session()
            self._tlocal.session = s
            with self._pool_sessions_lock:
                self._pool_sessions.append(s)
        return s

    def _auth_headers(self) -> dict:
        return {
            "Authorization": self._oauth2.authorization(),
            "User-Agent": API_USER_AGENT,
            "Accept": "application/json",
        }

    # ── Consumer key ─────────────────────────────────────────────

    def _ensure_consumer(self) -> dict:
        if self._consumer:
            return self._consumer
        try:
            r = self._serial_session().get(OAUTH_CONSUMER_URL, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                if data.get("consumer_key") and data.get("consumer_secret"):
                    self._consumer = data
                    return self._consumer
        except Exception as e:
            log.debug("Could not fetch OAuth consumer from S3: %s", e)
        log.debug("Using fallback OAuth consumer credentials")
        self._consumer = dict(OAUTH_CONSUMER_FALLBACK)
        return self._consumer

    # ── Token persistence ────────────────────────────────────────

    def _save_tokens(self) -> None:
        if not (self._oauth1 and self._oauth2):
            return
        payload = {
            "oauth1": asdict(self._oauth1),
            "oauth2": asdict(self._oauth2),
            "saved_at": time.time(),
        }
        try:
            self.token_file.parent.mkdir(parents=True, exist_ok=True)
            fd = _os.open(str(self.token_file), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
            with _os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            log.debug("Saved OAuth tokens to %s", self.token_file)
        except Exception as e:
            log.debug("Could not save tokens: %s", e)

    def _load_tokens(self) -> bool:
        if not self.token_file or not self.token_file.exists():
            return False
        try:
            payload = json.loads(self.token_file.read_text())
            o1 = payload.get("oauth1")
            o2 = payload.get("oauth2")
            if not o1 or not o2:
                return False
            self._oauth1 = OAuth1Token(
                oauth_token=o1["oauth_token"],
                oauth_token_secret=o1["oauth_token_secret"],
                mfa_token=o1.get("mfa_token"),
            )
            known = OAuth2Token.__dataclass_fields__.keys()
            self._oauth2 = OAuth2Token(**{k: v for k, v in o2.items() if k in known})
            log.info("Restored OAuth tokens from %s", self.token_file)
            return True
        except Exception as e:
            log.debug("Could not load tokens (will re-login): %s", e)
            self._oauth1 = None
            self._oauth2 = None
            return False

    # ── Login flow ───────────────────────────────────────────────

    def login(self, timeout_ms: int = 600000) -> bool:
        """Authenticate. Restores a cached session when possible, otherwise
        runs the full SSO + OAuth login. Returns True on success."""
        self._lifecycle = _ProcessLifecycle(self.close)
        self._lifecycle.install()

        # 1. Try to restore a cached session.
        if self._load_tokens():
            try:
                if self._ensure_oauth2() and self._fetch_display_name():
                    print("Already logged in (session restored)")
                    return True
            except Exception as e:
                log.debug("Session restore failed, falling back to login: %s", e)

        # 2. Full interactive login.
        print("Logging in...")
        try:
            ticket = self._sso_get_ticket()
        except Exception as e:
            log.error("SSO login failed: %s", e)
            print(f"Login failed: {e}")
            return False
        if not ticket:
            return False

        try:
            self._complete_oauth(ticket)
        except Exception as e:
            log.error("OAuth exchange failed: %s", e)
            print(f"Login failed during OAuth exchange: {e}")
            return False

        self._save_tokens()
        print("Login successful!")
        if not self._fetch_display_name():
            log.warning("Logged in but could not read social profile")
        return True

    def _sso_get_ticket(self) -> Optional[str]:
        """Run the mobile SSO flow and return a service ticket (ST-...)."""
        sess = self._serial_session()
        login_params = {"clientId": CLIENT_ID, "locale": "en-US", "service": SERVICE_URL}

        # Prime cookies with the sign-in page.
        sess.get(
            f"{SSO_BASE}/mobile/sso/en/sign-in",
            params={"clientId": CLIENT_ID},
            headers={**SSO_PAGE_HEADERS, "Sec-Fetch-Site": "none"},
            timeout=REQUEST_TIMEOUT,
        )

        resp = sess.post(
            f"{SSO_BASE}/mobile/api/login",
            params=login_params,
            headers=SSO_PAGE_HEADERS,
            json={"username": self.email, "password": self.password, "rememberMe": True, "captchaToken": ""},
            timeout=REQUEST_TIMEOUT,
        )
        data = self._json_or_none(resp)
        if data is None:
            print(f"Unexpected login response (HTTP {resp.status_code}). Check credentials.")
            return None

        status = (data.get("responseStatus") or {}).get("type")

        if status == SSO_MFA_REQUIRED:
            mfa_info = data.get("customerMfaInfo") or {}
            mfa_method = mfa_info.get("mfaLastMethodUsed") or "email"
            code = self._prompt_mfa()
            if not code:
                print("MFA required but no code was provided.")
                return None
            resp = sess.post(
                f"{SSO_BASE}/mobile/api/mfa/verifyCode",
                params=login_params,
                headers=SSO_PAGE_HEADERS,
                json={
                    "mfaMethod": mfa_method,
                    "mfaVerificationCode": code,
                    "rememberMyBrowser": True,
                    "reconsentList": [],
                    "mfaSetup": False,
                },
                timeout=REQUEST_TIMEOUT,
            )
            data = self._json_or_none(resp)
            status = (data or {}).get("responseStatus", {}).get("type")

        if status != SSO_SUCCESSFUL:
            msg = (data or {}).get("responseStatus", {}).get("message", status)
            print(f"Login failed: {msg}")
            return None

        ticket = data.get("serviceTicketId")
        if not ticket:
            print("Login succeeded but no service ticket was returned.")
            return None

        # Best-effort embed call (sets a Cloudflare LB cookie).
        try:
            sess.get(
                f"{SSO_BASE}/portal/sso/embed",
                headers={**SSO_PAGE_HEADERS, "Sec-Fetch-Site": "same-origin"},
                timeout=REQUEST_TIMEOUT,
            )
        except Exception:
            pass

        return ticket

    def _prompt_mfa(self) -> Optional[str]:
        """Get an MFA code: env var first (for automation), then console."""
        env_code = _os.environ.get("GARMIN_MFA_CODE")
        if env_code:
            log.info("Using MFA code from GARMIN_MFA_CODE")
            return env_code.strip()
        if sys.stdin.isatty():
            print()
            print("  MFA required!")
            try:
                return input("  Enter MFA code: ").strip()
            except (EOFError, OSError):
                return None
        log.error("MFA required but session is non-interactive (no TTY, no GARMIN_MFA_CODE)")
        print(
            "  MFA required, but this run is non-interactive.\n"
            "  Run `garmin-givemydata` once in a terminal to complete MFA,\n"
            "  or set GARMIN_MFA_CODE before syncing."
        )
        return None

    # ── OAuth exchange ───────────────────────────────────────────

    def _complete_oauth(self, ticket: str) -> None:
        self._oauth1 = self._get_oauth1_token(ticket)
        self._oauth2 = self._exchange_oauth2(self._oauth1, login=True)

    def _get_oauth1_token(self, ticket: str) -> OAuth1Token:
        consumer = self._ensure_consumer()
        url = (
            f"{CONNECTAPI_BASE}/oauth-service/oauth/preauthorized"
            f"?ticket={ticket}&login-url={SERVICE_URL}&accepts-mfa-tokens=true"
        )
        header = oauth1_authorization_header("GET", url, consumer["consumer_key"], consumer["consumer_secret"])
        resp = self._serial_session().get(
            url,
            headers={"User-Agent": OAUTH_USER_AGENT, "Authorization": header},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OAuth1 preauthorized failed: HTTP {resp.status_code} {resp.text[:200]}")
        parsed = {k: v[0] for k, v in parse_qs(resp.text).items()}
        if "oauth_token" not in parsed or "oauth_token_secret" not in parsed:
            raise RuntimeError(f"OAuth1 response missing tokens: {resp.text[:200]}")
        return OAuth1Token(
            oauth_token=parsed["oauth_token"],
            oauth_token_secret=parsed["oauth_token_secret"],
            mfa_token=parsed.get("mfa_token"),
        )

    def _exchange_oauth2(self, oauth1: OAuth1Token, login: bool = False) -> OAuth2Token:
        consumer = self._ensure_consumer()
        url = f"{CONNECTAPI_BASE}/oauth-service/oauth/exchange/user/2.0"
        body: dict = {}
        if login:
            body["audience"] = "GARMIN_CONNECT_MOBILE_ANDROID_DI"
        if oauth1.mfa_token:
            body["mfa_token"] = oauth1.mfa_token
        header = oauth1_authorization_header(
            "POST",
            url,
            consumer["consumer_key"],
            consumer["consumer_secret"],
            token=oauth1.oauth_token,
            token_secret=oauth1.oauth_token_secret,
            body_params=body,
        )
        resp = self._serial_session().post(
            url,
            headers={
                "User-Agent": OAUTH_USER_AGENT,
                "Authorization": header,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=body,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OAuth2 exchange failed: HTTP {resp.status_code} {resp.text[:200]}")
        token = resp.json()
        now = int(time.time())
        token["expires_at"] = now + int(token.get("expires_in", 0))
        token["refresh_token_expires_at"] = now + int(token.get("refresh_token_expires_in", 0))
        known = OAuth2Token.__dataclass_fields__.keys()
        return OAuth2Token(**{k: v for k, v in token.items() if k in known})

    def _ensure_oauth2(self) -> bool:
        """Make sure a valid OAuth2 bearer token is available, refreshing
        from the OAuth1 token when expired. Returns False if not logged in."""
        if self._oauth2 and not self._oauth2.expired:
            return True
        if not self._oauth1:
            return False
        try:
            self._oauth2 = self._exchange_oauth2(self._oauth1, login=False)
            self._save_tokens()
            log.info("Refreshed OAuth2 token")
            return True
        except Exception as e:
            log.warning("OAuth2 refresh failed: %s", e)
            return False

    def _fetch_display_name(self) -> bool:
        data = self.api_fetch("/gc-api/userprofile-service/socialProfile")
        if isinstance(data, dict) and data.get("displayName"):
            self._display_name = data["displayName"]
            log.info("Display name: %s", self._display_name)
            return True
        return False

    # ── URL / response helpers ───────────────────────────────────

    @staticmethod
    def _api_url(api_path: str) -> str:
        """Translate a web ``/gc-api/<service>/...`` path to its
        ``connectapi.garmin.com/<service>/...`` equivalent."""
        if api_path.startswith("http://") or api_path.startswith("https://"):
            return api_path
        path = api_path
        if path.startswith("/gc-api/"):
            path = path[len("/gc-api") :]
        elif path.startswith("gc-api/"):
            path = "/" + path[len("gc-api/") :]
        if not path.startswith("/"):
            path = "/" + path
        return CONNECTAPI_BASE + path

    @staticmethod
    def _json_or_none(resp):
        try:
            return resp.json()
        except Exception:
            return None

    # ── Public API ───────────────────────────────────────────────

    def navigate(self, url: str) -> None:
        """No-op kept for backward compatibility (there is no browser)."""
        return None

    def api_fetch(self, api_path: str):
        """Fetch JSON from a ``/gc-api`` endpoint. Returns parsed JSON or None."""
        if not self._ensure_oauth2():
            return None
        try:
            resp = self._serial_session().get(
                self._api_url(api_path), headers=self._auth_headers(), timeout=REQUEST_TIMEOUT
            )
            if resp.status_code != 200:
                return None
            return self._json_or_none(resp)
        except Exception as e:
            log.debug("api_fetch error for %s: %s", api_path, e)
            return None

    def download_file(self, api_path: str) -> Optional[bytes]:
        """Download a binary file from a ``/gc-api`` endpoint. Returns bytes or None."""
        if not self._ensure_oauth2():
            return None
        try:
            resp = self._serial_session().get(
                self._api_url(api_path), headers=self._auth_headers(), timeout=DOWNLOAD_TIMEOUT
            )
            if resp.status_code == 200 and resp.content:
                return resp.content
            return None
        except Exception as e:
            log.debug("download_file error for %s: %s", api_path, e)
            return None

    # ── Save raw debug data ─────────────────────────────────────

    def _save_raw(self, name: str, data):
        """Save raw JSON response under the ``debug/raw`` directory (next to the token cache)."""
        if not self.profile_dir:
            return
        raw_dir = self.profile_dir.parent / "debug" / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        safe_name = name.replace("/", "_").replace("?", "_").replace("=", "_").replace(":", "_")
        try:
            payload = json.dumps(data, indent=2, sort_keys=True)
            file_path = raw_dir / f"{safe_name}.json"

            if file_path.exists():
                try:
                    if file_path.read_text() == payload:
                        return
                except Exception:
                    pass

                suffix = 2
                while True:
                    candidate = raw_dir / f"{safe_name}__{suffix}.json"
                    if not candidate.exists():
                        file_path = candidate
                        break
                    try:
                        if candidate.read_text() == payload:
                            return
                    except Exception:
                        pass
                    suffix += 1

            file_path.write_text(payload)
        except Exception as e:
            log.debug("Could not save raw data: %s", e)

    # ── Batch fetching ───────────────────────────────────────────

    def _get_pool(self):
        if self._pool is None:
            from concurrent.futures import ThreadPoolExecutor

            self._pool = ThreadPoolExecutor(max_workers=DEFAULT_CONCURRENCY, thread_name_prefix="garmin-fetch")
        return self._pool

    def _fetch_one_rest(self, name: str, api_path: str, headers: dict):
        try:
            resp = self._pool_session().get(self._api_url(api_path), headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = self._json_or_none(resp)
                if data is None:
                    data = resp.text
                return name, {"status": 200, "data": data}
            return name, {"status": resp.status_code, "data": None}
        except Exception as e:
            return name, {"status": "error", "data": str(e)}

    def _fetch_one_gql(self, name: str, query: str, headers: dict):
        key = "gql_" + name
        try:
            resp = self._pool_session().post(
                GRAPHQL_URL,
                headers={**headers, "Content-Type": "application/json"},
                json={"query": query},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                return key, {"status": 200, "data": self._json_or_none(resp)}
            return key, {"status": resp.status_code, "data": None}
        except Exception as e:
            return key, {"status": "error", "data": str(e)}

    def _fetch_batch(self, rest: dict, gql: dict) -> dict:
        """Fetch a batch of REST + GraphQL endpoints in parallel.

        Returns ``{name: {"status": ..., "data": ...}}`` — REST results keyed
        by their name, GraphQL results keyed by ``gql_<name>`` (the contract
        ``save_to_db`` relies on).
        """
        if not self._ensure_oauth2():
            log.warning("_fetch_batch: no valid token")
            return {}

        headers = self._auth_headers()
        pool = self._get_pool()
        futures = []
        for name, api_path in rest.items():
            futures.append(pool.submit(self._fetch_one_rest, name, api_path, headers))
        for name, query in gql.items():
            futures.append(pool.submit(self._fetch_one_gql, name, query, headers))

        result: dict = {}
        for fut in futures:
            try:
                key, value = fut.result()
                result[key] = value
            except Exception as e:
                log.debug("batch task error: %s", e)

        # Save raw payloads and failures for later replay/debugging.
        if self._save_raw_enabled and result:
            for name, res in result.items():
                if res.get("status") == 200 and res.get("data") is not None:
                    self._save_raw(name, res["data"])
                else:
                    self._save_raw(name, res)

        return result

    def _date_chunks(self, start: str, end: str, max_days: int = 28) -> list:
        """Split a date range into chunks of max_days."""
        chunks = []
        s = date.fromisoformat(start)
        e = date.fromisoformat(end)
        while s < e:
            chunk_end = min(s + timedelta(days=max_days), e)
            chunks.append((s.isoformat(), chunk_end.isoformat()))
            s = chunk_end + timedelta(days=1)
        return chunks

    def fetch_all(
        self,
        target_date: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        on_batch=None,
        known_activity_ids: Optional[set] = None,
        save_raw: bool = False,
    ) -> dict:
        """Fetch all data from Garmin Connect.

        Parameters
        ----------
        on_batch : callable, optional
            ``on_batch(endpoint_name, data, cal_date=None)`` called after each
            successful fetch.
        known_activity_ids : set, optional
            Activity IDs that already have detail data (splits, HR zones, weather).
            These will be skipped during per-activity detail fetching.
        save_raw : bool, default False
            Whether to save raw JSON responses under the ``debug/raw`` directory
            (next to the token cache).
        """
        self._save_raw_enabled = save_raw
        today = target_date or date.today().isoformat()
        e_date = end_date or today
        s_date = start_date or (date.fromisoformat(today) - timedelta(days=30)).isoformat()

        all_results = {}
        fetched_activity_ids = []

        def _remember_activity_ids(data):
            if not isinstance(data, list):
                return
            for activity in data:
                if not isinstance(activity, dict):
                    continue
                aid = activity.get("activityId")
                if aid:
                    fetched_activity_ids.append(aid)

        def _process_batch(batch_result, cal_date=None):
            for name, result in batch_result.items():
                if result.get("status") != 200 or not result.get("data"):
                    continue
                if name in ("activities", "activities_range"):
                    _remember_activity_ids(result["data"])
                if on_batch:
                    on_batch(name, result["data"], cal_date=cal_date)
                else:
                    if name not in all_results:
                        all_results[name] = result
                    else:
                        existing = all_results[name].get("data")
                        new = result["data"]
                        all_results[name]["data"] = _merge_data(existing, new)

        # 1. Profile endpoints (no date)
        print("  Fetching profile data...")
        profile = self._fetch_batch(
            profile_endpoints(),
            profile_graphql(self._display_name),
        )
        _process_batch(profile)

        # 2. Full-range queries
        print("  Fetching full-range data (activities, HRV, training, VO2max, weight)...")
        full_rest = full_range_rest(self._display_name, s_date, e_date)
        full_gql = full_range_graphql(self._display_name, s_date, e_date)
        full = self._fetch_batch(full_rest, full_gql)
        _process_batch(full)

        # 2b. Paginate remaining activities within the date range
        page_start = 100
        while True:
            act_result = self._fetch_batch(
                {f"activities_page_{page_start}": activities_search_url(s_date, e_date, offset=page_start)},
                {},
            )
            page_data = act_result.get(f"activities_page_{page_start}", {})
            if page_data.get("status") != 200 or not page_data.get("data"):
                break
            activities_page = page_data["data"]
            if not isinstance(activities_page, list) or len(activities_page) == 0:
                break
            print(f"    Activities page: fetched {len(activities_page)} more (offset {page_start})")
            _remember_activity_ids(activities_page)
            if on_batch:
                for a in activities_page:
                    on_batch("activities", a)
            else:
                for a in activities_page:
                    if "activities" not in all_results:
                        all_results["activities"] = {"status": 200, "data": []}
                    all_results["activities"]["data"].append(a)
            page_start += 100
            if len(activities_page) < 100:
                break

        # 3. Monthly-chunked queries
        print("  Fetching monthly-chunked data (sleep stats, HRV, calories, etc.)...")
        chunks = self._date_chunks(s_date, e_date, max_days=28)
        for i, (cs, ce) in enumerate(chunks):
            print(f"    Chunk {i + 1}/{len(chunks)}: {cs} to {ce}")
            m_rest = monthly_rest(self._display_name, cs, ce)
            m_gql = monthly_graphql(self._display_name, cs, ce)
            chunk_result = self._fetch_batch(m_rest, m_gql)
            _process_batch(chunk_result)

        # 4. Daily-chunked REST + GraphQL
        print("  Fetching daily data (stress, HR, sleep, SpO2, body battery)...")
        all_days = []
        d = date.fromisoformat(s_date)
        end = date.fromisoformat(e_date)
        while d <= end:
            all_days.append(d.isoformat())
            d += timedelta(days=1)

        batch_size = 7
        for i in range(0, len(all_days), batch_size):
            batch_days = all_days[i : i + batch_size]
            print(f"    Days {i + 1}-{i + len(batch_days)}/{len(all_days)}: {batch_days[0]} to {batch_days[-1]}")

            rest_batch = {}
            gql_batch = {}
            for day in batch_days:
                for name, url in daily_rest(self._display_name, day).items():
                    rest_batch[f"{name}_{day}"] = url
                for name, query in daily_graphql(self._display_name, day).items():
                    gql_batch[f"{name}_{day}"] = query

            batch_result = self._fetch_batch(rest_batch, gql_batch)

            for full_name, result in batch_result.items():
                if result.get("status") != 200 or not result.get("data"):
                    continue
                parts = full_name.rsplit("_", 1)
                if len(parts) == 2 and len(parts[1]) == 10 and parts[1][4] == "-":
                    base_name = parts[0]
                    day_date = parts[1]
                else:
                    base_name = full_name
                    day_date = None

                flat = _flatten_single(result["data"])

                if on_batch:
                    on_batch(base_name, flat, cal_date=day_date)
                else:
                    if isinstance(flat, dict):
                        entry = {"date": day_date, **flat}
                    else:
                        entry = {"date": day_date, "value": flat}
                    if base_name not in all_results:
                        all_results[base_name] = {"status": 200, "data": []}
                    existing = all_results[base_name]["data"]
                    if isinstance(existing, list):
                        existing.append(entry)
                    else:
                        all_results[base_name] = {"status": 200, "data": [entry]}

        # 5. Per-activity detail data
        activity_ids = list(dict.fromkeys(fetched_activity_ids))

        if not activity_ids:
            for name_key, result in all_results.items():
                if name_key in ("activities", "activities_range"):
                    data = result.get("data", [])
                    if isinstance(data, list):
                        for a in data:
                            aid = a.get("activityId")
                            if aid:
                                activity_ids.append(aid)

        if not activity_ids and on_batch:
            try:
                act_data = self.api_fetch(activities_search_url(s_date, e_date, limit=1000))
                if isinstance(act_data, list):
                    all_api_ids = [a.get("activityId") for a in act_data if a.get("activityId")]
                    activity_ids = [aid for aid in all_api_ids if aid not in (known_activity_ids or set())]
            except Exception as e:
                log.debug("Could not fetch activity IDs: %s", e)
        elif known_activity_ids:
            activity_ids = [aid for aid in activity_ids if aid not in known_activity_ids]

        if activity_ids:
            print(f"  Fetching per-activity details ({len(activity_ids)} new)...")
            for i, aid in enumerate(activity_ids):
                if i % 10 == 0 and i > 0:
                    print(f"    Activity {i}/{len(activity_ids)}")
                detail_eps = activity_detail_endpoints(aid)
                detail_result = self._fetch_batch(detail_eps, {})
                for ep_name, result in detail_result.items():
                    if result.get("status") != 200 or not result.get("data"):
                        continue
                    if on_batch:
                        on_batch(ep_name, result["data"], cal_date=str(aid))
                    else:
                        all_results[f"{ep_name}_{aid}"] = result

        return all_results

    def export_for_ai(
        self,
        output_path: str = "garmin_data_for_ai.json",
        target_date: Optional[str] = None,
        days: int = 30,
    ) -> Path:
        today = target_date or date.today().isoformat()
        start = (date.fromisoformat(today) - timedelta(days=days)).isoformat()

        raw = self.fetch_all(target_date=today, start_date=start, end_date=today)

        export = {
            "_metadata": {
                "exported_at": datetime.now().isoformat(),
                "target_date": today,
                "date_range": {"start": start, "end": today},
                "display_name": self._display_name,
                "endpoints_ok": sum(1 for v in raw.values() if v.get("status") == 200),
                "endpoints_total": len(raw),
            },
            "data": {},
        }

        for name, result in raw.items():
            if result.get("status") == 200 and result.get("data"):
                data = result["data"]
                if isinstance(data, dict) and "data" in data and len(data) == 1:
                    data = data["data"]
                    if isinstance(data, dict) and len(data) == 1:
                        data = list(data.values())[0]
                export["data"][name] = _remove_nulls(data)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(export, f, indent=2)

        size_mb = path.stat().st_size / 1024 / 1024
        print(f"Exported {len(export['data'])} datasets to {path} ({size_mb:.1f} MB)")
        return path

    # ── Shutdown ─────────────────────────────────────────────────

    def close(self):
        # Persist whatever tokens we ended up with (e.g. after a refresh).
        try:
            self._save_tokens()
        except Exception:
            pass
        if self._pool is not None:
            try:
                self._pool.shutdown(wait=False)
            except Exception:
                pass
            self._pool = None
        with self._pool_sessions_lock:
            sessions = list(self._pool_sessions)
            self._pool_sessions.clear()
        for s in sessions:
            try:
                s.close()
            except Exception:
                pass
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None


# ─── Utility functions ───────────────────────────────────────────


def _merge_data(existing, new):
    """Merge two GraphQL responses (append lists, merge dicts)."""
    if isinstance(existing, dict) and isinstance(new, dict):
        merged = {}
        all_keys = set(list(existing.keys()) + list(new.keys()))
        for k in all_keys:
            if k in existing and k in new:
                merged[k] = _merge_data(existing[k], new[k])
            elif k in existing:
                merged[k] = existing[k]
            else:
                merged[k] = new[k]
        return merged
    if isinstance(existing, list) and isinstance(new, list):
        return existing + new
    return new


def _flatten_single(data):
    """If data is a dict with a single 'data' key wrapping another dict, flatten it."""
    if isinstance(data, dict) and "data" in data and len(data) == 1:
        inner = data["data"]
        if isinstance(inner, dict) and len(inner) == 1:
            return list(inner.values())[0]
        return inner
    return data


def _remove_nulls(obj):
    if isinstance(obj, dict):
        return {k: _remove_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_remove_nulls(item) for item in obj]
    return obj
