#!/usr/bin/env python3
"""
CMS Blue Button 2.0 (v2) OAuth helper — authorization-code flow + refresh loop.

What it does
  1. `login`   : runs the OAuth authorization-code flow (with PKCE) against the
                 Blue Button sandbox (or production), catches the redirect on a
                 local callback server, exchanges the code for tokens, and saves
                 them to a JSON token store.
  2. `refresh` : exchanges the stored refresh token for a new access token.
  3. `fetch`   : calls a FHIR endpoint (default: Patient), refreshing the access
                 token automatically when it is expired or a call returns 401.
  4. `status`  : shows token expiry and scope without printing secrets.

Standard library only (Python 3.9+). No pip installs required.

Setup
  - Register an app in the Blue Button sandbox (https://sandbox.bluebutton.cms.gov).
  - Add the callback URL to the app, exactly as configured below,
    e.g. http://localhost:8765/callback
  - Put credentials in a .env file next to this script (or in the current
    directory) — see .env.example — or export them in your shell. Shell
    variables override .env values:
        export BB_CLIENT_ID=...
        export BB_CLIENT_SECRET=...
    Optional:
        export BB_REDIRECT_URI=http://localhost:8765/callback
        export BB_BASE_URL=https://sandbox.bluebutton.cms.gov   # or https://api.bluebutton.cms.gov
        export BB_TOKEN_FILE=./bb_tokens.json

Usage
  python bluebutton_auth.py login
  python bluebutton_auth.py status
  python bluebutton_auth.py fetch                       # Patient
  python bluebutton_auth.py fetch ExplanationOfBenefit  # any v2 FHIR resource
  python bluebutton_auth.py fetch Coverage --out coverage.json
  python bluebutton_auth.py refresh

Sandbox test users: log in with a synthetic beneficiary in LOWERCASE, e.g.
bbuser00000 / pw00000!  (the mixed-case BBUser00000 / PW00000! shown in some
CMS docs was rejected by the sandbox login with "We can't process your request").
Other synthetic users likely follow the same pattern (bbuser00001 / pw00001!).

Note on grant duration: the 1-hour / 13-month / research access category is
assigned by CMS to your app during production approval — it is not a request
parameter. This script handles whatever category you have: if the refresh token
is rejected (grant expired or revoked), it tells you to run `login` again.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------- configuration

def load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, optional 'export ', quotes, # comments.
    Variables already set in the real environment take precedence."""
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, val = line.partition("=")
        if not sep:
            continue
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        elif " #" in val:
            val = val.split(" #", 1)[0].rstrip()
        os.environ.setdefault(key, val)


# Look for .env next to this script first, then in the current directory.
load_dotenv(Path(__file__).resolve().parent / ".env")
load_dotenv(Path.cwd() / ".env")

BASE_URL = os.environ.get("BB_BASE_URL", "https://sandbox.bluebutton.cms.gov").rstrip("/")
CLIENT_ID = os.environ.get("BB_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("BB_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("BB_REDIRECT_URI", "http://localhost:8765/callback")
TOKEN_FILE = Path(os.environ.get("BB_TOKEN_FILE", "bb_tokens.json"))
# Optional, space-separated, e.g. "openid profile patient/Patient.read patient/ExplanationOfBenefit.read patient/Coverage.read"
SCOPE = os.environ.get("BB_SCOPE", "").strip()
# Optional: edge | chrome | firefox | full path to a browser .exe
BROWSER = os.environ.get("BB_BROWSER", "").strip()
NO_BROWSER = False  # set by `login --no-browser`

AUTHORIZE_URL = f"{BASE_URL}/v2/o/authorize/"
TOKEN_URL = f"{BASE_URL}/v2/o/token/"
FHIR_BASE = f"{BASE_URL}/v2/fhir"

# Refresh this many seconds before the access token actually expires.
EXPIRY_SKEW = 120


class AuthError(Exception):
    pass


# ---------------------------------------------------------------- token store

def save_tokens(tok: dict) -> None:
    """Persist tokens with an absolute expiry time; file is chmod 600."""
    if "expires_in" in tok:
        tok["expires_at"] = int(time.time()) + int(tok["expires_in"])
    TOKEN_FILE.write_text(json.dumps(tok, indent=2))
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass  # e.g. Windows


def load_tokens() -> dict:
    if not TOKEN_FILE.exists():
        raise AuthError(f"No token file at {TOKEN_FILE}. Run `login` first.")
    return json.loads(TOKEN_FILE.read_text())


def is_expired(tok: dict) -> bool:
    return time.time() >= tok.get("expires_at", 0) - EXPIRY_SKEW


# ---------------------------------------------------------------- HTTP helpers

def _basic_auth_header() -> str:
    raw = f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": _basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        hint = ""
        if e.code == 401:
            hint = "\nHint: invalid_client — check BB_CLIENT_ID/BB_CLIENT_SECRET (sandbox creds don't work in production)."
        elif "invalid_grant" in detail:
            hint = "\nHint: invalid_grant — code already used/expired, redirect_uri mismatch, or grant expired."
        raise AuthError(f"Token endpoint returned {e.code}: {detail}{hint}") from None
    except urllib.error.URLError as e:
        raise AuthError(
            f"Could not reach {url}: {e.reason}\n"
            "If you're on a corporate network/VPN, a proxy or TLS inspection may be blocking it "
            "(set HTTPS_PROXY, or SSL_CERT_FILE to your corporate CA bundle)."
        ) from None


def _require_creds() -> None:
    if not CLIENT_ID or not CLIENT_SECRET:
        sys.exit("Set BB_CLIENT_ID and BB_CLIENT_SECRET environment variables first.")


# ---------------------------------------------------------------- PKCE

def make_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


# ---------------------------------------------------------------- browser launch

# Windows browser executables, in the order tried when BB_BROWSER names one.
_WIN_BROWSERS = {
    "edge": [r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
             r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"],
    "chrome": [r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
               r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
               r"%LocalAppData%\Google\Chrome\Application\chrome.exe"],
    "firefox": [r"%ProgramFiles%\Mozilla Firefox\firefox.exe",
                r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"],
}


def open_browser(url: str) -> bool:
    """Try hard to open `url`. Honors BB_BROWSER (edge | chrome | firefox | full path)."""
    import shutil
    import subprocess

    choice = BROWSER.lower()
    candidates: list[str] = []
    if choice:
        if os.path.sep in BROWSER or BROWSER.lower().endswith(".exe"):
            candidates.append(BROWSER)
        else:
            candidates += [os.path.expandvars(p) for p in _WIN_BROWSERS.get(choice, [])]
            exe = {"edge": "msedge"}.get(choice, choice)
            if shutil.which(exe):
                candidates.append(shutil.which(exe))
        for exe in candidates:
            if os.path.isfile(exe):
                try:
                    subprocess.Popen([exe, url])
                    return True
                except OSError:
                    pass
        print(f"BB_BROWSER={BROWSER!r} not found; falling back to the default browser.")

    if os.name == "nt":
        try:
            os.startfile(url)  # type: ignore[attr-defined]  # Windows default browser
            return True
        except OSError:
            pass
        try:
            # 'start' needs an empty title argument; ^& isn't needed when passed as a list.
            subprocess.Popen(["cmd", "/c", "start", "", url], shell=False)
            return True
        except OSError:
            pass
    try:
        return webbrowser.open(url)
    except Exception:
        return False


# ---------------------------------------------------------------- login flow

def login() -> dict:
    _require_creds()
    redirect = urllib.parse.urlparse(REDIRECT_URI)
    if redirect.hostname not in ("localhost", "127.0.0.1"):
        sys.exit("BB_REDIRECT_URI must point at localhost for this script's callback server.")

    state = secrets.token_urlsafe(24)
    verifier, challenge = make_pkce_pair()
    result: dict = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path.rstrip("/") != redirect.path.rstrip("/"):
                # e.g. /favicon.ico or a browser preconnect — ignore and keep waiting
                self.send_response(404)
                self.end_headers()
                return
            qs = urllib.parse.parse_qs(parsed.query)
            result.update({k: v[0] for k, v in qs.items()})
            ok = "code" in result and result.get("state") == state
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            msg = (
                "Authorization received. You can close this tab."
                if ok
                else f"Authorization failed: {result.get('error', 'state mismatch')} "
                f"{result.get('error_description', '')}"
            )
            self.wfile.write(f"<html><body><h3>{msg}</h3></body></html>".encode())
            done.set()

        def log_message(self, *args):  # keep the console quiet
            pass

    # "localhost" can resolve to IPv4 or IPv6 depending on the OS/browser, so
    # listen on both loopback addresses when possible.
    port = redirect.port or 80
    hosts = ["127.0.0.1", "::1"] if redirect.hostname == "localhost" else [redirect.hostname]
    servers = []
    for host in hosts:
        cls = http.server.ThreadingHTTPServer
        if ":" in host:
            cls = type("V6Server", (http.server.ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
        try:
            servers.append(cls((host, port), Handler))
        except OSError as e:
            if host == hosts[0]:
                raise AuthError(f"Can't listen on {host}:{port} ({e}). Is the port in use? "
                                "Change BB_REDIRECT_URI (and the app's registered callback).") from None
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if SCOPE:
        params["scope"] = SCOPE
    url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
    print(f"Redirect URI (must match the app registration exactly): {REDIRECT_URI}")
    print("\nOpen this URL in a browser ON THIS MACHINE to log in:\n\n" + url + "\n")
    if not NO_BROWSER and not open_browser(url):
        print("(Couldn't launch a browser automatically — copy the URL above into Edge, Chrome or Firefox.)")
    print("Waiting for the login to complete (5 minutes)...")

    done.wait(timeout=300)
    for s in servers:
        s.shutdown()
        s.server_close()

    if "error" in result:
        raise AuthError(f"Authorization denied: {result.get('error')} {result.get('error_description', '')}")
    if not result:
        raise AuthError("No callback received within 5 minutes.")
    if result.get("state") != state:
        raise AuthError("State mismatch in callback.")

    tok = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "code": result["code"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
        },
    )
    save_tokens(tok)
    print(f"Logged in. Patient ID: {tok.get('patient')}  Scope: {tok.get('scope')}")
    return tok


# ---------------------------------------------------------------- refresh

def refresh(tok: dict | None = None) -> dict:
    _require_creds()
    tok = tok or load_tokens()
    rt = tok.get("refresh_token")
    if not rt:
        raise AuthError(
            "No refresh token stored (one-time/1-hour apps can't refresh). Run `login` again."
        )
    try:
        new = _post_form(TOKEN_URL, {"grant_type": "refresh_token", "refresh_token": rt})
    except AuthError as e:
        raise AuthError(
            f"{e}\nRefresh failed — the grant has likely expired (e.g. 13 months) or was "
            "revoked by the enrollee. Run `login` to reauthorize."
        ) from None
    # Keep fields the refresh response may omit (e.g. patient), and keep the old
    # refresh token if a new one wasn't issued.
    merged = {**tok, **new}
    merged.setdefault("refresh_token", rt)
    save_tokens(merged)
    return merged


def get_valid_token() -> dict:
    tok = load_tokens()
    return refresh(tok) if is_expired(tok) else tok


# ---------------------------------------------------------------- FHIR calls

def fhir_get(resource: str, params: dict | None = None) -> dict:
    """GET a FHIR resource, refreshing once on 401."""
    tok = get_valid_token()
    query = dict(params or {})
    if resource in ("ExplanationOfBenefit", "Coverage") and "patient" not in query and tok.get("patient"):
        query["patient"] = tok["patient"]
    url = f"{FHIR_BASE}/{resource}/"
    if query:
        url += "?" + urllib.parse.urlencode(query)

    for attempt in (1, 2):
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {tok['access_token']}", "Accept": "application/fhir+json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 401 and attempt == 1:
                tok = refresh(tok)
                continue
            raise AuthError(f"FHIR {resource} returned {e.code}: {e.read().decode(errors='replace')}") from None
    raise AuthError("Unreachable")


def fetch_all_pages(resource: str, params: dict | None = None) -> list[dict]:
    """Follow Bundle 'next' links and return all entries."""
    bundle = fhir_get(resource, params)
    entries = list(bundle.get("entry", []))
    while True:
        nxt = next((l["url"] for l in bundle.get("link", []) if l.get("relation") == "next"), None)
        if not nxt:
            break
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(nxt).query))
        bundle = fhir_get(resource, q)
        entries.extend(bundle.get("entry", []))
    return entries


# ---------------------------------------------------------------- CLI

def cmd_status() -> None:
    tok = load_tokens()
    remaining = int(tok.get("expires_at", 0) - time.time())
    print(f"Base URL:        {BASE_URL}")
    print(f"Patient:         {tok.get('patient')}")
    print(f"Scope:           {tok.get('scope')}")
    print(f"Access token:    {'expired' if remaining <= 0 else f'valid for {remaining // 60} min'}")
    print(f"Refresh token:   {'present' if tok.get('refresh_token') else 'none'}")
    grant = tok.get("access_grant_expiration")
    if grant:
        print(f"Grant expires:   {grant}  (after this, run `login` again)")


def main() -> None:
    p = argparse.ArgumentParser(description="CMS Blue Button 2.0 OAuth helper")
    sub = p.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login", help="Run the authorization-code flow")
    lg.add_argument("--no-browser", action="store_true",
                    help="Just print the login URL; paste it into a browser yourself")
    lg.add_argument("--browser", help="edge | chrome | firefox | path to browser .exe (overrides BB_BROWSER)")
    sub.add_parser("refresh", help="Refresh the access token")
    sub.add_parser("status", help="Show token status")
    f = sub.add_parser("fetch", help="Fetch a FHIR resource (auto-refreshes)")
    f.add_argument("resource", nargs="?", default="Patient")
    f.add_argument("--all-pages", action="store_true", help="Follow Bundle next links")
    f.add_argument("--out", help="Write JSON to this file instead of stdout")
    args = p.parse_args()

    try:
        if args.cmd == "login":
            global NO_BROWSER, BROWSER
            NO_BROWSER = args.no_browser
            if args.browser:
                BROWSER = args.browser
            login()
        elif args.cmd == "refresh":
            tok = refresh()
            print(f"Refreshed. New access token valid for {int(tok['expires_in']) // 60} min.")
            if tok.get("access_grant_expiration"):
                print(f"Data access grant still expires at {tok['access_grant_expiration']}.")
        elif args.cmd == "status":
            cmd_status()
        elif args.cmd == "fetch":
            data = fetch_all_pages(args.resource) if args.all_pages else fhir_get(args.resource)
            text = json.dumps(data, indent=2)
            if args.out:
                Path(args.out).write_text(text)
                print(f"Wrote {args.out}")
            else:
                print(text)
    except AuthError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()