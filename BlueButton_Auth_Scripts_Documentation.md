# CMS Blue Button 2.0 OAuth Helper Scripts

Documentation for `bluebutton_auth.py` (Python), `BlueButtonAuth.java` and `BlueButtonAuthUsingJackson.java` (JBang / Java 21)

Version: October 2026

## 1. Overview

The three scripts are command-line helpers for the CMS Blue Button 2.0 API (version 2, FHIR R4): one in Python and two in Java. They do the same job and share the same commands, configuration and token file:

- **`login`** runs the OAuth 2.0 authorization-code flow with PKCE. The Medicare enrollee (in the sandbox, a synthetic test user) signs in in a browser and approves access. The script receives the redirect on a small local web server and exchanges the authorization code for tokens.
- **`refresh`** exchanges the stored refresh token for a new access token, without a browser.
- **`status`** shows when the access token and the data access grant expire, without printing secrets.
- **`fetch`** calls a FHIR endpoint (`Patient`, `ExplanationOfBenefit`, `Coverage`), refreshing the access token automatically when needed.

Tokens are stored in a JSON file (`bb_tokens.json` by default), so a single browser login can be reused for the whole life of the data access grant (13 months for apps in that category).

| | Python | Java, no dependencies | Java with Jackson |
|---|---|---|---|
| File | `bluebutton_auth.py` | `BlueButtonAuth.java` | `BlueButtonAuthUsingJackson.java` |
| Runtime | Python 3.9 or later | Java 21 or later, via JBang or the plain `java` launcher | Java 21 or later, via JBang |
| Dependencies | Python standard library only | JDK only (small built-in JSON parser) | Jackson Databind 2.18.2, downloaded by JBang |
| Size | about 480 lines | about 815 lines | about 690 lines |

The two Java scripts are identical except for JSON handling. Section 7.1 explains how to choose between them.

## 2. How Blue Button authorization works

Blue Button gives an application access to one enrollee's Medicare claims data. That enrollee must sign in with their Medicare.gov account and approve the sharing, which is why the first step always needs a browser. There is no client-credentials or other headless grant for enrollee data; `authorization_code` is the only grant type Blue Button supports.

### 2.1 Tokens and the grant

| Item | What it is | Lifetime |
|---|---|---|
| Access token | Bearer token sent with every FHIR call | 1 hour (`expires_in: 3600` in the sandbox) |
| Refresh token | Used to get a new access token without a browser | Valid until the grant ends, or until it is used if Blue Button rotates it |
| Data access grant | The enrollee's approval | Set by the app's category (see below); shown as `access_grant_expiration` |

The token response from the sandbox looks like this (values shortened):

```json
{
  "access_token": "6zI8qRai...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "patient/Patient.read patient/ExplanationOfBenefit.read patient/Coverage.read profile openid ...",
  "refresh_token": "0CW0Q1ZF...",
  "patient": "-88888888888888",
  "access_grant_expiration": "2027-11-06T17:24:15Z"
}
```

### 2.2 Data access duration categories

CMS assigns each production application a category during the production access process. It is not a parameter you can request in the OAuth flow.

| Category | Typical use | Behaviour |
|---|---|---|
| 1 hour | One-time-use apps | Authorization lasts 1 hour and cannot be refreshed |
| 13 months | Apps that pull data on an ongoing basis | Refresh tokens work for 13 months; then the user must authorize again |
| Research | IRB-approved research studies | Access does not expire unless revoked; reviewed every 2 years |

The sandbox app used while building these scripts received a 13-month grant (`access_grant_expiration` 13 months after login).

### 2.3 Important rules

- **Refreshing does not extend the grant.** The 13 months count from the login. Refreshing more or less often changes nothing; when the grant ends, run `login` again.
- **You do not need to refresh on a schedule.** Refresh when you need data; the `fetch` command does this for you.
- **Treat refresh tokens as single-use.** CMS lists "reused refresh token" as a cause of `invalid_grant`, so the scripts always save whatever new refresh token Blue Button returns. To confirm the behaviour in your environment, compare `refresh_token` in `bb_tokens.json` before and after a `refresh`.
- **One consumer per login.** Do not refresh the same login from two tools (for example this script and a Postman collection or a service) at the same time; whichever refreshes first can invalidate the other's refresh token.

## 3. Prerequisites

### 3.1 Blue Button sandbox application

1. Create an account and an application in the Blue Button developer sandbox (`https://sandbox.bluebutton.cms.gov`).
2. Register the callback (redirect) URL exactly as the scripts will use it. The default is `http://localhost:8765/callback` (`http`, not `https`, with the same port and path).
3. Choose whether the app collects demographic data. If it does, the token scope includes `patient/Patient.read` and `profile`.
4. Copy the **Client ID** and **Client Secret**.

### 3.2 Runtime

- **Python version:** Python 3.9 or later. No packages to install.
- **Java, no dependencies (`BlueButtonAuth.java`):** Java 21 or later. Either install JBang (`jbang BlueButtonAuth.java ...`) or run the file directly with `java BlueButtonAuth.java ...`. Nothing is downloaded.
- **Java with Jackson (`BlueButtonAuthUsingJackson.java`):** Java 21 or later and JBang. On first run JBang downloads Jackson Databind (and Jackson Core and Annotations) from Maven Central and caches them, so that first run needs access to Maven Central or your company's Maven mirror. The plain `java` launcher can't download dependencies; to run without JBang, put the three Jackson jars on the classpath yourself (see section 5).

### 3.3 Sandbox test users

Sign in with a synthetic beneficiary using **lowercase** credentials, for example `bbuser00000` / `pw00000!`. The mixed-case form `BBUser00000` / `PW00000!` that appears in some CMS material was rejected by the sandbox login page with "We can't process your request at this time." Other synthetic users are believed to follow the same pattern (`bbuser00001` / `pw00001!`), but only `bbuser00000` has been confirmed.

## 4. Configuration

All three scripts read the same settings from environment variables or from a `.env` file. Values set in the real environment take precedence over values in `.env`.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `BB_CLIENT_ID` | Yes | none | Client ID of the Blue Button app |
| `BB_CLIENT_SECRET` | Yes | none | Client secret of the Blue Button app |
| `BB_REDIRECT_URI` | No | `http://localhost:8765/callback` | Callback URL; must match the app registration exactly and point at `localhost` or `127.0.0.1` |
| `BB_BASE_URL` | No | `https://sandbox.bluebutton.cms.gov` | Use `https://api.bluebutton.cms.gov` for production |
| `BB_TOKEN_FILE` | No | `./bb_tokens.json` | Where tokens are stored |
| `BB_SCOPE` | No | none (all scopes the app allows) | Space-separated scopes to request |
| `BB_BROWSER` | No | system default browser | `edge`, `chrome`, `firefox`, or a full path to a browser executable |

### 4.1 The .env file

Example `.env`:

```dotenv
# Keep .env out of git (add it to .gitignore).
BB_CLIENT_ID=your-sandbox-client-id
BB_CLIENT_SECRET=your-sandbox-client-secret

# Optional
BB_REDIRECT_URI=http://localhost:8765/callback
BB_BASE_URL=https://sandbox.bluebutton.cms.gov
BB_TOKEN_FILE=./bb_tokens.json
```

The loader accepts `KEY=VALUE` lines, an optional `export ` prefix, single or double quotes around values, full-line `#` comments, and ` #` comments after unquoted values.

| | Python | Java |
|---|---|---|
| `.env` locations | Folder containing the script, then the current folder | Current folder only |

### 4.2 Setting variables in PowerShell

```powershell
$env:BB_CLIENT_ID="your-client-id"
$env:BB_CLIENT_SECRET="your-client-secret"
```

Variables set this way last only for that PowerShell window.

## 5. Commands

The examples use the Python script. The commands and options are identical in all three versions:

| Version | Command prefix |
|---|---|
| Python | `python bluebutton_auth.py` |
| Java, no dependencies | `jbang BlueButtonAuth.java` or `java BlueButtonAuth.java` |
| Java with Jackson | `jbang BlueButtonAuthUsingJackson.java` |

To run the Jackson version without JBang, add the Jackson jars to the classpath (use `:` instead of `;` on macOS and Linux):

```text
java -cp "jackson-databind.jar;jackson-core.jar;jackson-annotations.jar" BlueButtonAuthUsingJackson.java login
```

### 5.1 login

```text
python bluebutton_auth.py login [--no-browser] [--browser edge|chrome|firefox|<path>]
```

Runs the authorization-code flow and saves the tokens.

| Option | Meaning |
|---|---|
| `--no-browser` | Only print the login URL; paste it into a browser on the same machine yourself |
| `--browser` | Browser to launch; overrides `BB_BROWSER` |

What happens:

1. The script prints the redirect URI it will use and the full authorize URL.
2. It starts a local callback server on the redirect URI's port, listening on both `127.0.0.1` and `::1`.
3. It opens the browser (unless `--no-browser`).
4. You sign in and click allow on the consent page.
5. Blue Button redirects the browser to the callback URL with an authorization code. The browser shows "Authorization received. You can close this tab."
6. The script exchanges the code for tokens, saves them and prints the patient ID and scope. The Java versions also print the grant expiry.

The script waits up to 5 minutes for the callback.

Example output:

```text
Redirect URI (must match the app registration exactly): http://localhost:8765/callback

Open this URL in a browser ON THIS MACHINE to log in:

https://sandbox.bluebutton.cms.gov/v2/o/authorize/?response_type=code&client_id=...

Waiting for the login to complete (5 minutes)...
Logged in. Patient ID: -88888888888888  Scope: patient/Coverage.read patient/Patient.rs ...
```

### 5.2 refresh

```text
python bluebutton_auth.py refresh
```

Exchanges the stored refresh token for a new access token and saves the result. No browser is involved.

```text
Refreshed. New access token valid for 60 min.
Data access grant still expires at 2027-11-06T17:24:15Z.
```

You rarely need to run this yourself, because `fetch` refreshes automatically.

### 5.3 status

```text
python bluebutton_auth.py status
```

Shows the token state without printing any token values.

```text
Base URL:        https://sandbox.bluebutton.cms.gov
Patient:         -88888888888888
Scope:           patient/Coverage.read patient/Patient.rs launch/patient ...
Access token:    valid for 55 min
Refresh token:   present
Grant expires:   2027-11-06T16:31:53Z  (after this, run `login` again)
```

### 5.4 fetch

```text
python bluebutton_auth.py fetch [Resource] [--all-pages] [--out file.json]
```

Calls `GET {BB_BASE_URL}/v2/fhir/{Resource}/` and prints the JSON response, or writes it to a file.

| Argument / option | Meaning |
|---|---|
| `Resource` | `Patient` (default), `ExplanationOfBenefit` or `Coverage` |
| `--all-pages` | Follow the Bundle's `next` links and return all entries as one JSON array |
| `--out` | Write the JSON to this file instead of printing it |

Behaviour:

- For `ExplanationOfBenefit` the script adds `?patient=<patient id>`, and for `Coverage` it adds `?beneficiary=<patient id>`, using the patient ID from the token file.
- Without `--all-pages` you get only the first page of results (a FHIR Bundle).
- With `--all-pages` the output is a JSON array of Bundle entries, not a Bundle.

Examples:

```text
python bluebutton_auth.py fetch Patient
python bluebutton_auth.py fetch Coverage --out coverage.json
python bluebutton_auth.py fetch ExplanationOfBenefit --all-pages --out eob.json
```

## 6. How the scripts work

### 6.1 PKCE and state

For every login the scripts generate:

- a `state` value of 24 random bytes (base64url, 32 characters), checked when the callback arrives, which prevents cross-site request forgery;
- a PKCE `code_verifier` of 64 random bytes (base64url) and a `code_challenge` equal to `BASE64URL(SHA-256(code_verifier))`, sent with `code_challenge_method=S256`. Blue Button requires PKCE and supports only S256.

### 6.2 Token exchange and client authentication

Requests to `/v2/o/token/` are `application/x-www-form-urlencoded` POSTs with HTTP Basic authentication (`client_id:client_secret`).

| Request | Form fields |
|---|---|
| Code exchange (login) | `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, `client_id` |
| Refresh | `grant_type=refresh_token`, `refresh_token` |

### 6.3 Automatic refresh in fetch

Before each FHIR call, `fetch` loads the token file and checks `expires_at`:

1. If the access token has expired, or will expire within 120 seconds, the script refreshes first.
2. It makes the FHIR call with the access token.
3. If Blue Button still returns `401`, the script refreshes once and retries the call.
4. Any other error status is reported with the response body.

### 6.4 Refresh and token rotation

When a refresh succeeds, the script merges the new response into the stored tokens:

- New values (access token, `expires_in`, scope, grant expiry) replace the old ones.
- If the response contains a new `refresh_token`, it replaces the old one; if not, the old one is kept.
- Fields the response leaves out (for example `patient`) are kept.
- `expires_at` is recalculated as the current time plus `expires_in`.

### 6.5 The token file

`bb_tokens.json` holds the latest token response plus one field the scripts add:

| Field | Source | Notes |
|---|---|---|
| `access_token` | Blue Button | Current bearer token |
| `expires_in` | Blue Button | Seconds of validity, normally 3600 |
| `token_type` | Blue Button | `Bearer` |
| `scope` | Blue Button | Granted scopes |
| `refresh_token` | Blue Button | Current refresh token |
| `patient` | Blue Button | FHIR Patient ID of the enrollee |
| `access_grant_expiration` | Blue Button | When the data access grant ends |
| `expires_at` | Script | Access token expiry as Unix time (seconds) |

On macOS and Linux the file is created with owner-only permissions (`600`). On Windows the default folder permissions apply. All three scripts read and write the same format, with the same layout (`"key": value`, two-space indent), so you can switch between them.

### 6.6 The local callback server

- Listens on the port in `BB_REDIRECT_URI`, on both IPv4 and IPv6 loopback, because browsers may resolve `localhost` to either.
- Ignores requests for other paths (such as `/favicon.ico`) and keeps waiting.
- Shows a success or error page in the browser, then shuts down.

### 6.7 Opening the browser

1. If `--browser` or `BB_BROWSER` names Edge, Chrome or Firefox, the script looks in the standard Windows install folders (and on the `PATH`). A full path to an executable is used directly.
2. Otherwise the system default browser is used:
   - Python: `os.startfile` on Windows, then `cmd /c start`, then Python's `webbrowser` module.
   - Java (both versions): `rundll32 url.dll,FileProtocolHandler` on Windows, `open` on macOS, `xdg-open` on Linux, then `java.awt.Desktop`.
3. If nothing works, the script says so; copy the printed URL into a browser on the same machine.

## 7. Differences between the versions

| Area | Python (`bluebutton_auth.py`) | Java, no dependencies (`BlueButtonAuth.java`) | Java with Jackson (`BlueButtonAuthUsingJackson.java`) |
|---|---|---|---|
| Runtime | Python 3.9+ | Java 21+; JBang or plain `java` | Java 21+; JBang (or `java` with Jackson jars on the classpath) |
| JSON handling | `json` module | Built-in minimal parser and writer | Jackson Databind (`ObjectMapper`, `JsonNode`) |
| Decimal numbers in FHIR output | Re-written by Python (for example `1.50` becomes `1.5`) | Kept exactly as received | Kept exactly as received (read as `BigDecimal`, trailing zeros kept) |
| First run | Nothing to download | Nothing to download | JBang downloads Jackson from Maven Central (then cached) |
| `.env` lookup | Script folder, then current folder | Current folder only | Current folder only |
| Quotes/spaces around client ID and secret | Removed only when read from `.env` | Removed from environment variables and `.env` | Removed from environment variables and `.env` |
| Default browser on Windows | `os.startfile`, then `cmd /c start` | `rundll32 url.dll,FileProtocolHandler` (avoids `cmd` treating `&` in the URL as a command separator) | Same as the other Java version |
| Corporate proxy | Uses `HTTPS_PROXY`; CA bundle via `SSL_CERT_FILE` | Uses Windows/system proxy settings when run with JBang (`-Djava.net.useSystemProxies=true`); corporate CA must be in the JDK truststore | Same as the other Java version; JBang's dependency download also needs Maven Central or a mirror reachable |
| Grant expiry after `login` | Not printed (shown by `status`) | Printed | Printed |
| Paging with `--all-pages` | Re-issues the request using the `next` link's query parameters | Calls the `next` link URL directly | Calls the `next` link URL directly |

### 7.1 Choosing between the two Java versions

Both Java scripts have the same commands, options, configuration, token file, output format and error messages, and both passed the same 12-check test suite against a mock Blue Button server. Only the JSON code differs.

| Choose | When |
|---|---|
| `BlueButtonAuth.java` (no dependencies) | You want it to run anywhere Java 21 is installed, without JBang, or on machines that can't reach Maven Central |
| `BlueButtonAuthUsingJackson.java` | You prefer a widely used, well-tested JSON library, already use JBang, can reach Maven Central (or a mirror), or plan to extend the script with more JSON processing |

Why the dependency-free version has its own parser: Java's standard library has no JSON API (unlike Python's `json` module), and the plain `java` source launcher cannot download libraries. The built-in parser is about 150 lines and covers what the script needs: token responses, the token file, and FHIR Bundles. It is strict about valid JSON but has had far less real-world use than Jackson.

## 8. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| Sandbox login page shows "We can't process your request at this time." | Mixed-case test credentials | Use lowercase: `bbuser00000` / `pw00000!` |
| Browser shows a redirect URI mismatch before the login page | Callback URL not registered exactly | Register `BB_REDIRECT_URI` exactly in the sandbox app (scheme, port, path) |
| Browser shows "connection refused" after login | Callback server not reachable | Make sure the script is still running and the browser is on the same machine; check the port isn't blocked |
| "Can't listen on 127.0.0.1:8765 … Is the port in use?" | Another process uses the port | Change `BB_REDIRECT_URI` to another port and update the app registration |
| Browser doesn't open | Launching browsers from a shell is blocked or not supported | Use `--no-browser` and paste the URL, or try `--browser edge` |
| "No callback received within 5 minutes." | Login not completed in time | Run `login` again |
| `invalid_client` (HTTP 401 or 400, "Invalid client_id format") | Client ID or secret missing, wrong, or from another environment | Check `BB_CLIENT_ID` / `BB_CLIENT_SECRET`; sandbox credentials don't work in production |
| `invalid_grant` on refresh | Refresh token already used (rotated), grant expired, or access revoked | Run `login` again |
| `invalid_grant` on login | Code reused or expired, or redirect URI mismatch | Run `login` again; check `BB_REDIRECT_URI` |
| "No token file at bb_tokens.json." | No login yet, or a different working folder or `BB_TOKEN_FILE` | Run `login`, or point `BB_TOKEN_FILE` at the right file |
| SSL / certificate or connection errors | Corporate proxy or TLS inspection | Run off VPN, configure the proxy, or add the corporate CA (`SSL_CERT_FILE` for Python, JDK truststore for Java) |
| `fetch` returns 401 even after refresh | Token revoked or wrong environment | Check `BB_BASE_URL` matches the environment that issued the tokens; run `login` again |
| Jackson version: JBang fails to resolve `com.fasterxml.jackson.core:jackson-databind` | Maven Central blocked or proxied | Configure JBang/Maven to use your company's mirror or proxy, or use `BlueButtonAuth.java` |
| Jackson version: "package com.fasterxml.jackson... does not exist" | Run with plain `java`, which can't download dependencies | Run with `jbang`, or add the Jackson jars to the classpath |
| Java versions: accented characters show as `?` in the console | Console code page isn't UTF-8 | Use `--out file.json` (files are written as UTF-8), or run `chcp 65001` first |

## 9. Security considerations

- **`bb_tokens.json` gives access to a person's Medicare data** for the length of the grant. In production, store it only where the user expects, restrict permissions, and never commit it to source control.
- **The client secret identifies your app.** Keep it in environment variables or a git-ignored `.env`, not in code. Rotate it if it is exposed (for example, pasted into a chat or ticket).
- **The scripts never print token values** in `status`.
- **The callback server only listens on loopback addresses** and stops as soon as the callback arrives.
- **Sandbox data is synthetic**, so mistakes there are low-risk; production data is real protected health information.

## 10. Moving to production

1. Complete the CMS production access process; CMS assigns your app's data access category and issues production credentials.
2. Set `BB_BASE_URL=https://api.bluebutton.cms.gov` and use the production client ID and secret.
3. Register the production callback URL. The scripts' local callback server only works with `localhost` redirect URIs; a hosted application needs its own callback endpoint.
4. Users sign in with their real Medicare.gov accounts.

## 11. Related artifacts

- **Postman collection** with automatic refresh, using the same client credentials and tokens.
- **Quarkus proxy service** (`bluebutton-service`) exposing the six FHIR read and search endpoints, seeded with tokens from these scripts.

The one-consumer rule applies across all of them: only one tool should refresh a given login at a time.

## 12. References

- Blue Button API documentation: https://bluebutton.cms.gov/api-documentation/
- Authorization (OAuth, PKCE, token endpoint): https://bluebutton.cms.gov/api-documentation/authorization/
- Developer sandbox: https://sandbox.bluebutton.cms.gov
- Developer community group: https://groups.google.com/g/developer-group-for-cms-blue-button-api
- JBang: https://www.jbang.dev
- Jackson Databind: https://github.com/FasterXML/jackson-databind
