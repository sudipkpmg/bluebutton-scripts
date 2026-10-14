///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 21+
//JAVA_OPTIONS -Djava.net.useSystemProxies=true

/*
 * CMS Blue Button 2.0 (v2) OAuth helper - JBang / Java 21 port of bluebutton_auth.py.
 *
 * Commands
 *   login   [--no-browser] [--browser edge|chrome|firefox|<path>]
 *             Authorization-code flow with PKCE. Opens a browser for the Medicare login,
 *             catches the redirect on a local callback server, saves tokens to the token file.
 *   refresh   Exchange the stored refresh token for a new access token (no browser).
 *   status    Show token expiry, grant expiry and scope (no secrets printed).
 *   fetch   [Resource] [--all-pages] [--out file.json]
 *             GET a FHIR resource (default Patient); refreshes automatically when needed.
 *
 * No external dependencies - JDK 21 only.
 *
 * Configuration (environment variables, or a .env file in the current directory;
 * real environment variables win over .env):
 *   BB_CLIENT_ID, BB_CLIENT_SECRET            (required)
 *   BB_REDIRECT_URI  default http://localhost:8765/callback  (must match the app registration)
 *   BB_BASE_URL      default https://sandbox.bluebutton.cms.gov  (prod: https://api.bluebutton.cms.gov)
 *   BB_TOKEN_FILE    default ./bb_tokens.json
 *   BB_SCOPE         optional, space-separated
 *   BB_BROWSER       optional: edge | chrome | firefox | full path to a browser executable
 *
 * Usage
 *   jbang BlueButtonAuth.java login
 *   jbang BlueButtonAuth.java status
 *   jbang BlueButtonAuth.java fetch ExplanationOfBenefit --all-pages --out eob.json
 *   (or plain Java 21:  java BlueButtonAuth.java login)
 *
 * Sandbox test users: lowercase credentials, e.g. bbuser00000 / pw00000!
 *
 * The 1-hour / 13-month / research access category is assigned by CMS to your app; it is not
 * a request parameter. If a refresh fails with invalid_grant (grant expired, revoked, or the
 * refresh token was already used - tokens rotate), run `login` again.
 */

import com.sun.net.httpserver.HttpServer;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BlueButtonAuth {

    // ------------------------------------------------------------------ configuration

    static final Map<String, String> DOTENV = loadDotenv(Path.of(".env"));

    static final String BASE_URL = stripSlash(env("BB_BASE_URL", "https://sandbox.bluebutton.cms.gov"));
    static final String CLIENT_ID = clean(env("BB_CLIENT_ID", ""));
    static final String CLIENT_SECRET = clean(env("BB_CLIENT_SECRET", ""));
    static final String REDIRECT_URI = env("BB_REDIRECT_URI", "http://localhost:8765/callback");
    static final Path TOKEN_FILE = Path.of(env("BB_TOKEN_FILE", "bb_tokens.json"));
    static final String SCOPE = env("BB_SCOPE", "").trim();
    static String browser = env("BB_BROWSER", "").trim();

    static final String AUTHORIZE_URL = BASE_URL + "/v2/o/authorize/";
    static final String TOKEN_URL = BASE_URL + "/v2/o/token/";
    static final String FHIR_BASE = BASE_URL + "/v2/fhir";

    /** Refresh this many seconds before the access token actually expires. */
    static final long EXPIRY_SKEW = 120;

    static final HttpClient HTTP = HttpClient.newBuilder()
            .proxy(ProxySelector.getDefault())
            .connectTimeout(Duration.ofSeconds(30))
            .build();
    static final SecureRandom RANDOM = new SecureRandom();

    static class AuthError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        AuthError(String m) { super(m); }
    }

    // ------------------------------------------------------------------ main / CLI

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) {
            usage();
            return;
        }
        String cmd = args[0];
        List<String> rest = new ArrayList<>(List.of(args).subList(1, args.length));
        try {
            switch (cmd) {
                case "login" -> {
                    boolean noBrowser = rest.remove("--no-browser");
                    String b = option(rest, "--browser");
                    if (b != null) browser = b;
                    login(noBrowser);
                }
                case "refresh" -> {
                    Map<String, Object> tok = refresh(null);
                    System.out.println("Refreshed. New access token valid for " + asLong(tok.get("expires_in"), 3600) / 60 + " min.");
                    if (tok.get("access_grant_expiration") != null) {
                        System.out.println("Data access grant still expires at " + tok.get("access_grant_expiration") + ".");
                    }
                }
                case "status" -> status();
                case "fetch" -> {
                    boolean allPages = rest.remove("--all-pages");
                    String out = option(rest, "--out");
                    String resource = rest.isEmpty() ? "Patient" : rest.get(0);
                    Object data = allPages ? fetchAllPages(resource) : Json.parse(fhirGet(resource, Map.of()));
                    String text = Json.write(data, true);
                    if (out != null) {
                        Files.writeString(Path.of(out), text);
                        System.out.println("Wrote " + out);
                    } else {
                        System.out.println(text);
                    }
                }
                default -> {
                    System.err.println("Unknown command: " + cmd);
                    usage();
                    System.exit(2);
                }
            }
        } catch (AuthError e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Error: " + e);
            System.exit(1);
        }
    }

    static void usage() {
        System.out.println("""
                CMS Blue Button 2.0 OAuth helper
                  login   [--no-browser] [--browser edge|chrome|firefox|<path>]
                  refresh
                  status
                  fetch   [Resource] [--all-pages] [--out file.json]
                """);
    }

    /** Removes "--name value" from the list and returns value (or null). */
    static String option(List<String> args, String name) {
        int i = args.indexOf(name);
        if (i < 0) return null;
        if (i + 1 >= args.size()) throw new AuthError(name + " needs a value");
        String v = args.get(i + 1);
        args.remove(i + 1);
        args.remove(i);
        return v;
    }

    // ------------------------------------------------------------------ token store

    static void saveTokens(Map<String, Object> tok) throws IOException {
        if (tok.containsKey("expires_in")) {
            tok.put("expires_at", Instant.now().getEpochSecond() + asLong(tok.get("expires_in"), 3600));
        }
        Files.writeString(TOKEN_FILE, Json.write(tok, true));
        try {
            Files.setPosixFilePermissions(TOKEN_FILE, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // e.g. Windows
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> loadTokens() throws IOException {
        if (!Files.exists(TOKEN_FILE)) {
            throw new AuthError("No token file at " + TOKEN_FILE + ". Run `login` first.");
        }
        return (Map<String, Object>) Json.parse(Files.readString(TOKEN_FILE));
    }

    static boolean isExpired(Map<String, Object> tok) {
        return Instant.now().getEpochSecond() >= asLong(tok.get("expires_at"), 0) - EXPIRY_SKEW;
    }

    // ------------------------------------------------------------------ HTTP helpers

    static void requireCreds() {
        if (CLIENT_ID.isEmpty() || CLIENT_SECRET.isEmpty()) {
            throw new AuthError("Set BB_CLIENT_ID and BB_CLIENT_SECRET (environment variables or .env) first.");
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> postForm(String url, Map<String, String> form) {
        String body = form.entrySet().stream()
                .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
                .collect(Collectors.joining("&"));
        String basic = Base64.getEncoder().encodeToString(
                (CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = send(req, url);
        if (resp.statusCode() / 100 != 2) {
            String detail = resp.body() == null ? "" : resp.body();
            String hint = "";
            if (resp.statusCode() == 401 || detail.contains("invalid_client")) {
                hint = "\nHint: invalid_client - check BB_CLIENT_ID/BB_CLIENT_SECRET (sandbox creds don't work in production).";
            } else if (detail.contains("invalid_grant")) {
                hint = "\nHint: invalid_grant - code already used/expired, redirect_uri mismatch, or grant expired.";
            }
            throw new AuthError("Token endpoint returned " + resp.statusCode() + ": " + detail + hint);
        }
        return (Map<String, Object>) Json.parse(resp.body());
    }

    static HttpResponse<String> send(HttpRequest req, String url) {
        try {
            return HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new AuthError("Could not reach " + url + ": " + e
                    + "\nIf you're on a corporate network/VPN, a proxy or TLS inspection may be blocking it "
                    + "(set https.proxyHost/https.proxyPort, or import your corporate CA into the JDK truststore).");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthError("Interrupted");
        }
    }

    // ------------------------------------------------------------------ PKCE

    static String[] makePkcePair() {
        byte[] raw = new byte[64];
        RANDOM.nextBytes(raw);
        String verifier = b64url(raw);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return new String[] {verifier, b64url(digest)};
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    // ------------------------------------------------------------------ browser launch

    static final Map<String, List<String>> WIN_BROWSERS = Map.of(
            "edge", List.of("%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe",
                            "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe"),
            "chrome", List.of("%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe",
                              "%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe",
                              "%LocalAppData%\\Google\\Chrome\\Application\\chrome.exe"),
            "firefox", List.of("%ProgramFiles%\\Mozilla Firefox\\firefox.exe",
                               "%ProgramFiles(x86)%\\Mozilla Firefox\\firefox.exe"));

    static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().startsWith("windows");
    }

    static String expandWinVars(String s) {
        Matcher m = Pattern.compile("%([^%]+)%").matcher(s);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String v = System.getenv(m.group(1));
            m.appendReplacement(sb, Matcher.quoteReplacement(v == null ? m.group(0) : v));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    static boolean start(String... cmd) {
        try {
            new ProcessBuilder(cmd).redirectErrorStream(true).start();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Try hard to open the URL. Honors BB_BROWSER / --browser. */
    static boolean openBrowser(String url) {
        if (!browser.isEmpty()) {
            List<String> candidates = new ArrayList<>();
            String key = browser.toLowerCase();
            if (WIN_BROWSERS.containsKey(key)) {
                WIN_BROWSERS.get(key).forEach(p -> candidates.add(expandWinVars(p)));
                candidates.add(key.equals("edge") ? "msedge" : key); // on PATH (Linux/macOS or PATH entry)
            } else {
                candidates.add(browser); // full path given
            }
            for (String exe : candidates) {
                boolean isPath = exe.contains("\\") || exe.contains("/");
                if ((!isPath || Files.isRegularFile(Path.of(exe))) && start(exe, url)) {
                    return true;
                }
            }
            System.out.println("BB_BROWSER=" + browser + " not found; falling back to the default browser.");
        }
        // rundll32 avoids cmd.exe's special handling of '&' in the URL.
        if (isWindows() && start("rundll32", "url.dll,FileProtocolHandler", url)) return true;
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("mac") && start("open", url)) return true;
        if (!isWindows() && !os.contains("mac") && start("xdg-open", url)) return true;
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                return true;
            }
        } catch (Exception | Error ignored) {
            // headless JVM etc.
        }
        return false;
    }

    // ------------------------------------------------------------------ login flow

    static Map<String, Object> login(boolean noBrowser) throws IOException {
        requireCreds();
        URI redirect = URI.create(REDIRECT_URI);
        String host = redirect.getHost();
        if (!"localhost".equals(host) && !"127.0.0.1".equals(host)) {
            throw new AuthError("BB_REDIRECT_URI must point at localhost for the local callback server.");
        }
        int port = redirect.getPort() == -1 ? 80 : redirect.getPort();
        String callbackPath = stripSlash(redirect.getPath().isEmpty() ? "/" : redirect.getPath());

        byte[] st = new byte[24];
        RANDOM.nextBytes(st);
        String state = b64url(st);
        String[] pkce = makePkcePair();
        String verifier = pkce[0], challenge = pkce[1];
        CompletableFuture<Map<String, String>> callback = new CompletableFuture<>();

        // "localhost" may resolve to IPv4 or IPv6 depending on OS/browser - listen on both.
        List<String> hosts = "localhost".equals(host) ? List.of("127.0.0.1", "::1") : List.of(host);
        List<HttpServer> servers = new ArrayList<>();
        for (String h : hosts) {
            try {
                HttpServer srv = HttpServer.create(new InetSocketAddress(InetAddress.getByName(h), port), 0);
                srv.createContext("/", ex -> {
                    String path = stripSlash(ex.getRequestURI().getPath());
                    if (!path.equals(callbackPath)) { // favicon, preconnects... ignore and keep waiting
                        ex.sendResponseHeaders(404, -1);
                        ex.close();
                        return;
                    }
                    Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
                    boolean ok = q.containsKey("code") && state.equals(q.get("state"));
                    String msg = ok ? "Authorization received. You can close this tab."
                            : "Authorization failed: " + q.getOrDefault("error", "state mismatch") + " "
                              + q.getOrDefault("error_description", "");
                    byte[] html = ("<html><body><h3>" + escapeHtml(msg) + "</h3></body></html>")
                            .getBytes(StandardCharsets.UTF_8);
                    ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                    ex.sendResponseHeaders(ok ? 200 : 400, html.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(html);
                    }
                    callback.complete(q);
                });
                srv.start();
                servers.add(srv);
            } catch (IOException e) {
                if (h.equals(hosts.get(0))) {
                    servers.forEach(s -> s.stop(0));
                    throw new AuthError("Can't listen on " + h + ":" + port + " (" + e.getMessage()
                            + "). Is the port in use? Change BB_REDIRECT_URI (and the app's registered callback).");
                }
                // IPv6 loopback unavailable - fine.
            }
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("state", state);
        params.put("code_challenge", challenge);
        params.put("code_challenge_method", "S256");
        if (!SCOPE.isEmpty()) params.put("scope", SCOPE);
        String url = AUTHORIZE_URL + "?" + params.entrySet().stream()
                .map(e -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(Collectors.joining("&"));

        System.out.println("Redirect URI (must match the app registration exactly): " + REDIRECT_URI);
        System.out.println("\nOpen this URL in a browser ON THIS MACHINE to log in:\n\n" + url + "\n");
        if (!noBrowser && !openBrowser(url)) {
            System.out.println("(Couldn't launch a browser automatically - copy the URL above into Edge, Chrome or Firefox.)");
        }
        System.out.println("Waiting for the login to complete (5 minutes)...");

        Map<String, String> result;
        try {
            result = callback.get(300, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new AuthError("No callback received within 5 minutes.");
        } catch (Exception e) {
            throw new AuthError("Callback failed: " + e);
        } finally {
            servers.forEach(s -> s.stop(0));
        }

        if (result.containsKey("error")) {
            throw new AuthError("Authorization denied: " + result.get("error") + " " + result.getOrDefault("error_description", ""));
        }
        if (!state.equals(result.get("state"))) {
            throw new AuthError("State mismatch in callback.");
        }

        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", result.get("code"));
        form.put("redirect_uri", REDIRECT_URI);
        form.put("code_verifier", verifier);
        form.put("client_id", CLIENT_ID);
        Map<String, Object> tok = postForm(TOKEN_URL, form);
        saveTokens(tok);
        System.out.println("Logged in. Patient ID: " + tok.get("patient") + "  Scope: " + tok.get("scope"));
        if (tok.get("access_grant_expiration") != null) {
            System.out.println("Data access grant expires: " + tok.get("access_grant_expiration"));
        }
        return tok;
    }

    // ------------------------------------------------------------------ refresh

    static Map<String, Object> refresh(Map<String, Object> tok) throws IOException {
        requireCreds();
        if (tok == null) tok = loadTokens();
        Object rt = tok.get("refresh_token");
        if (rt == null || rt.toString().isBlank()) {
            throw new AuthError("No refresh token stored (one-time/1-hour apps can't refresh). Run `login` again.");
        }
        Map<String, Object> fresh;
        try {
            fresh = postForm(TOKEN_URL, Map.of("grant_type", "refresh_token", "refresh_token", rt.toString()));
        } catch (AuthError e) {
            throw new AuthError(e.getMessage() + "\nRefresh failed - the refresh token was already used (tokens rotate), "
                    + "the grant expired (e.g. 13 months), or the enrollee revoked access. Run `login` to reauthorize.");
        }
        // Keep fields the refresh response may omit (e.g. patient); keep old refresh token if none issued.
        Map<String, Object> merged = new LinkedHashMap<>(tok);
        merged.putAll(fresh);
        merged.putIfAbsent("refresh_token", rt);
        saveTokens(merged);
        return merged;
    }

    static Map<String, Object> validToken() throws IOException {
        Map<String, Object> tok = loadTokens();
        return isExpired(tok) ? refresh(tok) : tok;
    }

    // ------------------------------------------------------------------ FHIR calls

    /** GET a FHIR resource (or an absolute URL, for paging); refreshes once on 401. */
    static String fhirGet(String resourceOrUrl, Map<String, String> params) throws IOException {
        Map<String, Object> tok = validToken();
        String url;
        if (resourceOrUrl.startsWith("http")) {
            url = resourceOrUrl;
        } else {
            Map<String, String> query = new LinkedHashMap<>(params);
            Object patient = tok.get("patient");
            if (patient != null) {
                if (resourceOrUrl.equals("ExplanationOfBenefit")) query.putIfAbsent("patient", patient.toString());
                if (resourceOrUrl.equals("Coverage")) query.putIfAbsent("beneficiary", patient.toString());
            }
            url = FHIR_BASE + "/" + resourceOrUrl + "/";
            if (!query.isEmpty()) {
                StringJoiner j = new StringJoiner("&", "?", "");
                query.forEach((k, v) -> j.add(enc(k) + "=" + enc(v)));
                url += j;
            }
        }
        for (int attempt = 1; attempt <= 2; attempt++) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(60))
                    .header("Authorization", "Bearer " + tok.get("access_token"))
                    .header("Accept", "application/fhir+json")
                    .GET().build();
            HttpResponse<String> resp = send(req, url);
            if (resp.statusCode() == 401 && attempt == 1) {
                tok = refresh(tok);
                continue;
            }
            if (resp.statusCode() / 100 != 2) {
                throw new AuthError("FHIR " + resourceOrUrl + " returned " + resp.statusCode() + ": " + resp.body());
            }
            return resp.body();
        }
        throw new AuthError("Unreachable");
    }

    /** Follow Bundle 'next' links and return all entries. */
    @SuppressWarnings("unchecked")
    static List<Object> fetchAllPages(String resource) throws IOException {
        List<Object> entries = new ArrayList<>();
        Map<String, Object> bundle = (Map<String, Object>) Json.parse(fhirGet(resource, Map.of()));
        while (true) {
            Object e = bundle.get("entry");
            if (e instanceof List<?> l) entries.addAll(l);
            String next = null;
            if (bundle.get("link") instanceof List<?> links) {
                for (Object o : links) {
                    if (o instanceof Map<?, ?> m && "next".equals(m.get("relation"))) {
                        next = String.valueOf(m.get("url"));
                    }
                }
            }
            if (next == null) break;
            bundle = (Map<String, Object>) Json.parse(fhirGet(next, Map.of()));
        }
        return entries;
    }

    // ------------------------------------------------------------------ status

    static void status() throws IOException {
        Map<String, Object> tok = loadTokens();
        long remaining = asLong(tok.get("expires_at"), 0) - Instant.now().getEpochSecond();
        System.out.println("Base URL:        " + BASE_URL);
        System.out.println("Patient:         " + tok.get("patient"));
        System.out.println("Scope:           " + tok.get("scope"));
        System.out.println("Access token:    " + (remaining <= 0 ? "expired" : "valid for " + remaining / 60 + " min"));
        Object rt = tok.get("refresh_token");
        System.out.println("Refresh token:   " + (rt != null && !rt.toString().isBlank() ? "present" : "none"));
        if (tok.get("access_grant_expiration") != null) {
            System.out.println("Grant expires:   " + tok.get("access_grant_expiration") + "  (after this, run `login` again)");
        }
    }

    // ------------------------------------------------------------------ small utilities

    static String env(String key, String def) {
        String v = System.getenv(key);
        if (v == null) v = DOTENV.get(key);
        return v == null ? def : v;
    }

    /** Minimal .env loader: KEY=VALUE, optional 'export ', quotes, # comments. */
    static Map<String, String> loadDotenv(Path path) {
        Map<String, String> m = new HashMap<>();
        if (!Files.isRegularFile(path)) return m;
        try {
            for (String raw : Files.readAllLines(path)) {
                String line = raw.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (line.startsWith("export ")) line = line.substring(7).strip();
                int eq = line.indexOf('=');
                if (eq < 0) continue;
                String key = line.substring(0, eq).strip();
                String val = line.substring(eq + 1).strip();
                if (val.length() >= 2 && (val.charAt(0) == '"' || val.charAt(0) == '\'')
                        && val.charAt(val.length() - 1) == val.charAt(0)) {
                    val = val.substring(1, val.length() - 1);
                } else if (val.contains(" #")) {
                    val = val.substring(0, val.indexOf(" #")).strip();
                }
                m.put(key, val);
            }
        } catch (IOException e) {
            System.err.println("Warning: could not read .env: " + e.getMessage());
        }
        return m;
    }

    /** Trim whitespace and surrounding quotes that sneak in when pasting values. */
    static String clean(String s) {
        String t = s.strip();
        if (t.length() >= 2 && (t.charAt(0) == '"' || t.charAt(0) == '\'') && t.charAt(t.length() - 1) == t.charAt(0)) {
            t = t.substring(1, t.length() - 1).strip();
        }
        return t;
    }

    static Map<String, String> parseQuery(String raw) {
        Map<String, String> m = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String pair : raw.split("&")) {
            int i = pair.indexOf('=');
            String k = URLDecoder.decode(i < 0 ? pair : pair.substring(0, i), StandardCharsets.UTF_8);
            String v = i < 0 ? "" : URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
            m.putIfAbsent(k, v);
        }
        return m;
    }

    static long asLong(Object o, long def) {
        if (o == null) return def;
        try {
            return new java.math.BigDecimal(o.toString()).longValue();
        } catch (NumberFormatException e) {
            return def;
        }
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static String stripSlash(String s) {
        return s.length() > 1 && s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    // ------------------------------------------------------------------ minimal JSON (no dependencies)

    /** Number kept as its original text, so values round-trip exactly. */
    record JsonNumber(String raw) {
        @Override public String toString() { return raw; }
    }

    static final class Json {
        private final String s;
        private int i;

        private Json(String s) { this.s = s; }

        static Object parse(String text) {
            Json p = new Json(text);
            p.ws();
            Object v = p.value();
            p.ws();
            if (p.i != p.s.length()) throw p.error("trailing characters");
            return v;
        }

        private Object value() {
            if (i >= s.length()) throw error("unexpected end");
            char c = s.charAt(i);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (peek('}')) { i++; return m; }
            while (true) {
                ws();
                String k = string();
                ws();
                expect(':');
                ws();
                m.put(k, value());
                ws();
                if (peek(',')) { i++; continue; }
                expect('}');
                return m;
            }
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++;
            ws();
            if (peek(']')) { i++; return l; }
            while (true) {
                ws();
                l.add(value());
                ws();
                if (peek(',')) { i++; continue; }
                expect(']');
                return l;
            }
        }

        private String string() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                if (i >= s.length()) throw error("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c != '\\') { b.append(c); continue; }
                char e = s.charAt(i++);
                switch (e) {
                    case '"', '\\', '/' -> b.append(e);
                    case 'b' -> b.append('\b');
                    case 'f' -> b.append('\f');
                    case 'n' -> b.append('\n');
                    case 'r' -> b.append('\r');
                    case 't' -> b.append('\t');
                    case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                    default -> throw error("bad escape \\" + e);
                }
            }
        }

        private JsonNumber number() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            if (start == i) throw error("unexpected character '" + s.charAt(i) + "'");
            return new JsonNumber(s.substring(start, i));
        }

        private Object literal(String word, Object v) {
            if (!s.startsWith(word, i)) throw error("expected " + word);
            i += word.length();
            return v;
        }

        private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
        private boolean peek(char c) { return i < s.length() && s.charAt(i) == c; }
        private void expect(char c) { if (!peek(c)) throw error("expected '" + c + "'"); i++; }
        private AuthError error(String m) { return new AuthError("Invalid JSON at position " + i + ": " + m); }

        static String write(Object v, boolean pretty) {
            StringBuilder b = new StringBuilder();
            write(v, b, pretty, 0);
            return b.toString();
        }

        private static void write(Object v, StringBuilder b, boolean pretty, int depth) {
            switch (v) {
                case null -> b.append("null");
                case String str -> quote(str, b);
                case Boolean bool -> b.append(bool);
                case JsonNumber n -> b.append(n.raw());
                case Number n -> b.append(n);
                case Map<?, ?> m -> {
                    if (m.isEmpty()) { b.append("{}"); return; }
                    b.append('{');
                    boolean first = true;
                    for (Map.Entry<?, ?> e : m.entrySet()) {
                        if (!first) b.append(',');
                        first = false;
                        nl(b, pretty, depth + 1);
                        quote(String.valueOf(e.getKey()), b);
                        b.append(pretty ? ": " : ":");
                        write(e.getValue(), b, pretty, depth + 1);
                    }
                    nl(b, pretty, depth);
                    b.append('}');
                }
                case List<?> l -> {
                    if (l.isEmpty()) { b.append("[]"); return; }
                    b.append('[');
                    for (int k = 0; k < l.size(); k++) {
                        if (k > 0) b.append(',');
                        nl(b, pretty, depth + 1);
                        write(l.get(k), b, pretty, depth + 1);
                    }
                    nl(b, pretty, depth);
                    b.append(']');
                }
                default -> quote(v.toString(), b);
            }
        }

        private static void nl(StringBuilder b, boolean pretty, int depth) {
            if (pretty) b.append('\n').append("  ".repeat(depth));
        }

        private static void quote(String s, StringBuilder b) {
            b.append('"');
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"' -> b.append("\\\"");
                    case '\\' -> b.append("\\\\");
                    case '\n' -> b.append("\\n");
                    case '\r' -> b.append("\\r");
                    case '\t' -> b.append("\\t");
                    default -> {
                        if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                        else b.append(c);
                    }
                }
            }
            b.append('"');
        }
    }
}
