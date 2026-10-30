// cspell:ignore cheq siteverify duid unkeyed
import { CloudFrontHeaders, CloudFrontRequest, CloudFrontRequestResult, CloudFrontResponseResult, CloudFrontResultResponse } from "aws-lambda";
import { createHmac, timingSafeEqual } from "node:crypto";
import { RTIResponse } from "../../core/models/rti-response.model";
import { HttpsClient } from "../../core/services/https-client";
import type { CloudfrontConfig } from "./config";

/** Settings for the example Turnstile challenge, set in config.ts. */
export interface TurnstileSettings {
    /** Site key from the Cloudflare Turnstile dashboard. */
    siteKey: string;
    /** Secret key from the Turnstile dashboard, sent to Cloudflare's siteverify endpoint. */
    secretKey: string;
    /**
     * Signs the `_cq_se` session cookie so it cannot be forged. NOT the Turnstile secret: any long random
     * string, e.g. `openssl rand -hex 32`. Changing it invalidates every session (visitors are challenged again).
     */
    sessionSigningSecret: string;
    /** How long a solved challenge is remembered, in seconds. */
    sessionTtlSeconds: number;
    /**
     * Hostnames the challenge page is served on, e.g. ["www.example.com"]. Optional. Cloudflare reports the hostname
     * a token was solved on (siteverify `hostname`); it must be one of these, and the redirect after the challenge
     * goes there. When unset (or empty) it must equal the request's Host header instead: correct on viewer-request,
     * and on origin-request only when the origin request policy forwards `host`. With a policy that omits it
     * (the `-no-host` policies) the Lambda sees the origin's own domain, so set this list.
     */
    allowedHostnames?: string[];
    /**
     * How the solved widget is sent back. "POST" (default) keeps the Turnstile token out of the URL, browser history,
     * logs and Referer; it needs `IncludeBody: true` on the Lambda@Edge association and POST allowed on the behaviour.
     * "GET" needs nothing but puts the single-use token in the URL. A POST that arrives without a body (IncludeBody
     * off) is answered with a GET form, so visitors still get through while the misconfiguration is logged.
     */
    submitMethod?: "POST" | "GET";
}

const isPlaceholder = (value: string | undefined): boolean => !value || value.trim() === "" || value.trim() === "REPLACE_ME";

/**
 * Accepts `cheq_original_url` only when it is a same-site absolute path (a fragment at the end is fine) (as Akamai's reCAPTCHA challenge does).
 * It arrives as a query parameter, so any link can carry any value. Reflected into `Location` it would turn a
 * PASSED challenge into an open redirect: a strong phishing tool, since the victim really did just prove they
 * are human on the genuine site. `//host` and `/\host` are rejected too: browsers read both as protocol-relative.
 * Returns undefined so the caller falls back to the request URI.
 */
function safeReturnPath(raw: string | null | undefined): string | undefined {
    if (!raw || !raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) {
        return undefined;
    }
    // Browsers strip tab, CR and LF from a URL before parsing it, so "/\t/evil.com" becomes "//evil.com"
    // (protocol-relative). Reject every control character instead of stripping it.
    if (/[\u0000-\u001f\u007f]/.test(raw)) {
        return undefined;
    }
    return raw;
}

const DEFAULT_SESSION_TTL_SECONDS = 300;

// Escapes a value for an HTML text node or a quoted attribute. Every value put into the challenge page goes
// through it: the URI comes from the client, and a raw `"` there would otherwise close the attribute and
// let the rest of the URI inject markup or a script on the customer's site.
const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);

// All cookies of the request. A client (e.g. over HTTP/2) can split them over several Cookie headers.
const requestCookies = (request: CloudFrontRequest): string[] =>
    (request.headers["cookie"] ?? []).map(h => h.value).join(";").split(";").map(c => c.trim()).filter(Boolean);

// The User-Agent the session is bound to ("" when absent, on both the issuing and the validating request).
const userAgentOf = (request: CloudFrontRequest): string => request.headers["user-agent"]?.[0]?.value ?? "";

// The value of the cookie `name` (everything after the first "="), or undefined.
const cookieValue = (cookies: string[], name: string): string | undefined =>
    cookies.find(c => c.startsWith(`${name}=`))?.substring(name.length + 1);

/**
 * Signs a challenge session: HMAC-SHA256 over the expiry, rayId and User-Agent, keyed with `secret`, as 32 hex characters.
 * The User-Agent binds the cookie to the browser that solved the challenge: a `_cq_se` copied into another client
 * (a scraper reusing a human's session) fails unless it also copies the exact User-Agent.
 * Without the key nobody can produce a valid `_cq_se` cookie (the old unkeyed SHA-256 could be computed by anyone).
 * Deliberately NOT bound to the visitor's `_cq_duid`: on a first visit the challenge is solved before the CHEQ tag
 * has set that cookie, so a bound session broke as soon as it appeared and the visitor had to solve the CAPTCHA twice.
 */
function signSession(secret: string, expiresAt: number, rayId: string, userAgent: string): string {
    return createHmac("sha256", secret).update(JSON.stringify(["se", expiresAt, rayId, userAgent])).digest("hex").slice(0, 32);
}

/** Checks a session signature in constant time. The secret is never a placeholder: createTurnstileChallenge refuses one. */
function isValidSessionSignature(secret: string, expiresAt: number, rayId: string, userAgent: string, signature: string): boolean {
    const expected = Buffer.from(signSession(secret, expiresAt, rayId, userAgent));
    const actual = Buffer.from(signature);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/**
 * Builds the example `challenge` and `validateChallenge` callbacks from the settings in config.ts.
 * A factory, not an `import { config }`: config.ts imports this file, so that would be circular.
 *
 * Returns `{}` (and warns) while `siteKey`, `secretKey` or `sessionSigningSecret` is unset or `REPLACE_ME`:
 * the CAPTCHA is then disabled and challenged traffic is forwarded with `x-cheq-rti-result`, instead of
 * showing a broken widget or issuing sessions anyone could forge.
 */
export function createTurnstileChallenge(settings: TurnstileSettings): Pick<CloudfrontConfig, "challenge" | "validateChallenge" | "isChallengeAnswer" | "restoreReferer"> {
    const missing = (["siteKey", "secretKey", "sessionSigningSecret"] as const).filter(k => isPlaceholder(settings[k]));
    if (missing.length > 0) {
        console.warn(`[turnstile] CAPTCHA disabled, not configured: ${missing.join(", ")} (set them in config.ts)`);
        return {};
    }
    // A TTL of 0, a negative or fractional number, NaN or a string would issue sessions that are already expired
    // (every visitor challenged again and again) or a broken Max-Age. Fall back to the default instead.
    const ttlValid = Number.isInteger(settings.sessionTtlSeconds) && settings.sessionTtlSeconds > 0;
    if (!ttlValid) {
        console.warn(`[turnstile] invalid sessionTtlSeconds ${JSON.stringify(settings.sessionTtlSeconds)}, using ${DEFAULT_SESSION_TTL_SECONDS} (set a positive whole number of seconds in config.ts)`);
    }
    const resolved: TurnstileSettings = ttlValid ? settings : { ...settings, sessionTtlSeconds: DEFAULT_SESSION_TTL_SECONDS };
    return {
        challenge: (request, response, addRtiResultHeader) => turnstileChallengeExample(resolved, request, response, addRtiResultHeader),
        validateChallenge: (request, isDebug) => turnstileValidateChallengeExample(resolved, request, isDebug),
        isChallengeAnswer: isTurnstileAnswer,
        restoreReferer: restoreOriginalReferer,
    };
}

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
/** siteverify must answer well inside the viewer-request 5 s limit, which the RTI call (`timeout`) already uses part of. */
const SITEVERIFY_TIMEOUT_MS = 1500;
// The same node:https client as the RTI and logger calls, NOT fetch: on a 128 MB Lambda the first fetch after a
// freeze loads undici and opens a new TLS connection, and an abort during that left fetch's promise unsettled, so
// Node exited and CloudFront answered 503. HttpsClient bounds connect + send + read with one timer, drops
// connections that went stale during a freeze, and retries once on a reset pooled connection.
// Idle connections are closed after 50 s, as for the RTI and logger endpoints. Created on first use, so a deployment
// without the CAPTCHA pays nothing for it.
// A Turnstile token is single-use. In the rare case that HttpsClient retries a request Cloudflare had already
// processed (its idle close crossed our request on the wire), the retry answers timeout-or-duplicate and the visitor
// solves the widget once more on the retry page; nothing is let through.
let siteverifyClient: HttpsClient | undefined;
const getSiteverifyClient = (): HttpsClient => (siteverifyClient ??= new HttpsClient(SITEVERIFY_URL, 50_000));
/** Set on the widget (data-action) and required in the siteverify answer: a token minted for another widget is refused. */
const TURNSTILE_ACTION = "cheq-challenge";

// Every response generated here: never cached (CloudFront caches what an origin-request trigger returns), and no
// Referer from the challenge page or the redirect, whose URLs carry the Turnstile token.
const noStoreHeaders = (): CloudFrontHeaders => ({
    'cache-control': [{ key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate' }],
    'referrer-policy': [{ key: 'Referrer-Policy', value: 'no-referrer' }],
});

// Form field and query names. Prefixed so they cannot collide with the site's own parameters (a shop may well use
// `original_url` or `request_id` itself). `cf-turnstile-response` is the widget's own field name and cannot change.
const TOKEN_FIELD = "cf-turnstile-response";
const PARAM_ORIGINAL_URL = "cheq_original_url";
const PARAM_REQUEST_ID = "cheq_request_id";
/** Marks a POSTed answer in the query: the body may be missing (IncludeBody off), the marker never is. */
const PARAM_ANSWER_MARKER = "cheq_challenge";
/** The challenge's own parameters: never carried into the return URL (a stale copy would nest inside the next one). */
const CHALLENGE_PARAMS = [TOKEN_FIELD, PARAM_ORIGINAL_URL, PARAM_REQUEST_ID, PARAM_ANSWER_MARKER];

// The original Referer. A challenge is a detour: the request that comes back after it can only carry the challenge
// page as Referer (or none, see noStoreHeaders), so a site that reads the Referer (attribution, affiliate tracking,
// redirects back to where the visitor came from) would see every challenged visitor as coming from itself. The
// challenge page therefore stores the Referer of the request it interrupted in the `_cq_ref` cookie, together with
// the URL it belongs to, and `restoreOriginalReferer` puts it back on that URL's next request before RTI and the
// origin see it. The cookie is readable by the page's own scripts on purpose (no HttpOnly): `document.referrer`
// cannot be restored by anyone, so a front end that needs the original source reads it from there.
const REFERER_COOKIE = "_cq_ref";
/** Time the visitor has to solve the challenge before the carried Referer is forgotten. */
const REFERER_COOKIE_TTL_SECONDS = 1800;
/** After a solved challenge the cookie only has to survive the redirect back to the page. */
const REFERER_COOKIE_AFTER_ANSWER_SECONDS = 120;
const MAX_REFERER_LENGTH = 2048;
const MAX_REFERER_COOKIE_LENGTH = 3800;

/** An absolute http(s) URL without whitespace or control characters, at most MAX_REFERER_LENGTH; else undefined. */
const validReferer = (value: string | undefined): string | undefined =>
    value !== undefined && value.length <= MAX_REFERER_LENGTH && /^https?:\/\/[^\s\u0000-\u001f\u007f]+$/i.test(value) ? value : undefined;

/** The Referer header of the request, when it is a usable URL. */
const originalRefererOf = (request: CloudFrontRequest): string | undefined => validReferer(request.headers["referer"]?.[0]?.value);

/** The Set-Cookie value that carries `referer` for `returnPath`, or undefined when it would not fit in a cookie. */
function refererCookieHeader(returnPath: string, referer: string, maxAge: number): string | undefined {
    const value = `${REFERER_COOKIE}=${encodeURIComponent(returnPath)}|${encodeURIComponent(referer)}`;
    return value.length <= MAX_REFERER_COOKIE_LENGTH ? `${value}; Path=/; Secure; SameSite=Lax; Max-Age=${maxAge}` : undefined;
}

/** The `_cq_ref` cookie of the request, decoded and validated; undefined when absent or malformed. */
function refererCookieOf(request: CloudFrontRequest): { path: string; referer: string } | undefined {
    const raw = cookieValue(requestCookies(request), REFERER_COOKIE);
    const separator = raw?.indexOf("|") ?? -1;
    if (raw === undefined || separator < 1) return undefined;
    try {
        const path = safeReturnPath(decodeURIComponent(raw.substring(0, separator)));
        const referer = validReferer(decodeURIComponent(raw.substring(separator + 1)));
        return path && referer ? { path, referer } : undefined;
    } catch {
        return undefined; // not valid percent-encoding
    }
}

/**
 * Puts the Referer of the request that was challenged back on the request that follows the challenge, so RTI and the
 * origin see where the visitor really came from. Applies only to the URL the challenge was served for (carried in
 * `_cq_ref`), and only when the request has no Referer or names the page itself (which is what a browser sends after
 * the challenge, or on a reload). A Referer from another page is left alone. Returns whether the header was set.
 */
export function restoreOriginalReferer(request: CloudFrontRequest): boolean {
    const carried = refererCookieOf(request);
    if (!carried) return false;
    const current = pathWithQuery(request);
    if (carried.path !== current) return false;
    const referer = request.headers["referer"]?.[0]?.value;
    const host = request.headers["host"]?.[0]?.value;
    if (referer && referer !== (host ? `https://${host}${current}` : referer)) return false;
    request.headers["referer"] = [{ key: "Referer", value: carried.referer }];
    return true;
}

// The name of a raw "name=value" query pair, decoded; the raw name when it is not valid percent-encoding.
const queryPairName = (pair: string): string => {
    const name = pair.split("=")[0];
    try { return decodeURIComponent(name.replace(/\+/g, " ")); } catch { return name; }
};

/**
 * The request path with its query string exactly as the visitor sent it (percent-encoding, `+`, duplicate names and
 * order untouched), minus the challenge's own parameters. Re-serialising through URLSearchParams would re-encode
 * values (space → +) and some origins read those differently.
 */
const pathWithQuery = (request: CloudFrontRequest): string => {
    const kept = (request.querystring || "").split("&").filter((pair) => pair !== "" && !CHALLENGE_PARAMS.includes(queryPairName(pair)));
    return kept.length > 0 ? `${request.uri}?${kept.join("&")}` : request.uri;
};

/** What a request carries of a solved challenge. */
interface ChallengeAnswer {
    token: string | undefined;
    originalUrl: string | null;
    viaPost: boolean;
    /** The form was POSTed but CloudFront passed no body: IncludeBody is off on the Lambda association. */
    bodyMissing: boolean;
}

/**
 * True for a request that carries a solved challenge: our form marks it `cheq_challenge=1` (in the action query for a
 * POST, as a hidden field for a GET). A GET must also carry a non-empty token: a link that merely contains
 * `cf-turnstile-response=` (a customer's own Turnstile form, a crafted link) is an ordinary request, not an answer.
 * The handler passes an answer to `challenge` whatever the verdict, so a stray form submission never reaches the origin.
 */
export function isTurnstileAnswer(request: CloudFrontRequest): boolean {
    const query = new URLSearchParams(request.querystring);
    if (!query.has(PARAM_ANSWER_MARKER)) {
        return false;
    }
    if (request.method === "GET") {
        return (query.get(TOKEN_FIELD) ?? "") !== "";
    }
    return request.method === "POST";
}

/** Reads the answer from the POST body (form-urlencoded, base64 from CloudFront) or, for a GET, from the query. */
function readAnswer(request: CloudFrontRequest): ChallengeAnswer {
    const query = new URLSearchParams(request.querystring);
    if (request.method === "POST" && query.has(PARAM_ANSWER_MARKER)) {
        const body = request.body;
        if (body === undefined) {
            // CloudFront passed no body object at all: IncludeBody is off on the association. (An empty body is a
            // plain POST without a token, e.g. a bot's `curl -X POST`, and is handled like a missing token below.)
            // The return URL is also in the form's action query, so it survives a missing body.
            return { token: undefined, originalUrl: query.get(PARAM_ORIGINAL_URL), viaPost: true, bodyMissing: true };
        }
        const text = body.encoding === "base64" ? Buffer.from(body.data ?? "", "base64").toString("utf8") : (body.data ?? "");
        const form = new URLSearchParams(text);
        return { token: form.get(TOKEN_FIELD) ?? undefined, originalUrl: form.get(PARAM_ORIGINAL_URL) ?? query.get(PARAM_ORIGINAL_URL), viaPost: true, bodyMissing: false };
    }
    if (!query.has(PARAM_ANSWER_MARKER)) {
        // Not our form (a stale or crafted link): nothing to read, every cheq_ parameter is just stripped later.
        return { token: undefined, originalUrl: null, viaPost: false, bodyMissing: false };
    }
    return { token: query.get(TOKEN_FIELD) || undefined, originalUrl: query.get(PARAM_ORIGINAL_URL), viaPost: false, bodyMissing: false };
}

/** The configured hostname allow-list, or undefined when unset or empty. */
const allowedHostnamesOf = (settings: TurnstileSettings): string[] | undefined =>
    settings.allowedHostnames && settings.allowedHostnames.length > 0 ? settings.allowedHostnames : undefined;

type SiteverifyResult = { success: boolean; hostname?: string; action?: string; "error-codes"?: string[] };

/** Calls Cloudflare siteverify. Throws on a network error, a timeout, a non-2xx answer or a body that is not JSON. */
async function siteverify(settings: TurnstileSettings, token: string, clientIp: string): Promise<SiteverifyResult> {
    // siteverify accepts a JSON body as well as a form; HttpsClient posts JSON.
    const res = await getSiteverifyClient().post(JSON.stringify({ secret: settings.secretKey, response: token, remoteip: clientIp }), SITEVERIFY_TIMEOUT_MS);
    if (res.status < 200 || res.status >= 300) {
        throw new Error(`siteverify answered HTTP ${res.status}`);
    }
    return JSON.parse(res.body) as SiteverifyResult;
}

/**
 * The 403 challenge page with the Turnstile widget. `returnPath` (path + query) is where the visitor goes once solved;
 * `errorMessage` is shown above the widget after a failed verification, so the visitor can simply try again.
 */
/**
 * Options for the challenge page: an error to show above the widget, the form method (default: settings.submitMethod),
 * and the Referer of the interrupted request, carried in `_cq_ref` so it can be restored once the challenge is solved.
 */
interface ChallengePageOptions { errorMessage?: string; method?: "POST" | "GET"; originalReferer?: string }

function challengePage(settings: TurnstileSettings, uri: string, returnPath: string, rayId: string, options: ChallengePageOptions = {}): CloudFrontResultResponse {
    const method = options.method ?? settings.submitMethod ?? "POST";
    const errorMessage = options.errorMessage;
    // A POST form is marked in the action query and also carries the return URL there, so both survive a missing body.
    // A GET form must have no query in its action: the browser replaces it with the fields.
    const formAction = method === "POST" ? `${uri}?${PARAM_ANSWER_MARKER}=1&${PARAM_ORIGINAL_URL}=${encodeURIComponent(returnPath)}` : uri;
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title>Security verification</title>
<link rel="preconnect" href="https://challenges.cloudflare.com">
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        -webkit-font-smoothing: antialiased;
        background: #f4f5f7;
        color: #1f2937;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 24px 16px;
    }
    .card {
        width: 100%;
        max-width: 440px;
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 40px 36px 32px;
        box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04), 0 12px 32px rgba(16, 24, 40, 0.06);
        text-align: center;
    }
    .icon {
        width: 56px;
        height: 56px;
        margin: 0 auto 20px;
        border-radius: 50%;
        background: #f3f4f6;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #374151;
    }
    h1 {
        font-size: 1.375rem;
        font-weight: 600;
        letter-spacing: -0.01em;
        color: #111827;
        margin-bottom: 8px;
    }
    .subtitle {
        color: #6b7280;
        font-size: 0.9375rem;
        line-height: 1.55;
        margin-bottom: 28px;
    }
    .error-box {
        background: #fef2f2;
        border: 1px solid #fecaca;
        color: #b91c1c;
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 20px;
        font-size: 0.875rem;
        text-align: left;
    }
    .captcha-box {
        display: flex;
        justify-content: center;
        min-height: 65px;
        margin-bottom: 20px;
    }
    .cf-turnstile { display: flex; justify-content: center; }
    .btn {
        width: 100%;
        padding: 12px 20px;
        font-size: 0.9375rem;
        font-weight: 600;
        color: #ffffff;
        background: #111827;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: background 0.15s ease, opacity 0.15s ease;
    }
    .btn:hover:not(:disabled) { background: #1f2937; }
    .btn:focus-visible { outline: 2px solid #111827; outline-offset: 2px; }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }
    .loading {
        display: none;
        margin-top: 14px;
        color: #6b7280;
        font-size: 0.875rem;
    }
    .loading.show { display: block; }
    .ref {
        margin-top: 28px;
        padding-top: 20px;
        border-top: 1px solid #f0f1f3;
        font-size: 0.75rem;
        color: #9ca3af;
    }
    .ref-label {
        display: block;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-size: 0.6875rem;
        margin-bottom: 4px;
    }
    .ref code {
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 0.75rem;
        color: #6b7280;
        word-break: break-all;
    }
    @media (max-width: 480px) {
        .card { padding: 32px 22px 26px; }
    }
    @media (prefers-color-scheme: dark) {
        body { background: #0f1115; color: #e5e7eb; }
        .card { background: #171a21; border-color: #262a33; box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4); }
        .icon { background: #1f232c; color: #d1d5db; }
        h1 { color: #f3f4f6; }
        .subtitle, .loading { color: #9ca3af; }
        .error-box { background: #2a1416; border-color: #5b1f23; color: #fca5a5; }
        .btn { background: #f3f4f6; color: #111827; }
        .btn:hover:not(:disabled) { background: #ffffff; }
        .ref { border-top-color: #262a33; }
        .ref code { color: #9ca3af; }
    }
</style>
</head>
<body>
<main class="card" role="main">
    <div class="icon" aria-hidden="true">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 3l7 3v5c0 4.6-3 8.7-7 10-4-1.3-7-5.4-7-10V6l7-3z"/>
            <path d="M9 12l2 2 4-4"/>
        </svg>
    </div>
    <h1>Security verification</h1>
    <p class="subtitle">Please complete the quick check below to continue to the website.</p>
    ${errorMessage ? `<div class="error-box" role="alert">${escapeHtml(errorMessage)}</div>` : ""}
    <form id="captcha-form" action="${escapeHtml(formAction)}" method="${method}">
        <input type="hidden" name="${PARAM_ORIGINAL_URL}" id="cheq-original-url" value="${escapeHtml(returnPath)}">
        <input type="hidden" name="${PARAM_REQUEST_ID}" value="${escapeHtml(rayId)}">
        ${method === "GET" ? `<input type="hidden" name="${PARAM_ANSWER_MARKER}" value="1">` : ""}
        <div class="captcha-box">
            <div class="cf-turnstile"
                data-sitekey="${escapeHtml(settings.siteKey)}"
                data-action="${TURNSTILE_ACTION}"
                data-callback="onTurnstileSuccess"
                data-error-callback="onTurnstileReset"
                data-expired-callback="onTurnstileReset"
                data-timeout-callback="onTurnstileReset"
                data-theme="auto">
            </div>
        </div>
        <button type="submit" id="submit-btn" class="btn" disabled>Continue to Website</button>
        <div id="loading" class="loading" aria-live="polite">Verifying…</div>
    </form>
    <div class="ref"><span class="ref-label">Session ID</span><code>${escapeHtml(rayId)}</code></div>
</main>
<script>
    // The fragment (#section) never reaches the server: add it here so the visitor returns to it.
    var originalUrl = document.getElementById('cheq-original-url');
    if (location.hash && originalUrl.value.indexOf('#') === -1) { originalUrl.value += location.hash; }
    var btn = document.getElementById('submit-btn');
    var loading = document.getElementById('loading');
    function onTurnstileSuccess(token) {
        btn.disabled = false;
        loading.classList.remove('show');
    }
    // Error, expiry or timeout of the widget: the token is gone, so block submit and drop the spinner.
    function onTurnstileReset() {
        btn.disabled = true;
        loading.classList.remove('show');
    }
    document.getElementById('captcha-form').addEventListener('submit', function() {
        btn.disabled = true;
        loading.classList.add('show');
    });
    // Back/forward cache restores the page as it was left, spinner included: reset it and get a fresh token.
    window.addEventListener('pageshow', function(event) {
        if (!event.persisted) return;
        loading.classList.remove('show');
        btn.disabled = true;
        if (window.turnstile) window.turnstile.reset();
    });
</script>
</body>
</html>`;

    const headers: CloudFrontHeaders = {
        'content-type': [{ key: 'Content-Type', value: 'text/html;charset=UTF-8' }],
        ...noStoreHeaders(),
    };
    const refererCookie = options.originalReferer ? refererCookieHeader(returnPath, options.originalReferer, REFERER_COOKIE_TTL_SECONDS) : undefined;
    if (refererCookie) {
        headers['set-cookie'] = [{ key: 'Set-Cookie', value: refererCookie }];
    }
    return {
        status: '403',
        headers,
        body: html,
    };
}

const turnstileChallengeExample = async (settings: TurnstileSettings, request: CloudFrontRequest, response: RTIResponse, addRtiResultHeader?: (headers: CloudFrontHeaders) => void): Promise<CloudFrontRequestResult | CloudFrontResponseResult> => {
    const ttl = settings.sessionTtlSeconds;
    // "cf-turnstile-response" is not set by this code: once the visitor solves the challenge, the Turnstile widget
    // (api.js) injects a hidden input with this name into the enclosing <form>. The form submits by POST (body) or,
    // with submitMethod "GET", in the query. The token must still be verified server-side (siteverify below).
    const answer = readAnswer(request);

    if (answer.bodyMissing) {
        // IncludeBody is off on the Lambda@Edge association, so the token never reached us. Let the visitor through
        // with a GET form instead of looping, and make the misconfiguration visible in the logs.
        console.error(`[turnstile] a POSTed challenge answer arrived without a body: enable IncludeBody on the Lambda@Edge association, or set submitMethod: "GET"`);
        return challengePage(settings, request.uri, safeReturnPath(answer.originalUrl) ?? pathWithQuery(request), response.ids.rayId, { errorMessage: "Please verify once more.", method: "GET" });
    }

    if (!answer.token) {
        // Not solved yet: serve the widget. The return URL keeps the original query string (issue: ad parameters lost).
        // An answer that lost its token (widget reset before submit, empty POST) keeps the return URL it carried.
        // Only the interrupted request itself has the visitor's Referer; an answer's Referer is the challenge page.
        const originalReferer = isTurnstileAnswer(request) ? undefined : originalRefererOf(request);
        return challengePage(settings, request.uri, safeReturnPath(answer.originalUrl) ?? pathWithQuery(request), response.ids.rayId, { originalReferer });
    }

    // Redirect back to where the visitor was, on THIS site. The host comes from the request (CloudFront only
    // routes hosts of this distribution), never from the query string, and original_url must be a path
    // (see safeReturnPath). Without a Host header the Location stays relative, which the browser resolves
    // against the current site.
    const host = request.headers["host"]?.[0]?.value;
    const returnPath = safeReturnPath(answer.originalUrl) ?? pathWithQuery(request);

    // A network error, timeout or bad answer from siteverify throws: the handler fails open (forwards the request).
    const result = await siteverify(settings, answer.token, request.clientIp);
    // The token must come from OUR widget (action) on OUR site (hostname), not just be valid somewhere. Cloudflare
    // reports the hostname the widget was solved on: it must be in the allow-list when one is configured, else equal
    // the request Host (see TurnstileSettings.allowedHostnames for the origin-request case).
    const allowedHostnames = allowedHostnamesOf(settings);
    const hostnameOk = allowedHostnames ? allowedHostnames.includes(result.hostname ?? "") : !host || result.hostname === host;
    const accepted = result.success === true && result.action === TURNSTILE_ACTION && hostnameOk;
    if (!accepted) {
        // Make a misconfiguration visible: a wrong secretKey (invalid-input-secret), test keys (hostname example.com,
        // no action) or a hostname mismatch would otherwise loop every visitor with nothing in the logs.
        console.error(`[turnstile] verification rejected: error-codes=${JSON.stringify(result["error-codes"] ?? [])} action=${result.action ?? "none"} hostname=${result.hostname ?? "none"} expected=${allowedHostnames ? allowedHostnames.join("|") : host ?? "any"}`);
        // Show the widget again with an error instead of a dead-end page.
        return challengePage(settings, request.uri, returnPath, response.ids.rayId, { errorMessage: "Verification failed. Please try again." });
    }

    const expiresAt = Date.now() + (ttl * 1000);
    const signature = signSession(settings.sessionSigningSecret, expiresAt, response.ids.rayId, userAgentOf(request));
    const sessionToken = `${expiresAt}.${signature}`;

    // Redirect host: the hostname Cloudflare verified (and we allow-listed) when a list is configured, which is right
    // even when the Lambda sees the origin's Host; otherwise the request Host.
    const redirectHost = allowedHostnames ? result.hostname : host;
    const headers: CloudFrontHeaders = {
        location: [{ key: 'Location', value: redirectHost ? `https://${redirectHost}${returnPath}` : returnPath }],
        // SameSite=Lax, NOT Strict. A visitor who reaches the site from another site
        // (link click, ad, redirect) makes a cross-site top-level navigation. With Strict
        // the browser does not send _cq_se on that request, so the session is never seen
        // and the visitor is challenged again on every arrival from outside. Lax sends the
        // cookie on top-level GET navigations but still withholds it from cross-site
        // subrequests (iframes, images, fetch) and cross-site POSTs. Do not change to Strict.
        'set-cookie': [{ key: 'Set-Cookie', value: `_cq_se=${sessionToken}|${response.ids.rayId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ttl}` }],
        ...noStoreHeaders(),
    };
    // The carried Referer only has to survive the redirect now: shorten its life instead of leaving it for 30 minutes.
    const carried = refererCookieOf(request);
    const carriedCookie = carried ? refererCookieHeader(carried.path, carried.referer, REFERER_COOKIE_AFTER_ANSWER_SECONDS) : undefined;
    if (carriedCookie) {
        headers['set-cookie'].push({ key: 'Set-Cookie', value: carriedCookie });
    }
    // Adds x-cheq-rti-result (the verdict that triggered the challenge), provided by the handler. This 302 goes
    // to the BROWSER (not the origin), so the client sees verdict, threat-type-code and ids. The redirected
    // request is checked by RTI again and gets its own header on the way to the origin.
    addRtiResultHeader?.(headers);

    return {
        status: '302',
        headers,
    };
};

const turnstileValidateChallengeExample = async (settings: TurnstileSettings, request: CloudFrontRequest, isDebug: boolean | undefined = false): Promise<boolean> => {
    // Validate session token (if the validation already happened in a previous request and the client has a valid session cookie or header, allow the request to proceed without triggering another challenge)
    const cookies = requestCookies(request);
    const [cookieToken, cookieRayId] = cookieValue(cookies, "_cq_se")?.split("|") ?? [];
    const rayId = request.headers["x-cheq-ray-id"]?.[0]?.value || cookieRayId;
    const sessionToken = request.headers["x-cheq-challenge"]?.[0]?.value || cookieToken;

    const shouldValidateChallenge = sessionToken && rayId;
    if (isDebug) {
        // Never log cookie or token values: the debug logs land in CloudWatch, and a logged _cq_se is a usable session.
        console.log(`[validateChallenge] cookies: ${cookies.length > 0 ? `${cookies.length} present` : "NOT PRESENT"}`);
        console.log(`[validateChallenge] sessionToken: ${sessionToken ? "present" : "NOT FOUND"}, rayId: ${rayId ?? "NOT FOUND"}, shouldValidateChallenge: ${shouldValidateChallenge ? "yes" : "NOTHING_TO_VALIDATE_CALL_RTI"}`);
    }

    if (shouldValidateChallenge) {
        try {
            const [expiresAtStr, signature] = sessionToken.split(".");
            
            if (!expiresAtStr || !signature) { 
                if (isDebug) {
                    console.log("[validateChallenge] invalid sessionToken format, returning 'false'");
                }
                
                return false; 
            }

            // Digits only: parseInt would accept "1700000000000abc" or "17e5".
            const expiresAt = /^\d+$/.test(expiresAtStr) ? Number(expiresAtStr) : NaN;
            if (isNaN(expiresAt)) { 
                if (isDebug) {
                    console.log("[validateChallenge] expiresAt is NaN, returning 'false'");
                }

                return false; 
            }

            if (Date.now() > expiresAt) {
                if (isDebug) {
                    console.log(`[validateChallenge] session token expired at ${expiresAt}, current time is ${Date.now()}, returning 'false'`);
                }

                return false; 
            }
            
            // Verify signature (keyed HMAC, constant-time compare)
            const match = isValidSessionSignature(settings.sessionSigningSecret, expiresAt, rayId, userAgentOf(request), signature);

            if (isDebug) {
                console.log(`[validateChallenge] signature match: ${match}`);
            }

            return match;
        } catch (e) {
            const err: Error = e as Error;
            console.error(`[validateChallenge] error validating challenge (continue running returning 'false'): ${err.message}`);
            return false;
        }
    }

    return false;
}
