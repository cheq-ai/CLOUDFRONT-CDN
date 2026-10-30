# Changelog

All notable changes to the CloudFront integration. Versions are git tags (`v1.0.0`); the version in `package.json`
is the version you run. Upgrade instructions are in [UPGRADE.md](UPGRADE.md).

## 1.0.0 — 2026-10-30

A major release: the CAPTCHA flow was reworked after a production review. Visitors who are not challenged see no
difference. Breaking changes are marked **(breaking)** and listed with their migration notes in UPGRADE.md, section 4.

### CAPTCHA flow

- The solved challenge is **POSTed**; the one-time token is no longer in the URL, browser history, logs or Referer.
  The answer is marked `?cheq_challenge=1`. Requires *Include body* on the Lambda@Edge association, or
  `submitMethod: "GET"`. **(breaking)**
- Challenge parameters are prefixed: `cheq_original_url`, `cheq_request_id`, `cheq_challenge`, so they cannot
  collide with a site's own `original_url` or `request_id`. **(breaking)**
- The visitor returns to the **exact original URL**: path, full query string (byte for byte: encoding, `+`,
  duplicate names, order) and `#fragment`. Advertising and attribution parameters survive the challenge.
- The **original Referer** is carried in the `_cq_ref` cookie while the challenge is open and **restored** on the
  request that follows the challenge, before RTI and the origin see it. The cookie is readable by the page's
  scripts because `document.referrer` cannot be restored by any CAPTCHA product.
- **Non-GET requests are never challenged** (POST, PUT, PATCH, DELETE): they are forwarded with `x-cheq-rti-result`
  so bodies such as payment returns (3-D Secure) and logins are never lost. A block, 404 or redirect still applies.
  **(breaking)**
- A request with a valid session that is itself an answer is still verified, never forwarded as a form.
- A link that merely contains `cf-turnstile-response=` is an ordinary request, not an answer; an answer needs the
  marker and a non-empty token.
- Refresh, Back and Forward on the challenge or landing page never show "verification failed"; the spinner resets
  on Back (bfcache), widget error and token expiry; an expired token resets the widget instead of dead-ending.
- The retry page keeps the original return URL; an empty POST is treated as "not solved" rather than as a missing
  body.
- Verification failures are answered with the widget and an error line, and logged with Cloudflare's error codes,
  action and hostname (`[turnstile] verification rejected: …`).
- If verification itself fails (network, timeout), an answer is redirected back to its page; it is never forwarded
  to the origin as a form.
- In `MONITORING` mode nothing is ever challenged or verified; an answer is sent back to its page unverified.

### Security

- Turnstile verification checks the token's **action** (`cheq-challenge`) and **hostname** against the request
  (or `allowedHostnames`), not only the success flag.
- The session cookie `_cq_se` is bound to the **User-Agent** in its signature: a copied cookie does not work in
  another client. Existing sessions become invalid once. **(breaking)**
- `x-cheq-rti-result` sent by a client is stripped from every incoming request; only the Lambda sets it.
- `cheq_original_url` is accepted only as a same-site path; control characters and protocol-relative values are
  rejected.
- Debug logs never contain cookie or token values.
- Cloudflare siteverify is called through the same bounded HTTPS client as RTI (1.5 s), not `fetch`, which could
  leave the Lambda unanswered after a freeze.

### Caching and CloudFront

- Every generated response (challenge, retry, redirects, block page) is `Cache-Control: no-store`. Behaviours with
  the trigger need Minimum TTL 0. **(breaking: configuration)**
- The origin request policies in `template.yaml` list `x-cheq-rti-result`, so CloudFront no longer drops the header
  the Lambda adds for the origin. `true-client-ip` was removed to stay within the 10-header quota. **(breaking)**
- `HEAD` is challenged like `GET`.

### Challenge page

- Redesigned as a neutral page: no logo, no vendor name, system font, light and dark mode, "Session ID" shown for
  support. No Google Fonts; preconnect to `challenges.cloudflare.com`.

### Configuration

- `createTurnstileChallenge` returns four callbacks: `challenge`, `validateChallenge`, `isChallengeAnswer`,
  `restoreReferer`. Wire all four in `src/config.ts`. A start-up warning is logged when `challenge` is set without
  `isChallengeAnswer`.
- New Turnstile settings: `submitMethod` (`"POST"` default, `"GET"`), `allowedHostnames`.
- A missing body on a POSTed answer (Include body off) is logged clearly and answered with a GET form, so a
  misconfiguration never traps visitors.

### Documentation and tests

- README: challenge flow, what survives the challenge, the original Referer, policy and forged-header notes,
  troubleshooting for cached challenge pages and failing verification on origin-request.
- UPGRADE.md and this changelog.
- 320 unit tests.

## 0.2.0 — baseline

The CloudFront integration as released before this repository: viewer-request and origin-request Lambdas,
Turnstile CAPTCHA example with a GET form, origin request policies, README.
