# Upgrade and migration guide

How to move an existing CloudFront integration to version **1.0.0**, what has to be configured in AWS and in
`src/config.ts`, what changed in a way you can notice, and how to check the result.

Contents

1. [Which version you are running](#1-which-version-you-are-running)
2. [Required configuration and recommended values](#2-required-configuration-and-recommended-values)
3. [Migration steps](#3-migration-steps)
4. [Compatibility and breaking changes](#4-compatibility-and-breaking-changes)
5. [Verifying the integration after deployment](#5-verifying-the-integration-after-deployment)
6. [Rolling back](#6-rolling-back)

---

## 1. Which version you are running

| You have | Signs | Upgrade path |
|---|---|---|
| **0.2.x** (any copy delivered before this repository) | `package.json` says `0.2.0`; the challenge form in `src/turnstile-challenge-example.ts` is `method="GET"` with the field names `original_url` and `request_id` | Section 3, all steps |
| **1.0.0** | `package.json` says `1.0.0`; `CHANGELOG.md` present | Nothing to do |

Every release is a git tag. To see exactly what changed between your version and the target:

```sh
git fetch --tags
git diff v0.2.0 v1.0.0 --stat -- integrations/
git diff v0.2.0 v1.0.0 -- integrations/cloudfront/src/config.ts
```

Files you may have edited locally and must diff before copying over: `src/config.ts` (your keys and routing),
`template.yaml` (if you changed the policies), `src/turnstile-challenge-example.ts` (if you changed the page).

---

## 2. Required configuration and recommended values

### 2.1 Lambda@Edge (set by `template.yaml`, check after `sam deploy`)

| Setting | Value | Why |
|---|---|---|
| Region of the stack | `us-east-1` | Lambda@Edge functions must be published there |
| Runtime | `nodejs20.x` | As in the template |
| Memory | 128 MB | Enough; the code is small. Raise to 256 MB only if cold starts time out (see README *Memory, CPU and Cold Starts*) |
| Timeout | viewer-request **5 s** (hard limit), origin-request **30 s** | The RTI call (`timeout` below) plus the Turnstile check (1.5 s) must fit inside |
| Version attached | the **version ARN** from the stack outputs (`ViewerRequestVersionARN` or `OriginRequestVersionARN`), never `$LATEST` or the alias | CloudFront only accepts numbered versions |

### 2.2 CloudFront behaviour that carries the Lambda

| Setting | Value | Why |
|---|---|---|
| Trigger | `viewer-request` (recommended) or `origin-request` | Viewer-request sees every request and all headers; origin-request only runs on cache misses and only sees what the policies forward |
| **Include body** | **on** | The solved CAPTCHA is POSTed; without the body the Lambda cannot read the token (it falls back to a GET form and logs an error) |
| Allowed HTTP methods | `GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE` | The CAPTCHA answer is a POST; your checkout and payment returns are POSTs too |
| Cache policy, **Minimum TTL** | **0** on every behaviour that has the trigger | The challenge and block pages are sent with `Cache-Control: no-store`; a minimum TTL above 0 overrides that and caches them for every visitor |
| Cache key | not keyed on `Cookie` or `Referer` | Keep your cache hit ratio; the Lambda reads cookies from the request, not from the cache key |
| Origin request policy (**origin-request only**) | cookies **all**, query strings **all**, headers at least: `host`, `user-agent`, `accept`, `accept-language`, `referer`, `x-forwarded-for`, `cloudfront-viewer-tls`, `cloudfront-viewer-ja3-fingerprint`, `cloudfront-viewer-ja4-fingerprint`, **`x-cheq-rti-result`** | The stack creates such policies (`OriginRequestPolicy` outputs). The header the Lambda adds for your origin is dropped by CloudFront unless the policy lists it. The CAPTCHA cookies (`_cq_se`, `_cq_ref`) and the CHEQ tag cookies (`_cq_duid`, `_cq_pvid`) must reach the Lambda. The whitelist has a quota of 10 headers |
| Another bot-management product on the same behaviour | put it on `viewer-request` and this integration on `origin-request`, or chain them in the order you want | Two viewer-request functions on one behaviour are not possible |

### 2.3 `src/config.ts`

| Field | Recommended | Notes |
|---|---|---|
| `mode` | `Mode.MONITORING` for the first days, then `Mode.BLOCKING` | MONITORING never answers a request itself; it only adds `x-cheq-rti-result` |
| `apiKey`, `tagHash` | your values | From the CHEQ platform; the tag hash must be the tag that runs on the site, otherwise the page-view ids never match |
| `blockingStrategy` | `ActionStrategy.CAPTCHA` during rollout, `ActionStrategy.ACCESS_DENIED` once you trust the verdicts | What a BLOCK verdict gets |
| `challengingStrategy` | `ActionStrategy.CAPTCHA` | What a CHALLENGE verdict gets |
| `challengeTTCodes`, `challengeReasons`, `blockTTCodes`, `blockReasons` | leave empty unless CHEQ tells you otherwise | Adds to the verdict's own action |
| `redirectLocation` | only with `redirectReasons` | Config validation fails otherwise |
| `ignorePaths` | the shipped list (static files, health checks) plus your own | Paths that never go to RTI |
| `timeout` | `2000` | RTI call timeout in ms. Do not go below 1500 |
| `keepHeadersNames` | `[]` (all headers) | What RTI receives |
| `debug` | `false` in production | Debug logs every decision to CloudWatch |
| `logErrors` | `true` | Sends caught errors to the CHEQ logger as well as CloudWatch |
| `challenge`, `validateChallenge`, `isChallengeAnswer`, `restoreReferer` | the four values returned by `createTurnstileChallenge(...)` | **All four must be wired** (0.2.x had two). Without `isChallengeAnswer` the Lambda warns at start-up and a solved CAPTCHA can be forwarded to the origin as a form |

### 2.4 Turnstile settings (`turnstileConfig` in `src/config.ts`)

| Field | Recommended | Notes |
|---|---|---|
| `siteKey`, `secretKey` | from your Cloudflare Turnstile widget | Widget mode *Managed*; the widget's hostname list must contain **every hostname** the site is served on (production, staging). A hostname missing there makes every verification fail |
| `sessionSigningSecret` | `openssl rand -hex 32` | Signs `_cq_se`. Not the Turnstile secret. Changing it logs every visitor out of their CAPTCHA session (they solve it once more) |
| `sessionTtlSeconds` | `300` to `1800` | How long a solved CAPTCHA is remembered. Every request is still checked by RTI; the session only waives the CAPTCHA |
| `submitMethod` | `"POST"` (default) | Keeps the one-time token out of URLs, logs and history. Needs *Include body* (above). `"GET"` needs nothing but puts the token in the URL |
| `allowedHostnames` | leave unset with viewer-request; set to your public hostnames with origin-request when the policy does **not** forward `host` | The hostname Cloudflare verified must match the site the visitor is on |

---

## 3. Migration steps

Do this on a staging distribution first, then production. Each step is safe to stop after.

1. **Get the release.**
   ```sh
   git fetch --tags && git checkout v1.0.0
   cd integrations/cloudfront && npm ci
   ```
2. **Carry your settings over.** Open your old `src/config.ts` next to the new one and copy: `apiKey`, `tagHash`,
   `mode`, the routing lists, `redirectLocation`, your additions to `ignorePaths`, and the whole `turnstileConfig`
   (`siteKey`, `secretKey`, `sessionSigningSecret`). Keep the new file's structure; it wires `isChallengeAnswer` and
   `restoreReferer`, which the old one did not have. Do not copy the old file over the new one.
3. **Re-apply local changes, if any,** to `template.yaml` or the challenge page (`git diff v0.2.0 v1.0.0` shows what
   moved). The challenge page is neutral by design (no vendor name); keep it that way if you restyle it.
4. **Check and build.**
   ```sh
   npm test      # type check + unit tests, all must pass
   sam build
   ```
5. **Deploy the stack** to the same stack name you used before, so the new version is published on the same functions:
   ```sh
   sam deploy --region us-east-1
   ```
   Note the new `…VersionARN` outputs. Publishing a version does not change CloudFront yet.
6. **Update the CloudFront behaviour.** Edit the Lambda function association: paste the new version ARN, tick
   **Include body**. Then check the rest of section 2.2 on the same behaviour: allowed methods include POST, cache
   policy minimum TTL is 0, and, for origin-request, the origin request policy lists `x-cheq-rti-result` and forwards
   all cookies and query strings. Save and wait for the distribution to show *Deployed* (3 to 5 minutes).
7. **Turnstile dashboard.** Confirm the widget's hostname list contains the distribution's public hostnames.
8. **Verify** with section 5. Then repeat steps 5 to 8 on production.
9. **Expect one extra CAPTCHA** for visitors who were in an open CAPTCHA session during the switch: the session
   cookie format changed and old cookies are no longer valid.

---

## 4. Compatibility and breaking changes

Version 1.0.0 is a **major** release relative to 0.2.x. Nothing changes for visitors who are not challenged. For
challenged visitors and for your own infrastructure, be aware of:

| Area | 0.2.x | 1.0.0 | What to check on your side |
|---|---|---|---|
| CAPTCHA answer transport | GET, token in the URL | **POST**, token in the body; `?cheq_challenge=1` marks the answer | *Include body* on the association (or `submitMethod: "GET"`) |
| Answer parameter names | `original_url`, `request_id`, `cf-turnstile-response` | `cheq_original_url`, `cheq_request_id`, `cheq_challenge`, `cf-turnstile-response` | WAF rules, analytics filters, log queries that matched the old names |
| URL after the CAPTCHA | path only; query string lost | path **and** full query string and `#fragment`, byte for byte | Nothing; attribution parameters (`gclid`, `utm_*`) now arrive |
| Original Referer | lost | carried in `_cq_ref` and **restored** on the request after the CAPTCHA (header to RTI and origin). `document.referrer` in the browser cannot be restored; the page's scripts can read `_cq_ref` | Front-end attribution code that reads `document.referrer` on the landing page: read `_cq_ref` first (snippet in README, *The original Referer*) |
| Non-GET requests (POST, PUT, …) | challenged like GET; body lost | **never challenged**; forwarded with `x-cheq-rti-result` (a BLOCK, 404 or redirect still applies) | Payment returns (3-D Secure), logins and form posts complete. If you want to act on bad POSTs, read the header at the origin |
| Session cookie `_cq_se` | signed with `sessionSigningSecret` | also **bound to the User-Agent**: a copied cookie does not work in another client | All old sessions are invalid once (one extra CAPTCHA) |
| New cookie `_cq_ref` | — | set while a CAPTCHA is open (30 min), shortened to 2 min after it is solved; not HttpOnly | Cookie forwarding (origin-request); cookie notices if you list cookies |
| Generated responses | `no-store` on the challenge page only | `Cache-Control: no-store` on every generated response: challenge, retry, redirects, block page | Minimum TTL 0 on the behaviour |
| Turnstile verification | success flag only | checks `action` and `hostname` too; rejections logged with Cloudflare's reason | Widget hostnames complete; `allowedHostnames` when `host` is not forwarded |
| Origin request policy headers | included `true-client-ip` | **`true-client-ip` removed**, `x-cheq-rti-result` added (10-header quota) | If your origin read `true-client-ip`, add it to your own policy in place of another header |
| Verdict header from the client | could reach the origin | stripped from every incoming request; only the Lambda sets it | Nothing |
| Config interface | `challenge`, `validateChallenge` | plus `isChallengeAnswer`, `restoreReferer` (optional types, but wire them) | `src/config.ts` |
| Turnstile settings | `siteKey`, `secretKey`, `sessionSigningSecret`, `sessionTtlSeconds` | plus `submitMethod`, `allowedHostnames` | Optional |
| Runtime, memory, timeouts | nodejs20.x, 128 MB, 5 s / 30 s | unchanged | — |

Not changed: the RTI request and verdict handling, `ignorePaths`, action routing, `x-cheq-rti-result` format, the
block page, MONITORING behaviour.

---

## 5. Verifying the integration after deployment

Run these against the **staging** distribution first. `HOST` is the public hostname of the distribution. A request
from `curl` is normally rated as a bot by RTI, which is what makes these checks possible.

### 5.1 Five-minute check from a terminal

```sh
HOST=www.example.com

# 1. Challenge page: 403, not cacheable, POST form marked cheq_challenge=1, no vendor name
curl -s -D - -o /tmp/page "https://$HOST/some-product?utm_source=check" | grep -iE "^HTTP|cache-control|set-cookie"
grep -o '<form[^>]*>' /tmp/page            # expect method="POST" action="/some-product?cheq_challenge=1&amp;cheq_original_url=%2Fsome-product%3Futm_source%3Dcheck"

# 2. Referer is carried: a request with a Referer gets _cq_ref
curl -s -D - -o /dev/null -H "Referer: https://www.google.com/" "https://$HOST/some-product" | grep -i "set-cookie: _cq_ref"

# 3. A bad token is refused and never forwarded: retry page (403), not your origin's page
curl -s -o /dev/null -w "%{http_code}\n" -X POST -d "cf-turnstile-response=bad" \
  "https://$HOST/some-product?cheq_challenge=1&cheq_original_url=%2Fsome-product"     # expect 403

# 4. A POST is never challenged (payment returns work) and carries the verdict to the origin
curl -s -o /dev/null -w "%{http_code}\n" -X POST -d "PaRes=test" "https://$HOST/checkout/return"   # expect your origin's answer, not 403

# 5. The challenge page is not cached: request it twice, the second must not be a cache hit
for i in 1 2; do curl -s -D - -o /dev/null "https://$HOST/some-product" | grep -i "x-cache"; done     # expect Miss both times (or RefreshHit, never Hit)
```

### 5.2 In a browser (one pass, 10 minutes)

| # | Do | Expect |
|---|---|---|
| 1 | Clear cookies for the site. Open a product page from a link on another site (or paste the URL with `?gclid=TEST1` in a tab where you have a VPN on, which is usually rated as a bot) | The neutral verification page, widget solves, you land on the same URL **with** `gclid=TEST1` |
| 2 | DevTools → Application → Cookies while the verification page is shown | `_cq_ref` present when you arrived from a link; after solving, `_cq_se` present |
| 3 | On the landing page, check your server-side logs or an echo of the request headers | `Referer` is the site you came from, not the product page itself |
| 4 | Press Back, then Forward; press Reload on the landing page | No "verification failed" page, no second CAPTCHA |
| 5 | Open a second product page within 5 minutes | No CAPTCHA (session) |
| 6 | Wait for the session to expire (`sessionTtlSeconds`) and open another page | CAPTCHA again, solves normally |
| 7 | Complete a test checkout with a 3-D Secure card on staging | The bank's return POST completes; no CAPTCHA inside the payment flow |

### 5.3 CloudWatch

The Lambda@Edge logs are in the region that served the request, log group `/aws/lambda/us-east-1.<function name>`.
After the first hour of traffic search for:

| Message | Meaning | Action |
|---|---|---|
| `[turnstile] verification rejected: error-codes=…` | Cloudflare refused a token | `invalid-input-secret`: wrong `secretKey`; hostname mismatch: widget hostnames or `allowedHostnames` |
| `[turnstile] a POSTed challenge answer arrived without a body` | *Include body* is off on the association | Tick it (section 2.2). Visitors are not stuck meanwhile: they get a GET form |
| `[turnstile] CAPTCHA disabled, not configured` | `siteKey`, `secretKey` or `sessionSigningSecret` still a placeholder | Set them |
| `challenge is configured without isChallengeAnswer` | `src/config.ts` does not wire `isChallengeAnswer` | Wire it (section 2.3) |

### 5.4 At the origin

Confirm that requests arrive with `x-cheq-rti-result` (`version=…;verdict=…;threat-type-code=…;ids={…}`) on
**every** page request. If it is missing on some requests with the origin-request trigger, the origin request
policy does not list the header (section 2.2).

---

## 6. Rolling back

1. In the CloudFront behaviour, put the previous Lambda version ARN back into the association (the old versions stay
   published on the function). Wait for *Deployed*.
2. Visitors in an open CAPTCHA session solve it once more (cookie format differs between versions). Nothing else is
   stored anywhere, so there is no data to migrate back.
3. Keep the CloudFront settings from section 2.2; they are correct for the old version as well.

For the code, `git checkout v0.2.0` is the previous state of this repository.
