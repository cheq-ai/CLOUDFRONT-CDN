// cspell:ignore cheq
import { describe, it, expect, vi, afterEach } from 'vitest';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { createTurnstileChallenge, TurnstileSettings } from './turnstile-challenge-example';
import type { CloudFrontRequest } from 'aws-lambda/common/cloudfront';
import type { RTIResponse } from '../../core/models/rti-response.model';
import { HttpsClient } from '../../core/services/https-client';

// Pass-through spy on timingSafeEqual, so a test can check the signature compare is constant-time.
vi.mock('node:crypto', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:crypto')>();
    return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});

const testSettings: TurnstileSettings = {
    siteKey: 'test-site-key',
    secretKey: 'test-turnstile-secret',
    sessionSigningSecret: 'test-session-signing-secret',
    sessionTtlSeconds: 300,
};

type Callbacks = Required<ReturnType<typeof createTurnstileChallenge>>;
const build = (settings: TurnstileSettings) => createTurnstileChallenge(settings) as Callbacks;
const { challenge, validateChallenge } = build(testSettings);

function buildRequest(cookieValue?: string, rayIdHeader?: string, challengeHeader?: string): CloudFrontRequest {
    const headers: Record<string, { key: string; value: string }[]> = {};
    if (cookieValue !== undefined) {
        headers['cookie'] = [{ key: 'Cookie', value: cookieValue }];
    }
    if (rayIdHeader !== undefined) {
        headers['x-cheq-ray-id'] = [{ key: 'x-cheq-ray-id', value: rayIdHeader }];
    }
    if (challengeHeader !== undefined) {
        headers['x-cheq-challenge'] = [{ key: 'x-cheq-challenge', value: challengeHeader }];
    }
    return {
        clientIp: '1.2.3.4',
        method: 'GET',
        uri: '/page',
        querystring: '',
        headers,
    } as unknown as CloudFrontRequest;
}

function buildTurnstileRequest(querystring = '', hostHeader?: string, cookie?: string): CloudFrontRequest {
    const headers: Record<string, { key: string; value: string }[]> = {};
    if (hostHeader) {
        headers['host'] = [{ key: 'Host', value: hostHeader }];
    }
    if (cookie) {
        headers['cookie'] = [{ key: 'Cookie', value: cookie }];
    }
    return {
        clientIp: '1.2.3.4',
        method: 'GET',
        uri: '/page',
        querystring,
        headers,
    } as unknown as CloudFrontRequest;
}

function buildRTIResponse(rayId = 'ray-123'): RTIResponse {
    return {
        ids: { rayId, pageViewId: null, duid: null, uniqueVisitId: null },
        decision: { verdict: 'suspicious' },
        classification: { code: 0 },
        cheqDetection: { reasons: [] },
        metadata: { version: '1.0' },
    } as unknown as RTIResponse;
}

const solvedQuery = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'valid-token' }).toString();

// A siteverify answer for OUR widget (action) on example.com, the Host the redirect tests use.
// siteverify goes through HttpsClient.post(body, timeoutMs); the stub answers like Cloudflare does.
const stubSiteverify = (success: boolean, answer: Record<string, unknown> = {}) =>
    vi.spyOn(HttpsClient.prototype, 'post').mockResolvedValue({
        status: 200, statusText: 'OK', body: JSON.stringify({ success, action: 'cheq-challenge', hostname: 'example.com', ...answer }),
    });
const siteverifyBody = (post: ReturnType<typeof stubSiteverify>) => JSON.parse(post.mock.calls[0][0] as string);

/**
 * Solves the challenge (siteverify stubbed to succeed) and returns the session cookie it issues, so the
 * validate tests use a real signature without reaching into the signing code.
 * @param now Date.now() while the cookie is issued (e.g. in the past to get an expired session)
 */
async function issueSession(rayId: string, settings = testSettings, now?: number, requestCookie?: string): Promise<{ cookie: string; token: string; expiresAt: number; signature: string }> {
    stubSiteverify(true);
    const nowSpy = now !== undefined ? vi.spyOn(Date, 'now').mockReturnValue(now) : undefined;
    const result = await build(settings).challenge(buildTurnstileRequest(solvedQuery, undefined, requestCookie), buildRTIResponse(rayId)) as any;
    nowSpy?.mockRestore();
    vi.unstubAllGlobals();
    const cookie: string = result.headers['set-cookie'][0].value.split(';')[0]; // `_cq_se=<token>|<rayId>`
    const token = cookie.slice('_cq_se='.length).split('|')[0];
    const [expiresAt, signature] = token.split('.');
    return { cookie, token, expiresAt: Number(expiresAt), signature };
}

describe('createTurnstileChallenge', () => {
    it('returns challenge and validateChallenge when all settings are set, without warning', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const result = createTurnstileChallenge(testSettings);
        expect(result.challenge).toBeTypeOf('function');
        expect(result.validateChallenge).toBeTypeOf('function');
        expect(warn).not.toHaveBeenCalled();
    });

    it.each([
        ['siteKey', 'REPLACE_ME'],
        ['secretKey', 'REPLACE_ME'],
        ['sessionSigningSecret', 'REPLACE_ME'],
        ['sessionSigningSecret', ' REPLACE_ME '],
        ['sessionSigningSecret', ''],
        ['secretKey', '   '],
    ])('returns {} and warns once when %s is %j', (field, value) => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const result = createTurnstileChallenge({ ...testSettings, [field]: value });
        expect(result).toEqual({});
        expect(warn).toHaveBeenCalledOnce();
        expect(warn).toHaveBeenCalledWith(expect.stringContaining(field));
    });
});

describe('createTurnstileChallenge sessionTtlSeconds', () => {
    it.each([0, -5, 1.5, NaN, Infinity, '300' as unknown as number, undefined as unknown as number])(
        'warns and uses the default 300 s when sessionTtlSeconds is %j', async (ttl) => {
            const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const callbacks = createTurnstileChallenge({ ...testSettings, sessionTtlSeconds: ttl });
            expect(warn).toHaveBeenCalledOnce();
            expect(warn).toHaveBeenCalledWith(expect.stringContaining('sessionTtlSeconds'));

            stubSiteverify(true);
            const result = await callbacks.challenge!(buildTurnstileRequest(solvedQuery), buildRTIResponse()) as any;
            expect(result.headers['set-cookie'][0].value).toContain('Max-Age=300');
        });

    it('keeps a valid sessionTtlSeconds without warning', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const callbacks = createTurnstileChallenge({ ...testSettings, sessionTtlSeconds: 60 });
        expect(warn).not.toHaveBeenCalled();

        stubSiteverify(true);
        const result = await callbacks.challenge!(buildTurnstileRequest(solvedQuery), buildRTIResponse()) as any;
        expect(result.headers['set-cookie'][0].value).toContain('Max-Age=60');
    });

    it('still disables the CAPTCHA (one warning) when a secret is missing, whatever the TTL', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        expect(createTurnstileChallenge({ ...testSettings, secretKey: 'REPLACE_ME', sessionTtlSeconds: 0 })).toEqual({});
        expect(warn).toHaveBeenCalledOnce();
    });
});

describe('validateChallenge', () => {

    // --- No session present ---

    it('returns false when no cookie header is present', async () => {
        expect(await validateChallenge(buildRequest(), false)).toBe(false);
    });

    it('returns false when cookie header has no _cq_se cookie', async () => {
        expect(await validateChallenge(buildRequest('_cq_duid=device-abc; _cq_pvid=pv-xyz'), false)).toBe(false);
    });

    // --- Valid session ---

    it('accepts the session cookie issued by challenge', async () => {
        const { cookie } = await issueSession('ray-roundtrip');
        expect(cookie).toMatch(/^_cq_se=\d+\.[0-9a-f]{32}\|ray-roundtrip$/); // format unchanged: 32 hex signature
        expect(await validateChallenge(buildRequest(cookie), false)).toBe(true);
    });

    it('returns true when _cq_se is alongside other cookies', async () => {
        const { cookie } = await issueSession('ray-abc123', testSettings, undefined, '_cq_duid=device-abc');
        expect(await validateChallenge(buildRequest(`_cq_duid=device-abc; ${cookie}; _cq_pvid=pv-xyz`), false)).toBe(true);
    });

    // --- Forged or tampered sessions ---

    it('rejects a token signed the old unkeyed way, SHA-256(expiresAt:rayId) (forgery regression)', async () => {
        const rayId = 'ray-abc123';
        const expiresAt = Date.now() + 60_000;
        const unkeyed = createHash('sha256').update(`${expiresAt}:${rayId}`).digest('hex').slice(0, 32);
        expect(await validateChallenge(buildRequest(`_cq_se=${expiresAt}.${unkeyed}|${rayId}`), false)).toBe(false);
    });

    it('rejects a session issued with a different signing secret', async () => {
        const { cookie } = await issueSession('ray-abc123', { ...testSettings, sessionSigningSecret: 'another-secret' });
        expect(await validateChallenge(buildRequest(cookie), false)).toBe(false);
    });

    it('rejects a valid token presented with another rayId', async () => {
        const { token } = await issueSession('ray-abc123');
        expect(await validateChallenge(buildRequest(`_cq_se=${token}|ray-other`), false)).toBe(false);
    });

    it('rejects a token whose expiry was extended', async () => {
        const { expiresAt, signature } = await issueSession('ray-abc123');
        expect(await validateChallenge(buildRequest(`_cq_se=${expiresAt + 3_600_000}.${signature}|ray-abc123`), false)).toBe(false);
    });

    it.each([
        ['one character short', (sig: string) => sig.slice(0, 31)],
        ['one character long', (sig: string) => sig + '0'],
        ['a different value', (sig: string) => sig.replace(/^./, c => (c === '0' ? '1' : '0'))],
    ])('rejects a signature that is %s, without throwing', async (_label, tamper) => {
        const { expiresAt, signature } = await issueSession('ray-abc123');
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        expect(await validateChallenge(buildRequest(`_cq_se=${expiresAt}.${tamper(signature)}|ray-abc123`), false)).toBe(false);
        expect(errorSpy).not.toHaveBeenCalled(); // rejected by the length check, not by timingSafeEqual throwing
    });

    // --- Expired session ---

    it('returns false when the session is expired', async () => {
        const { cookie } = await issueSession('ray-abc123', testSettings, Date.now() - 301_000); // issued 301 s ago, TTL 300 s
        expect(await validateChallenge(buildRequest(cookie), false)).toBe(false);
    });

    // --- Malformed token ---

    it('returns false when token has no "." separator (missing signature)', async () => {
        expect(await validateChallenge(buildRequest('_cq_se=1234567890|ray-abc'), false)).toBe(false);
    });

    it('returns false when expiresAt part is not a number (NaN)', async () => {
        expect(await validateChallenge(buildRequest('_cq_se=notanumber.abcdef|ray-abc'), false)).toBe(false);
    });

    // --- Header fallbacks ---

    it('returns true when rayId comes from x-cheq-ray-id header alongside _cq_se cookie token', async () => {
        const { token } = await issueSession('ray-from-header');
        // cookie contains only the token portion; rayId comes from the header
        expect(await validateChallenge(buildRequest(`_cq_se=${token}|`, 'ray-from-header'), false)).toBe(true);
    });

    it('returns true when sessionToken comes from x-cheq-challenge header instead of cookie', async () => {
        const { token } = await issueSession('ray-abc123');
        // cookie has only the rayId portion, token supplied via header
        expect(await validateChallenge(buildRequest('_cq_se=|ray-abc123', undefined, token), false)).toBe(true);
    });

    it('returns true when both token and rayId come from headers (no _cq_se cookie)', async () => {
        const { token } = await issueSession('ray-abc123');
        expect(await validateChallenge(buildRequest(undefined, 'ray-abc123', token), false)).toBe(true);
    });

    // --- Debug logging branches ---

    it('logs debug info when isDebug=true and no session present', async () => {
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await validateChallenge(buildRequest(), true);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('[validateChallenge]'));
    });

    it('logs token/rayId info when isDebug=true with a valid token', async () => {
        const { cookie } = await issueSession('ray-debug');
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await validateChallenge(buildRequest(cookie), true);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('signature match'));
    });

    it('logs debug info when isDebug=true and token is expired', async () => {
        const { cookie } = await issueSession('ray-debug', testSettings, Date.now() - 301_000);
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await validateChallenge(buildRequest(cookie), true);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('expired'));
    });

    it('logs debug info when isDebug=true and token has no separator', async () => {
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await validateChallenge(buildRequest('_cq_se=1234567890|ray-abc'), true);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('invalid sessionToken format'));
    });

    it('logs debug info when isDebug=true and expiresAt is NaN', async () => {
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await validateChallenge(buildRequest('_cq_se=notanumber.abcdef|ray-abc'), true);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('NaN'));
    });

    // --- Signature format and comparison ---

    it.each([
        ['without a _cq_duid cookie', undefined],
        ['with a _cq_duid cookie', '_cq_duid=dev-A'],
    ])('signs %s as HMAC-SHA256(secret, JSON ["se", expiresAt, rayId, userAgent]), first 32 hex (known answer)', async (_label, cookie) => {
        const now = 1_700_000_000_000;
        const { signature, expiresAt } = await issueSession('ray-1', testSettings, now, cookie);
        const signed = JSON.stringify(['se', now + 300_000, 'ray-1', '']); // no User-Agent header on the issuing request
        const expected = createHmac('sha256', testSettings.sessionSigningSecret).update(signed).digest('hex').slice(0, 32);
        expect(expiresAt).toBe(now + 300_000);
        expect(signature).toBe(expected);
    });

    // --- Not bound to the visitor's _cq_duid ---

    it('accepts a session issued before the CHEQ tag set _cq_duid once the cookie appears (no second CAPTCHA)', async () => {
        // First visit: the challenge is solved before any page with the CHEQ tag has loaded, so there is no _cq_duid yet.
        const { cookie } = await issueSession('ray-abc123');
        expect(await validateChallenge(buildRequest(`${cookie}; _cq_duid=dev-A`), false)).toBe(true);
    });

    it.each([
        ['the same _cq_duid', '; _cq_duid=dev-A'],
        ['a different _cq_duid', '; _cq_duid=dev-B'],
        ['no _cq_duid', ''],
    ])('accepts a session issued with _cq_duid when the request has %s', async (_label, duidCookie) => {
        const { cookie } = await issueSession('ray-abc123', testSettings, undefined, '_cq_duid=dev-A');
        expect(await validateChallenge(buildRequest(`${cookie}${duidCookie}`), false)).toBe(true);
    });

    // --- Several Cookie header entries (HTTP/2 clients can split cookies) ---

    it('finds _cq_se in a later Cookie header entry', async () => {
        const { cookie } = await issueSession('ray-abc123');
        const request = buildRequest();
        request.headers['cookie'] = [
            { key: 'Cookie', value: 'theme=dark' },
            { key: 'Cookie', value: cookie },
            { key: 'Cookie', value: '_cq_duid=dev-A' },
        ];
        expect(await validateChallenge(request, false)).toBe(true);
    });

    it('compares signatures with timingSafeEqual (constant time)', async () => {
        const { cookie } = await issueSession('ray-abc123');
        vi.mocked(timingSafeEqual).mockClear();
        expect(await validateChallenge(buildRequest(cookie), false)).toBe(true);
        expect(timingSafeEqual).toHaveBeenCalledOnce();
    });

    it('accepts a session up to and including its expiry time, and rejects it 1 ms later', async () => {
        const { cookie, expiresAt } = await issueSession('ray-abc123');
        vi.spyOn(Date, 'now').mockReturnValue(expiresAt);
        expect(await validateChallenge(buildRequest(cookie), false)).toBe(true);
        vi.spyOn(Date, 'now').mockReturnValue(expiresAt + 1);
        expect(await validateChallenge(buildRequest(cookie), false)).toBe(false);
    });

    // --- Header precedence over the cookie ---

    it('x-cheq-challenge wins over the token in the cookie', async () => {
        const { token } = await issueSession('ray-abc123');
        expect(await validateChallenge(buildRequest('_cq_se=1.bogus|ray-abc123', undefined, token), false)).toBe(true);
    });

    it('x-cheq-ray-id wins over the rayId in the cookie', async () => {
        const { token } = await issueSession('ray-from-header');
        expect(await validateChallenge(buildRequest(`_cq_se=${token}|ray-in-cookie`, 'ray-from-header'), false)).toBe(true);
    });

    // --- Catch block ---

    it('returns false and logs error when validation throws', async () => {
        const { cookie } = await issueSession('ray-abc123');
        vi.spyOn(Date, 'now').mockImplementationOnce(() => { throw new Error('clock failed'); });
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        expect(await validateChallenge(buildRequest(cookie), false)).toBe(false);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('clock failed'));
    });
});

describe('challenge', () => {

    // --- No token: serve challenge page ---

    it('returns 403 with HTML challenge page when no cf-turnstile-response token present', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('cf-turnstile');
        expect(result.headers['content-type'][0].value).toContain('text/html');
        expect(result.headers['cache-control'][0].value).toContain('no-store');
    });

    it('embeds rayId and the configured site key in challenge page HTML', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse('ray-embed-test')) as any;
        expect(result.body).toContain('ray-embed-test');
        expect(result.body).toContain('data-sitekey="test-site-key"');
    });

    it('HTML-escapes the request URI in the challenge page', async () => {
        const request = buildTurnstileRequest();
        (request as any).uri = '/page"><script>alert(1)</script>';
        const result = await challenge(request, buildRTIResponse()) as any;
        expect(result.body).not.toContain('<script>alert(1)</script>');
        expect(result.body).toContain('action="/page&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;?cheq_challenge=1&amp;cheq_original_url=');
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"');
    });

    it("HTML-escapes the rayId and the site key (& < > \" ')", async () => {
        const result = await build({ ...testSettings, siteKey: `k"'<&>` }).challenge(buildTurnstileRequest(), buildRTIResponse(`r"'<&>`)) as any;
        expect(result.body).toContain('data-sitekey="k&quot;&#39;&lt;&amp;&gt;"');
        expect(result.body).toContain('name="cheq_request_id" value="r&quot;&#39;&lt;&amp;&gt;"');
        expect(result.body).toContain('<code>r&quot;&#39;&lt;&amp;&gt;</code>');
        expect(result.body).not.toContain(`r"'<&>`);
    });

    it('leaves a normal URI and rayId unchanged', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse('ray-abc-123')) as any;
        expect(result.body).toContain('action="/page?cheq_challenge=1&amp;cheq_original_url=%2Fpage"');
        expect(result.body).toContain('value="ray-abc-123"');
    });

    // --- Token present: verify with Turnstile ---

    it('sends the configured Turnstile secret to siteverify', async () => {
        const post = stubSiteverify(true);
        await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse());
        expect(siteverifyBody(post)).toMatchObject({ secret: 'test-turnstile-secret', response: 'valid-token' });
    });

    it('returns 302 with session cookie when Turnstile verification succeeds', async () => {
        stubSiteverify(true);
        const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'valid-token', 'cheq_original_url': '/target' }).toString();
        const result = await challenge(buildTurnstileRequest(qs, 'example.com'), buildRTIResponse()) as any;
        expect(result.status).toBe('302');
        expect(result.headers.location[0].value).toBe('https://example.com/target');
        expect(result.headers['set-cookie'][0].value).toContain('_cq_se=');
        expect(result.headers['set-cookie'][0].value).toContain('Max-Age=300');
    });

    it('sets the session cookie with exactly Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=<ttl>', async () => {
        stubSiteverify(true);
        const result = await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse('ray-123')) as any;
        expect(result.headers['set-cookie']).toHaveLength(1);
        expect(result.headers['set-cookie'][0].value).toMatch(/^_cq_se=\d+\.[0-9a-f]{32}\|ray-123; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=300$/);
    });

    it('verifies the token with a JSON POST to Cloudflare siteverify, including the client IP, within 1.5 s', async () => {
        const post = stubSiteverify(true);
        await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse());
        expect(siteverifyBody(post)).toEqual({ secret: 'test-turnstile-secret', response: 'valid-token', remoteip: '1.2.3.4' });
        expect(post.mock.calls[0][1]).toBe(1500);
    });

    it('rejects when the siteverify call fails (the handler then fails open)', async () => {
        vi.spyOn(HttpsClient.prototype, 'post').mockRejectedValue(new Error('siteverify unreachable'));
        await expect(challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse())).rejects.toThrow('siteverify unreachable');
    });

    it('uses sessionTtlSeconds for the cookie expiry', async () => {
        const { cookie } = await issueSession('ray-ttl', { ...testSettings, sessionTtlSeconds: 60 }, 1_700_000_000_000);
        expect(cookie).toContain(`_cq_se=${1_700_000_000_000 + 60_000}.`);
    });

    it('sets Max-Age from sessionTtlSeconds', async () => {
        stubSiteverify(true);
        const result = await build({ ...testSettings, sessionTtlSeconds: 60 }).challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse()) as any;
        expect(result.headers['set-cookie'][0].value).toContain('Max-Age=60');
    });

    // --- x-cheq-rti-result: added only on the success 302, through the handler's addRtiResultHeader ---

    it('calls addRtiResultHeader with the success 302 headers', async () => {
        stubSiteverify(true);
        const addRtiResultHeader = vi.fn();
        const result = await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse(), addRtiResultHeader) as any;
        expect(result.status).toBe('302');
        expect(addRtiResultHeader).toHaveBeenCalledOnce();
        expect(addRtiResultHeader).toHaveBeenCalledWith(result.headers);
    });

    it('does not set x-cheq-rti-result itself (works without addRtiResultHeader)', async () => {
        stubSiteverify(true);
        const result = await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse()) as any;
        expect(result.status).toBe('302');
        expect(result.headers['x-cheq-rti-result']).toBeUndefined();
    });

    it('does not call addRtiResultHeader for the challenge page', async () => {
        const addRtiResultHeader = vi.fn();
        await challenge(buildTurnstileRequest(), buildRTIResponse(), addRtiResultHeader);
        expect(addRtiResultHeader).not.toHaveBeenCalled();
    });

    it('does not call addRtiResultHeader when verification fails', async () => {
        stubSiteverify(false);
        const addRtiResultHeader = vi.fn();
        await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse(), addRtiResultHeader);
        expect(addRtiResultHeader).not.toHaveBeenCalled();
    });

    // --- Redirect target (as in Akamai's reCAPTCHA challenge: host from the request, path checked) ---

    it('redirects to the Host header and the request URI when no cheq_original_url is given', async () => {
        stubSiteverify(true);
        const result = await challenge(buildTurnstileRequest(solvedQuery, 'example.com'), buildRTIResponse()) as any;
        expect(result.headers.location[0].value).toBe('https://example.com/page');
    });

    it('ignores a viewer_host query parameter (it used to set the redirect host: an open redirect)', async () => {
        stubSiteverify(true);
        const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'valid-token', 'viewer_host': 'evil.com', 'cheq_original_url': '/target' }).toString();
        const result = await challenge(buildTurnstileRequest(qs, 'example.com'), buildRTIResponse()) as any;
        expect(result.headers.location[0].value).toBe('https://example.com/target');
    });

    it('keeps the query string of an accepted cheq_original_url', async () => {
        stubSiteverify(true);
        const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'valid-token', 'cheq_original_url': '/search?q=shoes&page=2' }).toString();
        const result = await challenge(buildTurnstileRequest(qs, 'example.com'), buildRTIResponse()) as any;
        expect(result.headers.location[0].value).toBe('https://example.com/search?q=shoes&page=2');
    });

    it.each(['//evil.com', '/\\evil.com', 'https://evil.com/x', '@evil.com', '.evil.com', 'evil.com', ''])(
        'rejects cheq_original_url %j and redirects to the request URI instead', async (originalUrl) => {
            stubSiteverify(true);
            const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'valid-token', 'cheq_original_url': originalUrl }).toString();
            const result = await challenge(buildTurnstileRequest(qs, 'example.com'), buildRTIResponse()) as any;
            expect(result.headers.location[0].value).toBe('https://example.com/page');
        });

    it('uses a relative Location when the request has no Host header', async () => {
        stubSiteverify(true);
        const result = await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse()) as any;
        expect(result.headers.location[0].value).toBe('/page');
    });

    it('does not put a viewer_host field in the challenge form', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse()) as any;
        expect(result.body).not.toContain('viewer_host');
    });

    it('returns 403 with error message when Turnstile verification fails', async () => {
        stubSiteverify(false);
        const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'bad-token' }).toString();
        const result = await challenge(buildTurnstileRequest(qs), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('Verification failed');
        expect(result.headers?.['set-cookie']).toBeUndefined();
    });
});

describe('challenge flow hardening', () => {
    const withUa = (request: CloudFrontRequest, ua: string) => {
        request.headers['user-agent'] = [{ key: 'User-Agent', value: ua }];
        return request;
    };

    // Issue 5: query string after the challenge

    it('keeps the query string in the return URL of the challenge page', async () => {
        const result = await challenge(buildTurnstileRequest('utm_source=google&gclid=TeSt123'), buildRTIResponse()) as any;
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page?utm_source=google&amp;gclid=TeSt123"');
        expect(result.body).toContain('action="/page?cheq_challenge=1&amp;cheq_original_url=%2Fpage%3Futm_source%3Dgoogle%26gclid%3DTeSt123"');
    });

    it('redirects to the original path and query once solved', async () => {
        stubSiteverify(true);
        const qs = new URLSearchParams({ cheq_challenge: '1', 'cheq_original_url': '/page?utm_source=google&gclid=TeSt123', 'cf-turnstile-response': 'valid-token' }).toString();
        const result = await challenge(buildTurnstileRequest(qs, 'example.com'), buildRTIResponse()) as any;
        expect(result.headers.location[0].value).toBe('https://example.com/page?utm_source=google&gclid=TeSt123');
    });

    // Issue 7: control characters in cheq_original_url

    it.each(['/\t/evil.com', '/\n/evil.com', '/\r/evil.com', '/x\u0000y', '/\u007f/evil.com'])(
        'rejects cheq_original_url %j (browsers strip tab/CR/LF, turning it protocol-relative)', async (originalUrl) => {
            stubSiteverify(true);
            const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'valid-token', 'cheq_original_url': originalUrl }).toString();
            const result = await challenge(buildTurnstileRequest(qs), buildRTIResponse()) as any;
            expect(result.headers.location[0].value).toBe('/page');
        });

    // Issue 8: siteverify errors and the failed-verification page

    it('throws (handler fails open) when siteverify answers non-2xx', async () => {
        vi.spyOn(HttpsClient.prototype, 'post').mockResolvedValue({ status: 500, statusText: 'Internal Server Error', body: '{}' });
        await expect(challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse())).rejects.toThrow('HTTP 500');
    });

    it('throws (handler fails open) when siteverify returns a body that is not JSON', async () => {
        vi.spyOn(HttpsClient.prototype, 'post').mockResolvedValue({ status: 200, statusText: 'OK', body: '<html>Bad gateway</html>' });
        await expect(challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse())).rejects.toThrow('Unexpected token');
    });

    it('does not use fetch for siteverify (undici hung after a Lambda freeze: 503)', async () => {
        const fetchSpy = vi.fn();
        vi.stubGlobal('fetch', fetchSpy);
        stubSiteverify(true);
        await challenge(buildTurnstileRequest(solvedQuery), buildRTIResponse());
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('shows the widget again with an error after a failed verification (no dead end), not cacheable', async () => {
        stubSiteverify(false);
        const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'bad-token', 'cheq_original_url': '/page?gclid=1' }).toString();
        const result = await challenge(buildTurnstileRequest(qs, 'example.com'), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('class="cf-turnstile"');
        expect(result.body).toContain('role="alert"');
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page?gclid=1"');
        expect(result.headers['cache-control'][0].value).toContain('no-store');
    });

    // Issue 9: hostname, action, Referer

    it.each([
        ['another action', { action: 'login' }],
        ['no action', { action: undefined }],
        ['another hostname', { hostname: 'evil.example' }],
    ])('refuses a valid token with %s', async (_label, answer) => {
        stubSiteverify(true, answer);
        const result = await challenge(buildTurnstileRequest(solvedQuery, 'example.com'), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.headers['set-cookie']).toBeUndefined();
    });

    it('sets data-action on the widget', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse()) as any;
        expect(result.body).toContain('data-action="cheq-challenge"');
    });

    it('sends Referrer-Policy: no-referrer and no-store on the challenge page and the 302', async () => {
        const page = await challenge(buildTurnstileRequest(), buildRTIResponse()) as any;
        stubSiteverify(true);
        const redirect = await challenge(buildTurnstileRequest(solvedQuery, 'example.com'), buildRTIResponse()) as any;
        for (const result of [page, redirect]) {
            expect(result.headers['referrer-policy'][0].value).toBe('no-referrer');
            expect(result.headers['cache-control'][0].value).toContain('no-store');
        }
    });

    // Issue 10: debug logs, strict expiry, User-Agent binding

    it('never logs the cookie or session token in debug mode', async () => {
        const { cookie, token } = await issueSession('ray-log');
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await validateChallenge(buildRequest(cookie), true);
        const logged = consoleSpy.mock.calls.flat().join('\n');
        expect(logged).not.toContain(token);
        expect(logged).not.toContain(token.split('.')[1]);
    });

    it.each(['abc', '17e5', '1.5', '-1'])('rejects a session whose expiry is %j followed by a valid-looking signature', async (expiry) => {
        const { signature } = await issueSession('ray-x');
        expect(await validateChallenge(buildRequest(`_cq_se=${expiry}.${signature}|ray-x`), false)).toBe(false);
    });

    it('rejects an expiry with trailing junk that parseInt would have accepted', async () => {
        const { expiresAt, signature } = await issueSession('ray-x');
        expect(await validateChallenge(buildRequest(`_cq_se=${expiresAt}abc.${signature}|ray-x`), false)).toBe(false);
    });

    it('binds the session to the User-Agent that solved the challenge', async () => {
        stubSiteverify(true);
        const issued = await challenge(withUa(buildTurnstileRequest(solvedQuery), 'Browser A'), buildRTIResponse('ray-ua')) as any;
        const cookie = issued.headers['set-cookie'][0].value.split(';')[0];
        expect(await validateChallenge(withUa(buildRequest(cookie), 'Browser A'), false)).toBe(true);
        expect(await validateChallenge(withUa(buildRequest(cookie), 'python-requests/2.31'), false)).toBe(false);
    });

    // The challenge's own parameters never nest into the return URL

    it('drops stale cf-turnstile-response / cheq_original_url / cheq_request_id from the return URL, keeps the rest', async () => {
        const qs = new URLSearchParams({ cheq_original_url: '/shop', cheq_request_id: 'ray-old', gclid: '1', utm_source: 'ad' }).toString();
        const result = await challenge(buildTurnstileRequest(qs), buildRTIResponse()) as any;
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page?gclid=1&amp;utm_source=ad"');
        expect(result.body).not.toContain('ray-old');
    });

    it('returns to the bare path when only challenge parameters were in the query', async () => {
        const result = await challenge(buildTurnstileRequest('cheq_original_url=%2Fshop&cheq_request_id=r1'), buildRTIResponse()) as any;
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page"');
    });

    // Hostname check on origin-request, where Host may be the origin's domain

    const originHostRequest = (qs: string) => buildTurnstileRequest(qs, 'alb-123.us-east-1.elb.amazonaws.com');

    it('without allowedHostnames, a token solved on the viewer host is refused when the Lambda sees the origin Host (documents G11)', async () => {
        stubSiteverify(true, { hostname: 'www.shop.com' });
        const result = await challenge(originHostRequest(solvedQuery), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.headers['set-cookie']).toBeUndefined();
    });

    it('with allowedHostnames, accepts a token solved on a listed host and redirects there, not to the Host header', async () => {
        stubSiteverify(true, { hostname: 'www.shop.com' });
        const qs = new URLSearchParams({ cheq_challenge: '1', 'cf-turnstile-response': 'valid-token', cheq_original_url: '/products/1?gclid=9' }).toString();
        const result = await build({ ...testSettings, allowedHostnames: ['shop.com', 'www.shop.com'] }).challenge(originHostRequest(qs), buildRTIResponse()) as any;
        expect(result.status).toBe('302');
        expect(result.headers.location[0].value).toBe('https://www.shop.com/products/1?gclid=9');
        expect(result.headers['set-cookie'][0].value).toContain('_cq_se=');
    });

    it.each([
        ['another hostname', { hostname: 'evil.example' }],
        ['no hostname', { hostname: undefined }],
    ])('with allowedHostnames, refuses a token with %s', async (_label, answer) => {
        stubSiteverify(true, answer);
        const result = await build({ ...testSettings, allowedHostnames: ['www.shop.com'] }).challenge(originHostRequest(solvedQuery), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
    });

    it('treats an empty allowedHostnames list as unset (Host header check applies)', async () => {
        stubSiteverify(true); // hostname example.com
        const result = await build({ ...testSettings, allowedHostnames: [] }).challenge(buildTurnstileRequest(solvedQuery, 'example.com'), buildRTIResponse()) as any;
        expect(result.status).toBe('302');
        expect(result.headers.location[0].value).toBe('https://example.com/page');
    });

    // POST-based verification, cheq_ parameter names, raw query, fragment

    const postAnswer = (form: Record<string, string>, host = 'example.com', query = 'cheq_challenge=1'): CloudFrontRequest => {
        const request = buildTurnstileRequest(query, host);
        (request as any).method = 'POST';
        (request as any).body = { data: Buffer.from(new URLSearchParams(form).toString()).toString('base64'), encoding: 'base64', inputTruncated: false };
        return request;
    };

    it('serves a POST form by default, marked in the action query, with cheq_-prefixed fields', async () => {
        const result = await challenge(buildTurnstileRequest('gclid=1'), buildRTIResponse('ray-1')) as any;
        expect(result.body).toContain('action="/page?cheq_challenge=1&amp;cheq_original_url=%2Fpage%3Fgclid%3D1" method="POST"');
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page?gclid=1"');
        expect(result.body).toContain('name="cheq_request_id" value="ray-1"');
        expect(result.body).not.toContain('name="original_url"');
    });

    it('serves a GET form with a bare action when submitMethod is "GET"', async () => {
        const result = await build({ ...testSettings, submitMethod: 'GET' }).challenge(buildTurnstileRequest('gclid=1'), buildRTIResponse()) as any;
        expect(result.body).toContain('action="/page" method="GET"');
    });

    it('verifies a POSTed answer from the base64 body and redirects to the original URL, query and fragment intact', async () => {
        const post = stubSiteverify(true);
        const result = await challenge(postAnswer({ 'cf-turnstile-response': 'tok-1', cheq_original_url: '/page?a=1&a=2&q=hello%20world#top', cheq_request_id: 'r' }), buildRTIResponse()) as any;
        expect(result.status).toBe('302');
        expect(result.headers.location[0].value).toBe('https://example.com/page?a=1&a=2&q=hello%20world#top');
        expect(result.headers['set-cookie'][0].value).toContain('_cq_se=');
        expect(siteverifyBody(post).response).toBe('tok-1');
    });

    it('falls back to the return URL in the action query when the POST body lacks it', async () => {
        stubSiteverify(true);
        const result = await challenge(postAnswer({ 'cf-turnstile-response': 'tok-1' }, 'example.com', 'cheq_challenge=1&cheq_original_url=%2Fshop%3Fx%3D1'), buildRTIResponse()) as any;
        expect(result.headers.location[0].value).toBe('https://example.com/shop?x=1');
    });

    it('answers a POST without a body (IncludeBody off) with a GET form and an error, and logs it', async () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const request = buildTurnstileRequest('cheq_challenge=1&cheq_original_url=%2Fshop%3Fx%3D1', 'example.com');
        (request as any).method = 'POST';
        const result = await challenge(request, buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('method="GET"');
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/shop?x=1"');
        expect(result.body).toContain('role="alert"');
        expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('IncludeBody'));
    });

    it('treats a POST with an empty body as a missing token: POST retry page, no IncludeBody error', async () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const request = buildTurnstileRequest('cheq_challenge=1&cheq_original_url=%2Fshop%3Fx%3D1', 'example.com');
        (request as any).method = 'POST';
        (request as any).body = { data: '', encoding: 'base64', inputTruncated: false };
        const result = await challenge(request, buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('method="POST"');
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/shop?x=1"');
        expect(errorSpy).not.toHaveBeenCalled();
    });

    it('keeps the return URL from the form when a POSTed answer has no token (widget reset before submit)', async () => {
        const result = await challenge(postAnswer({ cheq_original_url: '/page?gclid=1&utm_source=ad' }), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page?gclid=1&amp;utm_source=ad"');
    });

    it('ignores a stale token in a GET without the marker: serves the widget, no siteverify call', async () => {
        const post = stubSiteverify(true);
        const result = await challenge(buildTurnstileRequest('cf-turnstile-response=stale&gclid=1'), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('name="cheq_original_url" id="cheq-original-url" value="/page?gclid=1"');
        expect(post).not.toHaveBeenCalled();
    });

    it('marks the GET form with cheq_challenge=1 as a hidden field', async () => {
        const result = await challenge(buildTurnstileRequest('gclid=1'), buildRTIResponse(), undefined) as any;
        const getForm = await challenge(buildTurnstileRequest('cheq_challenge=1&cheq_original_url=%2Fpage', 'example.com'), buildRTIResponse()) as any;
        expect(result.body).not.toContain('name="cheq_challenge"');
        expect(getForm.body).toContain('method="POST"');
        const request = buildTurnstileRequest('cheq_challenge=1', 'example.com');
        (request as any).method = 'POST';
        vi.spyOn(console, 'error').mockImplementation(() => {});
        const fallback = await challenge(request, buildRTIResponse()) as any;
        expect(fallback.body).toContain('method="GET"');
        expect(fallback.body).toContain('name="cheq_challenge" value="1"');
    });

    it('logs why siteverify rejected a token (codes, action, hostname), never the token', async () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        vi.spyOn(HttpsClient.prototype, 'post').mockResolvedValue({ status: 200, statusText: 'OK', body: JSON.stringify({ success: false, 'error-codes': ['invalid-input-secret'] }) } as any);
        const result = await challenge(postAnswer({ 'cf-turnstile-response': 'secret-token-value', cheq_original_url: '/page' }), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('invalid-input-secret'));
        expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('expected=example.com'));
        expect(errorSpy.mock.calls.flat().join(' ')).not.toContain('secret-token-value');
    });

    it('shows the retry page again (POST form) when a POSTed token fails', async () => {
        stubSiteverify(false);
        const result = await challenge(postAnswer({ 'cf-turnstile-response': 'bad', cheq_original_url: '/page?gclid=1' }), buildRTIResponse()) as any;
        expect(result.status).toBe('403');
        expect(result.body).toContain('role="alert"');
        expect(result.body).toContain('method="POST"');
        expect(result.body).toContain('value="/page?gclid=1"');
    });

    it.each([
        ['POST with the marker', 'POST', 'cheq_challenge=1', true],
        ['POST without the marker (a normal form)', 'POST', 'return=%2Faccount', false],
        ['GET with the marker and a token (GET form)', 'GET', 'cheq_challenge=1&cf-turnstile-response=x', true],
        ['GET with a token but no marker (crafted or foreign link)', 'GET', 'cf-turnstile-response=x', false],
        ['GET with the marker but an empty token', 'GET', 'cheq_challenge=1&cf-turnstile-response=', false],
        ['GET without a token', 'GET', 'gclid=1', false],
        ['PUT with the marker', 'PUT', 'cheq_challenge=1', false],
    ])('isChallengeAnswer: %s → %s', (_label, method, query, expected) => {
        const request = buildTurnstileRequest(query);
        (request as any).method = method;
        expect(build(testSettings).isChallengeAnswer!(request)).toBe(expected);
    });

    it('keeps the query string raw: percent-encoding, +, duplicate names and order', async () => {
        const result = await challenge(buildTurnstileRequest('q=hello%20world&a=1&b=x+y&a=2&x=%2F%3F'), buildRTIResponse()) as any;
        expect(result.body).toContain('value="/page?q=hello%20world&amp;a=1&amp;b=x+y&amp;a=2&amp;x=%2F%3F"');
    });

    it('does not strip the site\'s own original_url / request_id parameters (only the cheq_ ones)', async () => {
        const result = await challenge(buildTurnstileRequest('original_url=keep&request_id=keep&cheq_request_id=old&gclid=3'), buildRTIResponse()) as any;
        expect(result.body).toContain('value="/page?original_url=keep&amp;request_id=keep&amp;gclid=3"');
    });

    it('carries the fragment from the browser into the return URL (client-side script)', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse()) as any;
        expect(result.body).toContain("if (location.hash && originalUrl.value.indexOf('#') === -1) { originalUrl.value += location.hash; }");
    });

    // Issue 12: challenge page load and spinner

    it('loads no Google Fonts and preconnects to Turnstile', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse()) as any;
        expect(result.body).not.toContain('fonts.googleapis.com');
        expect(result.body).toContain('<link rel="preconnect" href="https://challenges.cloudflare.com">');
    });

    it('resets the spinner on bfcache restore and on widget error, expiry or timeout', async () => {
        const result = await challenge(buildTurnstileRequest(), buildRTIResponse()) as any;
        expect(result.body).toContain("addEventListener('pageshow'");
        for (const cb of ['data-error-callback', 'data-expired-callback', 'data-timeout-callback']) {
            expect(result.body).toContain(`${cb}="onTurnstileReset"`);
        }
    });
});
