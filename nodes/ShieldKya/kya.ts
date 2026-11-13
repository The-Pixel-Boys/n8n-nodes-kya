// Shared, dependency-free helpers for the Shield KYA nodes (only node:crypto).
// Kept free of n8n runtime imports so test/*.test.js can exercise it from dist/.
import { createHash, createHmac, timingSafeEqual } from 'crypto';

export const SIGNATURE_HEADER = 'x-shield-agent-signature';
export const EVENT_ID_HEADER = 'x-shield-agent-event-id';
export const DEFAULT_REPLAY_WINDOW_SECONDS = 300;

export type VerifyFailure = 'missing' | 'malformed' | 'stale' | 'mismatch';
export type VerifyResult = { ok: true; t: number } | { ok: false; reason: VerifyFailure };

/**
 * Verify `X-Shield-Agent-Signature: t=<unix>,v1=<hex>` over the RAW body bytes
 * (docs/dev/kya-approval-notify-webhook.md section 5). Never re-serialize JSON before this:
 * Jackson and JSON.stringify differ on escaping.
 */
export function verifySignature(
	secret: string,
	header: string | undefined,
	rawBody: Buffer,
	nowSeconds: number,
	windowSeconds: number = DEFAULT_REPLAY_WINDOW_SECONDS,
): VerifyResult {
	if (!secret || !header || !header.trim()) return { ok: false, reason: 'missing' };
	let t: number | undefined;
	const candidates: string[] = [];
	for (const part of header.split(',')) {
		const eq = part.indexOf('=');
		if (eq <= 0) continue;
		const key = part.slice(0, eq).trim();
		const value = part.slice(eq + 1).trim();
		if (key === 't') {
			if (!/^\d{1,12}$/.test(value)) return { ok: false, reason: 'malformed' };
			t = Number(value);
		} else if (key === 'v1' && /^[0-9a-fA-F]{64}$/.test(value)) {
			candidates.push(value.toLowerCase());
		}
	}
	if (t === undefined || candidates.length === 0) return { ok: false, reason: 'malformed' };
	if (Math.abs(nowSeconds - t) > windowSeconds) return { ok: false, reason: 'stale' };
	const expected = Buffer.from(hmacHex(secret, t, rawBody), 'utf8');
	// Several v1 entries are allowed (secret rotation); each compare is constant time.
	let match = false;
	for (const c of candidates) {
		if (timingSafeEqual(expected, Buffer.from(c, 'utf8'))) match = true;
	}
	return match ? { ok: true, t } : { ok: false, reason: 'mismatch' };
}

export function signatureHeader(secret: string, t: number, rawBody: Buffer): string {
	return `t=${t},v1=${hmacHex(secret, t, rawBody)}`;
}

function hmacHex(secret: string, t: number, rawBody: Buffer): string {
	return createHmac('sha256', secret).update(`${t}.`, 'utf8').update(rawBody).digest('hex');
}

/**
 * Per-webhook signing secret, derived so no secret sits in workflow static data
 * (which is exported with the workflow). Rotating the API key changes it; the trigger
 * notices through the stored fingerprint and re-registers.
 */
export function deriveWebhookSecret(apiKey: string, webhookUrl: string): string {
	return createHmac('sha256', apiKey).update(`shield-kya-n8n-webhook-v1:${webhookUrl}`).digest('hex');
}

/**
 * Binds a stored subscription to the identity that created it: n8n credential id, KYA workspace
 * (tenant) id from the authenticated registration response, the derived secret (so the API key)
 * and the webhook URL. Any change (credential swapped or rotated, other workspace, other URL)
 * changes the binding, and deliveries are refused until the trigger re-registers.
 */
export function subscriptionBinding(credentialId: string, tenantId: string, secret: string, webhookUrl: string): string {
	return createHmac('sha256', secret)
		.update(`shield-kya-binding-v1|${credentialId}|${tenantId}|${webhookUrl}`)
		.digest('hex')
		.slice(0, 32);
}

export function fingerprint(value: string): string {
	return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

/** Same as sdks/kya/src/hash.ts: sorted keys, no whitespace, then sha256 hex. */
export function canonicalJson(value: unknown): string {
	return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
	if (value === null || typeof value !== 'object') return value;
	if (Array.isArray(value)) return value.map(sortKeys);
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) out[key] = sortKeys(obj[key]);
	return out;
}

export function computeArgsHash(args: unknown): string {
	return createHash('sha256')
		.update(canonicalJson(args === undefined ? {} : args), 'utf8')
		.digest('hex');
}

/** Same binding as sdks/kya factoryWorkItemId (UUID v3 of "kya.factory:" + argsHash). */
export function factoryWorkItemId(argsHash: string): string {
	const b = createHash('md5').update('kya.factory:' + argsHash.trim(), 'utf8').digest();
	b[6] = (b[6] & 0x0f) | 0x30;
	b[8] = (b[8] & 0x3f) | 0x80;
	const h = b.toString('hex');
	return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export const CLOUD_ORIGIN = 'https://shield-agent.com';

/**
 * Control-plane origin. No user-typed URL is ever used: the hosted cloud origin is fixed, and the
 * only alternative is the test-only loopback plane (http://127.0.0.1:<port>), chosen explicitly in
 * the credential. Anything else is undefined (callers refuse to send the API key).
 */
export function planeOrigin(plane: unknown, loopbackPort: unknown): string | undefined {
	if (plane === undefined || plane === null || plane === '' || plane === 'cloud') return CLOUD_ORIGIN;
	if (plane === 'loopbackTest') {
		const port = Number(loopbackPort);
		if (Number.isInteger(port) && port >= 1 && port <= 65535) return `http://127.0.0.1:${port}`;
	}
	return undefined;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
	return typeof value === 'string' && UUID_RE.test(value);
}

/**
 * The one place a request URL is built: parsed once with WHATWG URL, and the result must keep
 * exactly the planned origin and path (no "..", "//host", query or fragment smuggled in). A query
 * comes only from code, as key/value pairs encoded by URLSearchParams. The returned href is what
 * gets requested.
 */
export function apiUrl(origin: string, path: string, query?: Record<string, string | number | undefined>): string | undefined {
	if (!path.startsWith('/api/v1/kya/')) return undefined;
	let u: URL;
	try {
		u = new URL(path, origin);
	} catch {
		return undefined;
	}
	if (u.origin !== origin || u.pathname !== path || u.search !== '' || u.hash !== '' || u.username !== '' || u.password !== '') {
		return undefined;
	}
	if (query) {
		const qs = new URLSearchParams();
		for (const [k, v] of Object.entries(query)) {
			if (v !== undefined && v !== '') qs.set(k, String(v));
		}
		u.search = qs.toString();
		if (u.origin !== origin || u.pathname !== path || u.hash !== '') return undefined;
	}
	return u.href;
}

/** Remove every occurrence of the given secrets from text shown to users or logs. */
export function redact(text: string, secrets: Array<string | undefined>): string {
	let out = text;
	for (const s of secrets) {
		if (s && s.length >= 4) out = out.split(s).join('[redacted]');
	}
	return out;
}

export interface HttpResult {
	statusCode: number;
	headers: Record<string, unknown>;
	body: unknown;
}

export interface RetryOptions {
	/** Total attempts including the first (1..6). */
	maxAttempts: number;
	/** Retry 5xx too (only for calls that are safe to repeat). */
	retryServerErrors: boolean;
	baseDelayMs?: number;
	maxDelayMs?: number;
	sleep: (ms: number) => Promise<void>;
	random?: () => number;
	nowMs?: () => number;
}

export type RetryOutcome =
	| { ok: true; response: HttpResult; attempts: number }
	| { ok: false; response: HttpResult; attempts: number; reason: string };

/** Retry-After as seconds or HTTP-date, in ms; undefined when absent or unparsable. */
export function parseRetryAfter(value: unknown, nowMs: number): number | undefined {
	const raw = Array.isArray(value) ? value[0] : value;
	if (raw === undefined || raw === null || raw === '') return undefined;
	const s = String(raw).trim();
	if (/^\d+$/.test(s)) return Number(s) * 1000;
	const date = Date.parse(s);
	return Number.isNaN(date) ? undefined : Math.max(0, date - nowMs);
}

function headerValue(headers: Record<string, unknown>, name: string): unknown {
	for (const [k, v] of Object.entries(headers ?? {})) {
		if (k.toLowerCase() === name) return v;
	}
	return undefined;
}

/**
 * Bounded retry with jitter. 429 always retries (the rate limiter rejects before the
 * request runs); 5xx only when retryServerErrors. Honours Retry-After, but a server asking
 * for longer than maxDelayMs fails at once instead of parking the workflow. Never swallows:
 * the caller gets ok:false with the last response and must raise it.
 */
export async function sendWithRetry(
	send: () => Promise<HttpResult>,
	opts: RetryOptions,
): Promise<RetryOutcome> {
	const maxAttempts = Math.min(6, Math.max(1, Math.floor(opts.maxAttempts)));
	const base = opts.baseDelayMs ?? 500;
	const cap = opts.maxDelayMs ?? 30_000;
	const random = opts.random ?? Math.random;
	const now = opts.nowMs ?? Date.now;
	let attempt = 0;
	for (;;) {
		attempt++;
		const response = await send();
		const status = response.statusCode;
		if (status >= 200 && status < 300) return { ok: true, response, attempts: attempt };
		const retryable = status === 429 || (opts.retryServerErrors && status >= 500 && status <= 599);
		if (!retryable) return { ok: false, response, attempts: attempt, reason: `HTTP ${status}` };
		if (attempt >= maxAttempts) {
			return {
				ok: false,
				response,
				attempts: attempt,
				reason: `HTTP ${status} after ${attempt} attempt(s)`,
			};
		}
		const retryAfter = parseRetryAfter(headerValue(response.headers, 'retry-after'), now());
		if (retryAfter !== undefined && retryAfter > cap) {
			return {
				ok: false,
				response,
				attempts: attempt,
				reason: `HTTP ${status}, server asked to wait ${Math.ceil(retryAfter / 1000)}s (over the ${Math.ceil(cap / 1000)}s limit)`,
			};
		}
		const backoff = Math.min(cap, base * 2 ** (attempt - 1));
		// Retry-After is a floor; jitter spreads concurrent workflows apart.
		const delay =
			retryAfter !== undefined
				? Math.min(cap, retryAfter + Math.floor(random() * base))
				: Math.floor(random() * backoff);
		await opts.sleep(delay);
	}
}
