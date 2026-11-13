// Unit tests for the shared helpers, run against the compiled dist/ (npm run build first).
const test = require('node:test');
const assert = require('node:assert/strict');
const fixture = require('./fixtures/java-signed.json');
const kya = require('../dist/nodes/ShieldKya/kya.js');

const SECRET = 'unit-test-secret';
const body = Buffer.from('{"id":"evt_1","type":"kya.approval.pending","data":{"toolId":"x"}}');
const NOW = 1_800_000_000;

test('signature: valid header verifies', () => {
	const h = kya.signatureHeader(SECRET, NOW, body);
	assert.deepEqual(kya.verifySignature(SECRET, h, body, NOW), { ok: true, t: NOW });
});

test('signature: Java signer over a Jackson body verifies byte for byte', () => {
	const raw = Buffer.from(fixture.bodyBase64, 'base64');
	assert.equal(kya.verifySignature(fixture.secret, fixture.header, raw, fixture.t).ok, true);
	// Pretty-printed or otherwise re-encoded JSON is not the signed bytes.
	const pretty = Buffer.from(JSON.stringify(JSON.parse(raw.toString('utf8')), null, 1));
	assert.equal(kya.verifySignature(fixture.secret, fixture.header, pretty, fixture.t).reason, 'mismatch');
});

test('signature: tampered body is rejected', () => {
	const h = kya.signatureHeader(SECRET, NOW, body);
	const tampered = Buffer.from(body.toString().replace('"x"', '"y"'));
	assert.deepEqual(kya.verifySignature(SECRET, h, tampered, NOW), { ok: false, reason: 'mismatch' });
});

test('signature: wrong secret is rejected', () => {
	const h = kya.signatureHeader('other-secret', NOW, body);
	assert.equal(kya.verifySignature(SECRET, h, body, NOW).reason, 'mismatch');
});

test('signature: tampered timestamp breaks the MAC', () => {
	const h = kya.signatureHeader(SECRET, NOW, body).replace(`t=${NOW}`, `t=${NOW + 1}`);
	assert.equal(kya.verifySignature(SECRET, h, body, NOW).reason, 'mismatch');
});

test('signature: replay outside the window is rejected, edges inside pass', () => {
	const h = kya.signatureHeader(SECRET, NOW, body);
	assert.equal(kya.verifySignature(SECRET, h, body, NOW + 300, 300).ok, true);
	assert.equal(kya.verifySignature(SECRET, h, body, NOW + 301, 300).reason, 'stale');
	assert.equal(kya.verifySignature(SECRET, h, body, NOW - 301, 300).reason, 'stale');
});

test('signature: missing or empty header and empty secret are rejected', () => {
	assert.equal(kya.verifySignature(SECRET, undefined, body, NOW).reason, 'missing');
	assert.equal(kya.verifySignature(SECRET, '  ', body, NOW).reason, 'missing');
	assert.equal(kya.verifySignature('', kya.signatureHeader('x', NOW, body), body, NOW).reason, 'missing');
});

test('signature: malformed headers are rejected', () => {
	for (const h of ['garbage', `t=${NOW}`, 'v1=' + 'a'.repeat(64), `t=abc,v1=${'a'.repeat(64)}`, `t=${NOW},v1=short`]) {
		assert.equal(kya.verifySignature(SECRET, h, body, NOW).ok, false, h);
	}
});

test('signature: one matching v1 among several (rotation) verifies', () => {
	const good = kya.signatureHeader(SECRET, NOW, body).split('v1=')[1];
	const h = `t=${NOW},v1=${'0'.repeat(64)},v1=${good.toUpperCase()}`;
	assert.equal(kya.verifySignature(SECRET, h, body, NOW).ok, true);
});

test('argsHash and work item id match the KYA SDK vectors', () => {
	// Produced by sdks/kya dist/hash.js (computeArgsHash, factoryWorkItemId).
	const args = { b: [3, { z: 1, a: 'ü…' }], a: null, é: true };
	assert.equal(kya.computeArgsHash(args), '6a5b56085e22931c78d68efd995db4b254407fa54981f1c99dcd868e5dd725d3');
	assert.equal(kya.factoryWorkItemId(kya.computeArgsHash(args)), '13ecc7cd-05d1-3b12-892b-872364cf4f4a');
	assert.equal(kya.factoryWorkItemId('abc'), 'd9ae0e1a-72ee-3eb2-8df2-c512286989dc');
	assert.equal(kya.factoryWorkItemId(kya.computeArgsHash({})), '418bd044-015c-3bee-a74f-671c881efca3');
});

test('derived webhook secret depends on key and URL, fingerprint does not leak it', () => {
	const a = kya.deriveWebhookSecret('key-1', 'https://n8n.example.com/webhook/1');
	assert.notEqual(a, kya.deriveWebhookSecret('key-2', 'https://n8n.example.com/webhook/1'));
	assert.notEqual(a, kya.deriveWebhookSecret('key-1', 'https://n8n.example.com/webhook/2'));
	const fp = kya.fingerprint(a);
	assert.equal(fp, require('node:crypto').createHash('sha256').update(a).digest('hex').slice(0, 16));
	assert.ok(!a.includes(fp));
});

test('redact removes the API key everywhere and ignores short or empty values', () => {
	const key = 'kya-test-key-123456';
	assert.equal(kya.redact(`bad ${key} and ${key}`, [key]), 'bad [redacted] and [redacted]');
	assert.equal(kya.redact('abc', ['', undefined, 'ab']), 'abc');
});

function scripted(responses) {
	const calls = [];
	return {
		calls,
		send: async () => {
			calls.push(Date.now());
			return responses.shift();
		},
	};
}
const ok = { statusCode: 200, headers: {}, body: { verdict: 'ALLOW' } };
const r429 = (ra) => ({ statusCode: 429, headers: ra === undefined ? {} : { 'Retry-After': ra }, body: {} });

test('backoff: 429 then 200 honours Retry-After plus bounded jitter', async () => {
	const sleeps = [];
	const s = scripted([r429('2'), ok]);
	const out = await kya.sendWithRetry(s.send, {
		maxAttempts: 4, retryServerErrors: true, sleep: async (ms) => sleeps.push(ms), random: () => 0.5,
	});
	assert.equal(out.ok, true);
	assert.equal(out.attempts, 2);
	assert.deepEqual(sleeps, [2000 + 250]);
});

test('backoff: exhausted 429 fails with the last response, never swallowed', async () => {
	const sleeps = [];
	const s = scripted([r429('1'), r429('1'), r429('1')]);
	const out = await kya.sendWithRetry(s.send, { maxAttempts: 3, retryServerErrors: true, sleep: async (ms) => sleeps.push(ms), random: () => 0 });
	assert.equal(out.ok, false);
	assert.equal(out.response.statusCode, 429);
	assert.equal(out.attempts, 3);
	assert.match(out.reason, /429 after 3 attempt/);
	assert.deepEqual(sleeps, [1000, 1000]);
});

test('backoff: Retry-After above the cap fails at once without sleeping', async () => {
	const sleeps = [];
	const out = await kya.sendWithRetry(scripted([r429('600')]).send, {
		maxAttempts: 4, retryServerErrors: true, maxDelayMs: 30_000, sleep: async (ms) => sleeps.push(ms),
	});
	assert.equal(out.ok, false);
	assert.equal(out.attempts, 1);
	assert.match(out.reason, /600s/);
	assert.deepEqual(sleeps, []);
});

test('backoff: HTTP-date Retry-After uses the injected clock', async () => {
	const sleeps = [];
	const now = Date.parse('2026-10-14T10:00:00Z');
	const out = await kya.sendWithRetry(scripted([r429('Wed, 14 Oct 2026 10:00:05 GMT'), ok]).send, {
		maxAttempts: 2, retryServerErrors: false, sleep: async (ms) => sleeps.push(ms), random: () => 0, nowMs: () => now,
	});
	assert.equal(out.ok, true);
	assert.deepEqual(sleeps, [5000]);
});

test('backoff: 5xx retries with exponential full jitter only when allowed', async () => {
	const sleeps = [];
	const r503 = { statusCode: 503, headers: {}, body: {} };
	const out = await kya.sendWithRetry(scripted([r503, r503, ok]).send, {
		maxAttempts: 4, retryServerErrors: true, baseDelayMs: 500, sleep: async (ms) => sleeps.push(ms), random: () => 0.999,
	});
	assert.equal(out.ok, true);
	assert.deepEqual(sleeps, [499, 999]);
	const noRetry = await kya.sendWithRetry(scripted([r503, ok]).send, { maxAttempts: 4, retryServerErrors: false, sleep: async () => assert.fail('slept') });
	assert.equal(noRetry.ok, false);
	assert.equal(noRetry.attempts, 1);
});

test('backoff: 401 and 400 are never retried', async () => {
	for (const statusCode of [400, 401, 403, 404]) {
		const out = await kya.sendWithRetry(scripted([{ statusCode, headers: {}, body: {} }, ok]).send, {
			maxAttempts: 4, retryServerErrors: true, sleep: async () => assert.fail('slept'),
		});
		assert.equal(out.ok, false);
		assert.equal(out.attempts, 1);
	}
});

test('backoff: attempts are clamped to 1..6', async () => {
	const s = scripted(Array.from({ length: 10 }, () => r429('0')));
	const out = await kya.sendWithRetry(s.send, { maxAttempts: 50, retryServerErrors: true, sleep: async () => {} , random: () => 0 });
	assert.equal(out.attempts, 6);
	const one = await kya.sendWithRetry(scripted([r429('0')]).send, { maxAttempts: 0, retryServerErrors: true, sleep: async () => {} });
	assert.equal(one.attempts, 1);
});

test('trigger dedupe: first sighting only, bounded', () => {
	const { firstSighting } = require('../dist/nodes/ShieldKyaTrigger/ShieldKyaTrigger.node.js');
	assert.equal(firstSighting('wf:evt_a'), true);
	assert.equal(firstSighting('wf:evt_a'), false);
	assert.equal(firstSighting('other:evt_a'), true);
	for (let i = 0; i < 1000; i++) firstSighting(`fill:${i}`);
	assert.equal(firstSighting('wf:evt_a'), true, 'oldest entry evicted after 1000 newer ones');
});

const HOSTILE = [
	'https://shield-agent.com@evil.example/', 'https://evil.example\\@shield-agent.com/', '//evil.example',
	'https://evil.example\\shield-agent.com', 'https://shield-\tagent.com', 'https://shield-agent.com\n.evil.example',
	'HTTPS://SHIELD-AGENT.COM', 'https://shield-agent.com.evil.example', 'https://xn--shield-agnt-p7a.com',
	'https://shield-agent.com./', 'https://[::1]/', 'https://shield-agent.com/../evil', 'http://shield-agent.com',
	'https://user:pw@shield-agent.com', 'evil', 'loopbacktest', 'CLOUD',
];

test('control plane: only the fixed cloud origin or explicit 127.0.0.1 test plane', () => {
	assert.equal(kya.planeOrigin(undefined, undefined), 'https://shield-agent.com');
	assert.equal(kya.planeOrigin('cloud', 1), 'https://shield-agent.com');
	assert.equal(kya.planeOrigin('loopbackTest', 18787), 'http://127.0.0.1:18787');
	assert.equal(kya.planeOrigin('loopbackTest', '18787'), 'http://127.0.0.1:18787');
	for (const port of ['1@evil.example', '80/../x', -1, 0, 70000, 1.5, 'abc', '', undefined, '127.0.0.1:80', 'evil.example']) {
		assert.equal(kya.planeOrigin('loopbackTest', port), undefined, `port ${String(port)}`);
	}
	for (const plane of HOSTILE) assert.equal(kya.planeOrigin(plane, 443), undefined, `plane ${JSON.stringify(plane)}`);
});

test('apiUrl: a query only from code, encoded; a query in the path is still refused', () => {
	const origin = 'https://shield-agent.com';
	assert.equal(kya.apiUrl(origin, '/api/v1/kya/events', { types: 'kya.approval.pending', limit: 3, after: undefined }),
		'https://shield-agent.com/api/v1/kya/events?types=kya.approval.pending&limit=3');
	assert.equal(kya.apiUrl(origin, '/api/v1/kya/events', { types: 'a#b&c=@evil.example/x' }),
		'https://shield-agent.com/api/v1/kya/events?types=a%23b%26c%3D%40evil.example%2Fx');
	assert.equal(kya.apiUrl(origin, '/api/v1/kya/events?x=1', { limit: 3 }), undefined);
});

test('apiUrl: the requested href keeps the exact origin and path', () => {
	const origin = 'https://shield-agent.com';
	assert.equal(kya.apiUrl(origin, '/api/v1/kya/policy/evaluate'), 'https://shield-agent.com/api/v1/kya/policy/evaluate');
	assert.equal(kya.apiUrl('http://127.0.0.1:18787', '/api/v1/kya/approvals/0f9b2a1e-3c4d-4e5f-8a9b-0c1d2e3f4a5b'), 'http://127.0.0.1:18787/api/v1/kya/approvals/0f9b2a1e-3c4d-4e5f-8a9b-0c1d2e3f4a5b');
	for (const path of [
		'//evil.example/api/v1/kya/x', '/api/v1/kya/../../evil', '/api/v1/kya/webhooks/../../../x', '/api/v1/kya/x?y=1',
		'/api/v1/kya/x#f', '/api/v1/kya/\\\\evil.example', '/api/v1/kya/a b', 'https://evil.example/api/v1/kya/x',
		'/api/v1/kya/%2e%2e/x', '/api/v1/kya/x\n', '/other', '',
	]) {
		const u = kya.apiUrl(origin, path);
		assert.ok(u === undefined || new URL(u).origin === origin && new URL(u).pathname === path, `path ${JSON.stringify(path)} -> ${u}`);
		assert.equal(u, undefined, `path ${JSON.stringify(path)}`);
	}
	assert.equal(kya.isUuid('0f9b2a1e-3c4d-4e5f-8a9b-0c1d2e3f4a5b'), true);
	for (const id of ['../x', '0f9b2a1e-3c4d-4e5f-8a9b-0c1d2e3f4a5b/../x', '', undefined, 7]) assert.equal(kya.isUuid(id), false);
});
