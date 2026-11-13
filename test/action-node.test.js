// ShieldKya.execute against a scripted HTTP layer: URL, redirect policy, no raw args, fail closed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldKya } = require('../dist/nodes/ShieldKya/ShieldKya.node.js');
const kya = require('../dist/nodes/ShieldKya/kya.js');

const KEY = 'action-test-key-1';
function ctx({ params, responses, creds = { apiKey: KEY, plane: 'cloud' }, continueOnFail = false, input = {} }) {
	const calls = [];
	return {
		calls,
		getInputData: () => [{ json: input }],
		getNodeParameter: (name, _i, fallback) => (name in params ? params[name] : fallback),
		getCredentials: async () => creds,
		getNode: () => ({ name: 'Shield KYA', type: 'shieldKya', typeVersion: 1, parameters: {} }),
		continueOnFail: () => continueOnFail,
		helpers: {
			httpRequestWithAuthentication: async (cred, opts) => {
				calls.push({ cred, ...opts });
				return responses.shift();
			},
		},
	};
}
const evalParams = { operation: 'evaluate', toolId: 'org.example.data.write', toolArguments: '{"secret":"RAW-ARG-SENTINEL"}', host: 'runtime', additionalFields: {}, options: { maxAttempts: 1 } };
const run = (c) => new ShieldKya().execute.call(c);

test('evaluate: exact cloud URL, redirects disabled, only the hash is sent', async () => {
	const c = ctx({ params: evalParams, responses: [{ statusCode: 200, headers: {}, body: { verdict: 'ALLOW', reasonCode: 'OK' } }] });
	const [[item]] = await run(c);
	assert.equal(item.json.verdict, 'ALLOW');
	assert.equal(c.calls[0].url, 'https://shield-agent.com/api/v1/kya/policy/evaluate');
	assert.equal(c.calls[0].disableFollowRedirect, true);
	assert.equal(c.calls[0].body.argsHash, kya.computeArgsHash({ secret: 'RAW-ARG-SENTINEL' }));
	assert.ok(!JSON.stringify(c.calls[0]).includes('RAW-ARG-SENTINEL'));
	assert.ok(!JSON.stringify(c.calls[0].body).includes(KEY));
});

test('unknown control plane: refused before any request', async () => {
	for (const plane of ['https://evil.example', 'loopbacktest', 'custom']) {
		const c = ctx({ params: evalParams, responses: [], creds: { apiKey: KEY, plane } });
		await assert.rejects(run(c), /Unknown control plane/);
		assert.equal(c.calls.length, 0, plane);
	}
});

test('get approval: a non-UUID id never reaches the URL', async () => {
	const c = ctx({ params: { operation: 'getApproval', approvalId: '../../webhooks', options: {} }, responses: [] });
	await assert.rejects(run(c), /must be a UUID/);
	assert.equal(c.calls.length, 0);
});

test('redirect answer is an error, never a verdict; key not echoed', async () => {
	const c = ctx({ params: evalParams, responses: [{ statusCode: 302, headers: { location: 'https://evil.example/' }, body: { error: { message: `see ${KEY}` } } }] });
	await assert.rejects(run(c), (err) => {
		assert.match(err.message, /HTTP 302/);
		assert.ok(!err.message.includes(KEY));
		return true;
	});
	assert.equal(c.calls.length, 1);
});

test('continueOnFail: error item has failedClosed and no verdict', async () => {
	const c = ctx({ params: evalParams, continueOnFail: true, responses: [{ statusCode: 401, headers: {}, body: { error: { message: 'invalid or revoked API key' } } }] });
	const [[item]] = await run(c);
	assert.equal(item.json.failedClosed, true);
	assert.ok(!('verdict' in item.json));
});

test('a 200 without a valid verdict is an error', async () => {
	const c = ctx({ params: evalParams, responses: [{ statusCode: 200, headers: {}, body: { verdict: 'MAYBE' } }] });
	await assert.rejects(run(c), /no valid verdict/);
});

test('invalid Tool Arguments: fixed message, the argument text never appears (also under Continue On Fail)', async () => {
	for (const raw of ['SECRET-ARG-VALUE', 'card 4111111111111111', '{"k": SECRET-ARG-VALUE}']) {
		const params = { ...evalParams, toolArguments: raw };
		const c = ctx({ params, responses: [] });
		await assert.rejects(run(c), (err) => {
			assert.equal(err.message, 'Tool Arguments must be valid JSON');
			assert.ok(!JSON.stringify(err).includes('SECRET') && !JSON.stringify(err).includes('4111'), JSON.stringify(err));
			return true;
		});
		assert.equal(c.calls.length, 0);
		const cof = ctx({ params, responses: [], continueOnFail: true });
		const [[item]] = await run(cof);
		assert.equal(item.json.error, 'Tool Arguments must be valid JSON');
		assert.ok(!JSON.stringify(item).includes('SECRET') && !JSON.stringify(item).includes('4111'));
	}
});

test('request approval: 5xx is not retried (creating an approval is not idempotent); 429 is', async () => {
	const params = { operation: 'requestApproval', agentId: '11111111-2222-4333-8444-555555555555', toolId: 'org.example.data.write', toolArguments: '{}', host: 'runtime', approvalFields: {}, options: { maxAttempts: 3, maxWaitSeconds: 1 } };
	const c = ctx({ params, responses: [{ statusCode: 503, headers: {}, body: {} }, { statusCode: 201, headers: {}, body: { id: 'x', status: 'PENDING' } }] });
	await assert.rejects(run(c), /server error/);
	assert.equal(c.calls.length, 1);
	const r = ctx({ params, responses: [{ statusCode: 429, headers: { 'retry-after': '0' }, body: {} }, { statusCode: 201, headers: {}, body: { id: 'x', status: 'PENDING' } }] });
	const [[item]] = await run(r);
	assert.equal(item.json.status, 'PENDING');
	assert.equal(r.calls.length, 2);
});

test('continueOnFail: an upstream verdict on the input item is never passed through', async () => {
	const c = ctx({ params: evalParams, continueOnFail: true, input: { verdict: 'ALLOW', other: 1 }, responses: [{ statusCode: 500, headers: {}, body: {} }] });
	const [[item]] = await run(c);
	assert.equal(item.json.failedClosed, true);
	assert.ok(!('verdict' in item.json));
	assert.ok(!('other' in item.json));
});

test('list events: encoded query on the exact cloud path, one item per event, newest first', async () => {
	const events = [
		{ id: 'evt_kya_approved_0f9b2a1e3c4d4e5f8a9b0c1d2e3f4a5b', type: 'kya.approval.approved', data: { status: 'APPROVED' } },
		{ id: 'evt_kya_pending_0f9b2a1e3c4d4e5f8a9b0c1d2e3f4a5b', type: 'kya.approval.pending', data: { status: 'PENDING' } },
	];
	const params = {
		operation: 'listEvents',
		eventTypes: ['kya.approval.approved', 'kya.approval.pending', 'not.a.type&x=1'],
		afterEventId: 'evt_kya_pending_00000000000000000000000000000000',
		limit: 10,
		options: { maxAttempts: 1 },
	};
	const c = ctx({ params, responses: [{ statusCode: 200, headers: {}, body: events }] });
	const [items] = await run(c);
	assert.deepEqual(items.map((i) => i.json.id), events.map((e) => e.id));
	assert.equal(c.calls[0].method, 'GET');
	assert.equal(c.calls[0].url,
		'https://shield-agent.com/api/v1/kya/events?types=kya.approval.approved%2Ckya.approval.pending&after=evt_kya_pending_00000000000000000000000000000000&limit=10');
	assert.equal(c.calls[0].disableFollowRedirect, true);
});

test('list events: a bad cursor never reaches the URL; a non-array answer is an error', async () => {
	for (const after of ['../webhooks', 'evt_kya_pending_1&limit=1000', 'x#y']) {
		const c = ctx({ params: { operation: 'listEvents', eventTypes: [], afterEventId: after, limit: 5, options: {} }, responses: [] });
		await assert.rejects(run(c), /After Event ID/);
		assert.equal(c.calls.length, 0, after);
	}
	const c = ctx({ params: { operation: 'listEvents', eventTypes: [], afterEventId: '', limit: 5, options: { maxAttempts: 1 } },
		responses: [{ statusCode: 200, headers: {}, body: { verdict: 'ALLOW' } }] });
	await assert.rejects(run(c), /not a JSON array/);
	assert.equal(c.calls[0].url, 'https://shield-agent.com/api/v1/kya/events?limit=5');
});

test('list events: with After Event ID, full pages are followed with before until a short page', async () => {
	const id = (n) => `evt_kya_pending_${String(n).padStart(32, '0')}`;
	const page1 = [{ id: id(5) }, { id: id(4) }];
	const page2 = [{ id: id(3) }, { id: id(2) }];
	const page3 = [{ id: id(1) }];
	const params = { operation: 'listEvents', eventTypes: [], afterEventId: id(0), limit: 2, options: { maxAttempts: 1 } };
	const c = ctx({ params, responses: [page1, page2, page3].map((body) => ({ statusCode: 200, headers: {}, body })) });
	const [items] = await run(c);
	assert.deepEqual(items.map((i) => i.json.id), [id(5), id(4), id(3), id(2), id(1)]);
	assert.equal(c.calls.length, 3);
	assert.ok(!c.calls[0].url.includes('before='));
	assert.ok(c.calls[1].url.includes(`before=${id(4)}`) && c.calls[1].url.includes(`after=${id(0)}`));
	assert.ok(c.calls[2].url.includes(`before=${id(2)}`));
});

test('list events: without After Event ID, one page only', async () => {
	const id = (n) => `evt_kya_pending_${String(n).padStart(32, '0')}`;
	const c = ctx({ params: { operation: 'listEvents', eventTypes: [], afterEventId: '', limit: 2, options: { maxAttempts: 1 } },
		responses: [{ statusCode: 200, headers: {}, body: [{ id: id(2) }, { id: id(1) }] }] });
	const [items] = await run(c);
	assert.equal(items.length, 2);
	assert.equal(c.calls.length, 1);
});
