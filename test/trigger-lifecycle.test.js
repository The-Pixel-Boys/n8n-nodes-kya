// Trigger webhookMethods and webhook() against a scripted HTTP layer: which URLs get the API key,
// when a registration is kept, replaced or left alone, and that deliveries are accepted only for
// the subscription bound to the CURRENT credential, key, workspace and URL.
const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldKyaTrigger } = require('../dist/nodes/ShieldKyaTrigger/ShieldKyaTrigger.node.js');
const kya = require('../dist/nodes/ShieldKya/kya.js');

const KEY = 'lifecycle-test-key-1';
const KEY2 = 'lifecycle-test-key-2';
const URL_PROD = 'https://n8n.example.com/webhook/abc/webhook';
const URL_B = 'https://n8n.example.com/webhook/other/webhook';
const OLD = '11111111-1111-4111-8111-111111111111';
const NEW = '22222222-2222-4222-8222-222222222222';
const TENANT = '7c1e0d2a-1111-4222-8333-944455556666';
const TENANT2 = '99999999-9999-4999-8999-999999999999';
const CRED = 'cred-1';
const trigger = new ShieldKyaTrigger();
const methods = trigger.webhookMethods.default;

const bindingFor = ({ credId = CRED, tenant = TENANT, key = KEY, url = URL_PROD } = {}) =>
	kya.subscriptionBinding(credId, tenant, kya.deriveWebhookSecret(key, url), url);
const boundState = (over = {}) => ({ webhookId: OLD, tenantId: TENANT, binding: bindingFor(), ...over });

function ctx({ responses = [], state = {}, events = ['kya.approval.pending'], url = URL_PROD, key = KEY, plane = 'cloud', credId = CRED, mode = 'trigger' }) {
	const calls = [];
	return {
		calls,
		state,
		getMode: () => mode,
		getWorkflowStaticData: () => state,
		getCredentials: async () => ({ apiKey: key, plane }),
		getNodeWebhookUrl: () => url,
		getNodeParameter: () => events,
		getNode: () => ({ name: 'KYA Trigger', type: 'shieldKyaTrigger', typeVersion: 1, parameters: {}, credentials: { shieldKyaApi: { id: credId, name: credId } } }),
		getWorkflow: () => ({ id: 'wf1' }),
		helpers: {
			httpRequestWithAuthentication: async (cred, opts) => {
				calls.push({ cred, ...opts });
				return responses.shift();
			},
		},
	};
}
const remote = (over = {}) => ({ statusCode: 200, headers: {}, body: { id: OLD, merchantId: TENANT, url: URL_PROD, eventTypes: ['kya.approval.pending'], enabled: true, ...over } });
const created = (over = {}) => ({ statusCode: 201, headers: {}, body: { id: NEW, merchantId: TENANT, url: URL_PROD, ...over } });

test('create: fixed origin, redirects disabled, state bound to credential + workspace + key + URL', async () => {
	const c = ctx({ responses: [created()], state: { webhookId: OLD, tenantId: TENANT2, binding: 'stale' } });
	assert.equal(await methods.create.call(c), true);
	assert.equal(c.calls.length, 1);
	assert.equal(c.calls[0].url, 'https://shield-agent.com/api/v1/kya/webhooks');
	assert.equal(c.calls[0].disableFollowRedirect, true);
	assert.equal(c.calls[0].body.secret, kya.deriveWebhookSecret(KEY, URL_PROD));
	assert.ok(!JSON.stringify(c.calls[0].body).includes(KEY));
	assert.deepEqual(c.state, { webhookId: NEW, tenantId: TENANT, binding: bindingFor() });
});

test('create: refuses a response without UUID id, UUID workspace or our URL; keeps no state', async () => {
	for (const bad of [{ id: '../../evil' }, { merchantId: 'acme' }, { merchantId: undefined }, { url: 'https://evil.example/hook' }]) {
		const c = ctx({ responses: [created(bad)], state: boundState() });
		await assert.rejects(methods.create.call(c), /no valid id, workspace or URL/, JSON.stringify(bad));
		assert.deepEqual(c.state, {}, JSON.stringify(bad));
	}
});

test('an unknown control plane never sends the key', async () => {
	const c = ctx({ plane: 'https://evil.example' });
	await assert.rejects(methods.create.call(c), /Refusing to send/);
	assert.equal(c.calls.length, 0);
});

test('checkExists: current bound registration is kept', async () => {
	const c = ctx({ responses: [remote()], state: boundState() });
	assert.equal(await methods.checkExists.call(c), true);
	assert.deepEqual(c.calls.map((x) => x.method), ['GET']);
	assert.equal(c.calls[0].url, `https://shield-agent.com/api/v1/kya/webhooks/${OLD}`);
});

test('checkExists: incomplete or unbound stored state is never reused (no request, wiped)', async () => {
	for (const st of [{ webhookId: OLD }, { webhookId: OLD, tenantId: TENANT }, { webhookId: OLD, binding: bindingFor() }, { webhookId: '../x', tenantId: TENANT, binding: bindingFor() }]) {
		const c = ctx({ state: { ...st } });
		assert.equal(await methods.checkExists.call(c), false, JSON.stringify(st));
		assert.equal(c.calls.length, 0);
		assert.deepEqual(c.state, {});
	}
});

test('checkExists: manual test listen leaves a registration for another URL alone', async () => {
	const c = ctx({ mode: 'manual', responses: [remote({ url: 'https://n8n.example.com/webhook-test/abc/webhook' })], state: boundState() });
	assert.equal(await methods.checkExists.call(c), false);
	assert.deepEqual(c.calls.map((x) => x.method), ['GET']);
	assert.equal(c.state.webhookId, OLD);
});

test('checkExists: instance moved (new webhook URL, rotated tunnel host): old registration is deleted, not orphaned', async () => {
	const c = ctx({ url: 'https://new-tunnel.example.com/webhook/abc/webhook', responses: [remote(), { statusCode: 204, headers: {}, body: '' }], state: boundState() });
	assert.equal(await methods.checkExists.call(c), false);
	assert.deepEqual(c.calls.map((x) => `${x.method} ${x.url}`), [`GET https://shield-agent.com/api/v1/kya/webhooks/${OLD}`, `DELETE https://shield-agent.com/api/v1/kya/webhooks/${OLD}`]);
	assert.deepEqual(c.state, {});
});

test('checkExists: stale subscription (events, credential, key, workspace, disabled) is deleted, never reused', async () => {
	for (const [name, opts, rem] of [
		['events changed', {}, remote({ eventTypes: ['kya.incident.opened'] })],
		['credential swapped', { credId: 'cred-2' }, remote()],
		['key rotated', { key: KEY2 }, remote()],
		['workspace differs on the server', {}, remote({ merchantId: TENANT2 })],
		['disabled', {}, remote({ enabled: false })],
	]) {
		const c = ctx({ responses: [rem, { statusCode: 204, headers: {}, body: '' }], state: boundState(), ...opts });
		assert.equal(await methods.checkExists.call(c), false, name);
		assert.deepEqual(c.calls.map((x) => `${x.method} ${x.url}`), [`GET https://shield-agent.com/api/v1/kya/webhooks/${OLD}`, `DELETE https://shield-agent.com/api/v1/kya/webhooks/${OLD}`], name);
		assert.deepEqual(c.state, {}, name);
	}
});

test('checkExists: 404 wipes; other errors fail loudly without echoing the key', async () => {
	const c = ctx({ responses: [{ statusCode: 404, headers: {}, body: {} }], state: boundState() });
	assert.equal(await methods.checkExists.call(c), false);
	assert.deepEqual(c.state, {});
	const e = ctx({ responses: [{ statusCode: 401, headers: {}, body: { error: { message: `bad key ${KEY}` } } }], state: boundState() });
	await assert.rejects(methods.checkExists.call(e), (err) => {
		assert.match(err.message, /HTTP 401/);
		assert.ok(!err.message.includes(KEY));
		return true;
	});
});

test('delete: deregisters remotely and wipes id, workspace and binding (404 too)', async () => {
	for (const status of [204, 404]) {
		const c = ctx({ responses: [{ statusCode: status, headers: {}, body: '' }], state: boundState() });
		assert.equal(await methods.delete.call(c), true);
		assert.deepEqual(c.calls.map((x) => `${x.method} ${x.url}`), [`DELETE https://shield-agent.com/api/v1/kya/webhooks/${OLD}`]);
		assert.deepEqual(c.state, {});
	}
});

test('a redirect answer is an error, not followed', async () => {
	const c = ctx({ responses: [{ statusCode: 302, headers: { location: 'https://evil.example/' }, body: '' }] });
	await assert.rejects(methods.create.call(c), /HTTP 302/);
	assert.equal(c.calls.length, 1);
});

// ---- webhook() ----
function hookCtx({ raw, header, url = URL_PROD, state = boundState(), key = KEY, credId = CRED, window }) {
	const res = { code: undefined, body: undefined, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
	return {
		res,
		getRequestObject: () => ({ rawBody: Buffer.from(raw), headers: header === undefined ? {} : { 'x-shield-agent-signature': header } }),
		getResponseObject: () => res,
		getWorkflowStaticData: () => state,
		getCredentials: async () => ({ apiKey: key, plane: 'cloud' }),
		getNode: () => ({ name: 'KYA Trigger', credentials: { shieldKyaApi: { id: credId, name: credId } } }),
		getNodeWebhookUrl: () => url,
		getNodeParameter: (name) => (name === 'events' ? ['kya.approval.pending'] : window ? { replayWindowSeconds: window } : {}),
		getWorkflow: () => ({ id: 'wf-hook' }),
		helpers: { returnJsonArray: (a) => a.map((json) => ({ json })) },
	};
}
const secretA = kya.deriveWebhookSecret(KEY, URL_PROD);
const now = () => Math.floor(Date.now() / 1000);
const webhook = trigger.webhook;
let seq = 0;
const eventBody = (over = {}) => JSON.stringify({ id: `evt_hook_${Date.now()}_${seq++}`, type: 'kya.approval.pending', tenantId: TENANT, data: {}, ...over });
const signed = (body, secret = secretA, t = now()) => kya.signatureHeader(secret, t, Buffer.from(body));

test('webhook: valid bound delivery runs; duplicate id does not', async () => {
	const body = eventBody();
	const ok = hookCtx({ raw: body, header: signed(body) });
	const out = await webhook.call(ok);
	assert.equal(out.workflowData[0][0].json.type, 'kya.approval.pending');
	const again = hookCtx({ raw: body, header: signed(body) });
	assert.deepEqual(await webhook.call(again), { noWebhookResponse: true });
	assert.equal(again.res.code, 200);
});

test('webhook: subscription not bound to the current identity is refused before the signature', async () => {
	for (const [name, opts] of [
		['no stored binding (never registered / after deactivate)', { state: {} }],
		['credential swapped', { credId: 'cred-2' }],
		['key rotated in the credential (old-secret delivery)', { key: KEY2 }],
		['stored workspace altered', { state: boundState({ tenantId: TENANT2 }) }],
		['stored binding from another URL', { state: boundState({ binding: bindingFor({ url: URL_B }) }) }],
	]) {
		const body = eventBody();
		const c = hookCtx({ raw: body, header: signed(body), ...opts });
		assert.deepEqual(await webhook.call(c), { noWebhookResponse: true }, name);
		assert.equal(c.res.code, 401, name);
		assert.equal(c.res.body.reason, 'subscription_not_bound', name);
	}
});

test('webhook: delivery signed for another subscription (cross-delivery) is refused', async () => {
	const stateB = { webhookId: NEW, tenantId: TENANT, binding: bindingFor({ url: URL_B }) };
	const body = eventBody();
	const c = hookCtx({ raw: body, header: signed(body, secretA), url: URL_B, state: stateB });
	await webhook.call(c);
	assert.equal(c.res.code, 401);
	assert.equal(c.res.body.reason, 'mismatch');
	const own = hookCtx({ raw: body, header: signed(body, kya.deriveWebhookSecret(KEY, URL_B)), url: URL_B, state: stateB });
	assert.ok((await webhook.call(own)).workflowData, 'B accepts its own signature');
});

test('webhook: payload from another workspace is refused; workspace never taken from the payload', async () => {
	for (const tenantId of [TENANT2, undefined, '']) {
		const body = eventBody({ tenantId });
		const c = hookCtx({ raw: body, header: signed(body) });
		await webhook.call(c);
		assert.equal(c.res.code, 401, String(tenantId));
		assert.equal(c.res.body.reason, 'tenant_mismatch');
	}
});

test('webhook: signature is checked before the body is parsed', async () => {
	for (const header of [undefined, 'garbage', signed('not json', 'wrong')]) {
		const c = hookCtx({ raw: 'not json', header });
		assert.deepEqual(await webhook.call(c), { noWebhookResponse: true });
		assert.equal(c.res.code, 401, String(header));
	}
	const signedGarbage = hookCtx({ raw: 'not json', header: signed('not json') });
	await webhook.call(signedGarbage);
	assert.equal(signedGarbage.res.code, 400);
});

test('webhook: replay window enforced', async () => {
	const body = eventBody();
	const stale = hookCtx({ raw: body, header: signed(body, secretA, now() - 301) });
	await webhook.call(stale);
	assert.equal(stale.res.code, 401);
	assert.equal(stale.res.body.reason, 'stale');
});
