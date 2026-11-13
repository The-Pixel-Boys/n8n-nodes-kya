import type {
	IDataObject,
	IHookFunctions,
	IHttpRequestMethods,
	INodeType,
	INodeTypeDescription,
	IWebhookFunctions,
	IWebhookResponseData,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import {
	deriveWebhookSecret,
	EVENT_ID_HEADER,
	redact,
	apiUrl,
	isUuid,
	planeOrigin,
	SIGNATURE_HEADER,
	subscriptionBinding,
	verifySignature,
} from '../ShieldKya/kya';
import type { HttpResult } from '../ShieldKya/kya';

// ponytail: in-process dedupe. n8n 2.x drops node static data written in webhook() whenever that
// request starts an execution (the execution's Workflow resets the change flag), so static data
// cannot hold this. Ceiling: lost on restart and not shared between webhook processes in queue
// mode; a redelivery across those can run the workflow twice. Upgrade path: a hosted
// list-events cursor or dedupe on `id` downstream (nodes/N16/hosted-gaps.md).
const SEEN_LIMIT = 1000;
const seenEvents = new Map<string, true>();

/** True the first time a key is seen; bounded FIFO. */
export function firstSighting(key: string): boolean {
	if (seenEvents.has(key)) return false;
	seenEvents.set(key, true);
	if (seenEvents.size > SEEN_LIMIT) seenEvents.delete(seenEvents.keys().next().value as string);
	return true;
}

// ponytail: static data is per workflow and per n8n database. Several n8n instances sharing one
// KYA workspace each register their own subscription; in queue mode every worker reads the same
// workflow static data, so the binding check below holds there too.
interface TriggerState {
	webhookId?: string;
	/** KYA workspace id from the authenticated registration response, never from a payload. */
	tenantId?: string;
	/** subscriptionBinding(credential id, tenantId, secret, URL) at registration time. */
	binding?: string;
}

function wipe(state: TriggerState): void {
	delete state.webhookId;
	delete state.tenantId;
	delete state.binding;
}

type BindingSource = Pick<IHookFunctions, 'getNode' | 'getCredentials' | 'getNodeWebhookUrl'>;

/** Binding for the CURRENT credential and URL, plus the secret it implies. */
async function currentBinding(ctx: BindingSource, tenantId: string): Promise<{ binding: string; secret: string; url: string }> {
	const creds = await ctx.getCredentials('shieldKyaApi');
	const url = ctx.getNodeWebhookUrl('default') as string;
	const secret = deriveWebhookSecret(String(creds.apiKey ?? ''), url);
	const credentialId = String(ctx.getNode().credentials?.shieldKyaApi?.id ?? '');
	return { binding: subscriptionBinding(credentialId, tenantId, secret, url), secret, url };
}

async function kyaCall(
	ctx: IHookFunctions,
	method: IHttpRequestMethods,
	path: string,
	body?: IDataObject,
): Promise<{ result: HttpResult; apiKey: string }> {
	const creds = await ctx.getCredentials('shieldKyaApi');
	const apiKey = String(creds.apiKey ?? '');
	const origin = planeOrigin(creds.plane, creds.loopbackPort);
	const url = origin ? apiUrl(origin, path) : undefined;
	if (!url) {
		throw new NodeOperationError(ctx.getNode(), 'Refusing to send the Shield KYA API key: unknown control plane or unsafe path');
	}
	const result = (await ctx.helpers.httpRequestWithAuthentication.call(ctx, 'shieldKyaApi', {
		method,
		url,
		// Never follow redirects: the API key header must not reach another origin.
		disableFollowRedirect: true,
		body,
		json: true,
		timeout: 30_000,
		returnFullResponse: true,
		ignoreHttpStatusErrors: true,
	})) as HttpResult;
	return { result, apiKey };
}

function fail(ctx: IHookFunctions, what: string, result: HttpResult, apiKey: string): never {
	const body = result.body as { error?: { message?: unknown } } | undefined;
	const detail = body?.error?.message ? `: ${String(body.error.message).slice(0, 200)}` : '';
	const message = redact(`Shield KYA could not ${what} (HTTP ${result.statusCode})${detail}`, [apiKey]);
	throw new NodeApiError(ctx.getNode(), { message, httpCode: String(result.statusCode) } as JsonObject, {
		message,
		httpCode: String(result.statusCode),
	});
}

export class ShieldKyaTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Shield KYA Trigger',
		name: 'shieldKyaTrigger',
		icon: { light: 'file:shieldKya.svg', dark: 'file:shieldKya.svg' },
		group: ['trigger'],
		version: [1],
		subtitle: '={{$parameter["events"].join(", ")}}',
		description:
			'Starts the workflow on signed Shield KYA events (pending approvals, DENY and REQUIRE_APPROVE verdicts). Receiving an event never approves anything.',
		defaults: { name: 'Shield KYA Trigger' },
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		credentials: [{ name: 'shieldKyaApi', required: true }],
		webhooks: [
			{
				name: 'default',
				httpMethod: 'POST',
				responseMode: 'onReceived',
				path: 'webhook',
			},
		],
		properties: [
			{
				displayName:
					'Shield KYA only delivers to public HTTPS URLs. A local or http-only n8n cannot receive these events: use a Schedule Trigger with Shield KYA > List Events instead.',
				name: 'notice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Events',
				name: 'events',
				type: 'multiOptions',
				required: true,
				options: [
					{
						name: 'Approval Approved',
						value: 'kya.approval.approved',
						description: 'A human approved. Only Shield KYA lets the agent act; this event approves nothing.',
					},
					{
						name: 'Approval Expired',
						value: 'kya.approval.expired',
						description: 'Nobody decided before the workspace TTL. Treat as not approved.',
					},
					{
						name: 'Approval Pending',
						value: 'kya.approval.pending',
						description: 'A human approval was opened and waits for a decision',
					},
					{
						name: 'Approval Rejected',
						value: 'kya.approval.rejected',
						description: 'A human rejected. The agent must not act.',
					},
					{
						name: 'Incident Opened',
						value: 'kya.incident.opened',
						description: 'A hosted investigation opened a critical or high incident',
					},
					{
						name: 'Policy Evaluated',
						value: 'kya.policy.evaluated',
						description: 'An evaluate returned DENY or REQUIRE_APPROVE (never sent for ALLOW)',
					},
				],
				default: ['kya.approval.pending'],
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Replay Window Seconds',
						name: 'replayWindowSeconds',
						type: 'number',
						typeOptions: { minValue: 30, maxValue: 900 },
						default: 300,
						description: 'Reject events whose signature timestamp is further than this from now',
					},
				],
			},
		],
	};

	webhookMethods = {
		default: {
			async checkExists(this: IHookFunctions): Promise<boolean> {
				const state = this.getWorkflowStaticData('node') as TriggerState;
				if (!isUuid(state.webhookId) || !isUuid(state.tenantId) || !state.binding) {
					wipe(state);
					return false;
				}
				const { binding, url } = await currentBinding(this, state.tenantId);
				const { result, apiKey } = await kyaCall(this, 'GET', `/api/v1/kya/webhooks/${state.webhookId}`);
				if (result.statusCode === 404) {
					wipe(state);
					return false;
				}
				if (result.statusCode !== 200) fail(this, 'read the webhook', result, apiKey);
				const remote = result.body as { url?: string; eventTypes?: string[]; enabled?: boolean; merchantId?: string };
				// Manual test listen for another URL: leave the production registration alone (n8n keeps
				// test static data separate). Outside manual mode a different URL means this instance moved
				// (new WEBHOOK_URL, rotated tunnel host): fall through and delete it, or it would keep
				// sending signed events to the old host with nothing left to deregister it.
				if (remote.url !== url && this.getMode() === 'manual') return false;
				const events = (this.getNodeParameter('events') as string[]).slice().sort().join(',');
				const current =
					remote.enabled !== false &&
					remote.merchantId === state.tenantId &&
					(remote.eventTypes ?? []).slice().sort().join(',') === events &&
					state.binding === binding;
				if (current) return true;
				// Same URL but other events, credential, key or workspace: never reuse it. Delete it
				// (a 404 means it lives in another workspace this key cannot reach) and register fresh.
				const old = await kyaCall(this, 'DELETE', `/api/v1/kya/webhooks/${state.webhookId}`);
				if (![204, 404].includes(old.result.statusCode)) fail(this, 'replace the stale webhook', old.result, old.apiKey);
				wipe(state);
				return false;
			},
			async create(this: IHookFunctions): Promise<boolean> {
				const state = this.getWorkflowStaticData('node') as TriggerState;
				wipe(state);
				const creds = await this.getCredentials('shieldKyaApi');
				const url = this.getNodeWebhookUrl('default') as string;
				const secret = deriveWebhookSecret(String(creds.apiKey ?? ''), url);
				const { result, apiKey } = await kyaCall(this, 'POST', '/api/v1/kya/webhooks', {
					url,
					eventTypes: this.getNodeParameter('events') as string[],
					secret,
					enabled: true,
					description: `n8n workflow ${this.getWorkflow().id ?? ''}`.trim(),
				});
				if (result.statusCode !== 201 && result.statusCode !== 200) {
					fail(this, 'register the webhook', result, apiKey);
				}
				const body = result.body as { id?: unknown; merchantId?: unknown; url?: unknown };
				// Both go into later checks or paths: accept only UUIDs, and only our own URL back.
				if (!isUuid(body.id) || !isUuid(body.merchantId) || body.url !== url) {
					fail(this, 'register the webhook (no valid id, workspace or URL returned)', result, apiKey);
				}
				const { binding } = await currentBinding(this, body.merchantId);
				state.webhookId = body.id;
				state.tenantId = body.merchantId;
				state.binding = binding;
				return true;
			},
			async delete(this: IHookFunctions): Promise<boolean> {
				const state = this.getWorkflowStaticData('node') as TriggerState;
				if (isUuid(state.webhookId)) {
					const { result, apiKey } = await kyaCall(this, 'DELETE', `/api/v1/kya/webhooks/${state.webhookId}`);
					if (result.statusCode !== 204 && result.statusCode !== 404) fail(this, 'delete the webhook', result, apiKey);
				}
				wipe(state);
				return true;
			},
		},
	};

	async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const req = this.getRequestObject();
		const res = this.getResponseObject();
		const state = this.getWorkflowStaticData('node') as TriggerState;
		// 1. The stored subscription must belong to the CURRENT credential, key, workspace and URL.
		//    Swapped, rotated or deleted credential: refuse until the trigger is re-registered.
		const bound = isUuid(state.tenantId) && state.binding ? await currentBinding(this, state.tenantId) : undefined;
		if (!bound || bound.binding !== state.binding) {
			res.status(401).json({ error: 'invalid_signature', reason: 'subscription_not_bound' });
			return { noWebhookResponse: true };
		}
		const secret = bound.secret;
		const options = this.getNodeParameter('options', {}) as IDataObject;
		const windowSeconds = Number(options.replayWindowSeconds ?? 300);
		const r = req as unknown as { rawBody?: Buffer; readRawBody?: () => Promise<void> };
		if (!r.rawBody && r.readRawBody) await r.readRawBody();
		const raw = r.rawBody;
		const header = req.headers[SIGNATURE_HEADER];
		const verdict = verifySignature(
			secret,
			Array.isArray(header) ? header[0] : header,
			Buffer.isBuffer(raw) ? raw : Buffer.alloc(0),
			Math.floor(Date.now() / 1000),
			windowSeconds,
		);
		if (!verdict.ok) {
			// Do not echo the payload or say which check failed beyond a stable code.
			res.status(401).json({ error: 'invalid_signature', reason: verdict.reason });
			return { noWebhookResponse: true };
		}
		let event: IDataObject;
		try {
			event = JSON.parse(raw!.toString('utf8')) as IDataObject;
		} catch {
			res.status(400).json({ error: 'invalid_json' });
			return { noWebhookResponse: true };
		}
		// 4. Workspace comes from the authenticated registration, never from the payload; the
		//    payload only has to agree with it.
		if (event.tenantId !== state.tenantId) {
			res.status(401).json({ error: 'invalid_signature', reason: 'tenant_mismatch' });
			return { noWebhookResponse: true };
		}
		const id = String(event.id ?? req.headers[EVENT_ID_HEADER] ?? '');
		if (id && !firstSighting(`${this.getWorkflow().id ?? ''}:${id}`)) {
			// At-least-once delivery: acknowledge, do not run the workflow twice.
			res.status(200).json({ ok: true, duplicate: true });
			return { noWebhookResponse: true };
		}
		const events = this.getNodeParameter('events') as string[];
		if (!events.includes(String(event.type))) {
			res.status(200).json({ ok: true, ignored: true });
			return { noWebhookResponse: true };
		}
		return { workflowData: [this.helpers.returnJsonArray([event])] };
	}
}
