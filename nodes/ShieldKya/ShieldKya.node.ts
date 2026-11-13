import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError, sleep } from 'n8n-workflow';

import { apiUrl, computeArgsHash, factoryWorkItemId, planeOrigin, redact, sendWithRetry } from './kya';
import type { HttpResult } from './kya';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT_ID_RE = /^evt_kya_[a-z]+_[0-9a-f]{32}$/;
const MAX_PAGES = 20;
const EVENT_TYPE_OPTIONS = [
	{ name: 'Approval Approved', value: 'kya.approval.approved' },
	{ name: 'Approval Expired', value: 'kya.approval.expired' },
	{ name: 'Approval Pending', value: 'kya.approval.pending' },
	{ name: 'Approval Rejected', value: 'kya.approval.rejected' },
	{ name: 'Incident Opened', value: 'kya.incident.opened' },
	{ name: 'Policy Evaluated', value: 'kya.policy.evaluated' },
];
const EVENT_TYPES = new Set(EVENT_TYPE_OPTIONS.map((o) => o.value));

export class ShieldKya implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Shield KYA',
		name: 'shieldKya',
		icon: { light: 'file:shieldKya.svg', dark: 'file:shieldKya.svg' },
		group: ['transform'],
		version: [1],
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Ask the hosted Shield KYA plane for a policy verdict, open or read human approvals, and list recent events. Errors stop the workflow and never produce a verdict.',
		defaults: { name: 'Shield KYA' },
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		credentials: [{ name: 'shieldKyaApi', required: true }],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Evaluate',
						value: 'evaluate',
						description: 'Get ALLOW, DENY or REQUIRE_APPROVE for a tool call',
						action: 'Evaluate a tool call',
					},
					{
						name: 'Get Approval',
						value: 'getApproval',
						description: 'Read the status of a human approval',
						action: 'Get an approval',
					},
					{
						name: 'List Events',
						value: 'listEvents',
						description:
							'Read recent signed KYA events (newest first). Use with a Schedule Trigger when n8n has no public HTTPS URL.',
						action: 'List recent events',
					},
					{
						name: 'Request Approval',
						value: 'requestApproval',
						description: 'Open a pending human approval in Shield KYA',
						action: 'Request an approval',
					},
				],
				default: 'evaluate',
			},
			{
				displayName: 'Tool ID',
				name: 'toolId',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'org.example.data.write',
				description: 'Stable tool identifier the policy is written against',
				displayOptions: { show: { operation: ['evaluate', 'requestApproval'] } },
			},
			{
				displayName: 'Agent ID',
				name: 'agentId',
				type: 'string',
				required: true,
				default: '',
				description: 'UUID of the registered agent that wants to act',
				displayOptions: { show: { operation: ['requestApproval'] } },
			},
			{
				displayName: 'Tool Arguments',
				name: 'toolArguments',
				type: 'json',
				default: '{}',
				description:
					'Arguments of the tool call. They are hashed inside n8n (sha256 of canonical JSON); only the hash is sent to Shield KYA, never the values.',
				displayOptions: { show: { operation: ['evaluate', 'requestApproval'] } },
			},
			{
				displayName: 'Host',
				name: 'host',
				type: 'options',
				options: [
					{ name: 'Runtime', value: 'runtime' },
					{ name: 'IDE', value: 'ide' },
				],
				default: 'runtime',
				description: 'Where the agent runs',
				displayOptions: { show: { operation: ['evaluate', 'requestApproval'] } },
			},
			{
				displayName: 'Approval ID',
				name: 'approvalId',
				type: 'string',
				required: true,
				default: '',
				description: 'UUID returned by Request Approval',
				displayOptions: { show: { operation: ['getApproval'] } },
			},
			{
				displayName: 'Event Types',
				name: 'eventTypes',
				type: 'multiOptions',
				options: EVENT_TYPE_OPTIONS,
				default: [],
				description: 'Empty means all types',
				displayOptions: { show: { operation: ['listEvents'] } },
			},
			{
				displayName: 'After Event ID',
				name: 'afterEventId',
				type: 'string',
				default: '',
				placeholder: 'evt_kya_pending_0f9b2a1e3c4d4e5f8a9b0c1d2e3f4a5b',
				description:
					'Only events newer than this one (the newest ID you already processed). The node then reads pages of Limit events (up to 20 pages) until it has every newer event. Empty: one page of the most recent events of the last 30 days.',
				displayOptions: { show: { operation: ['listEvents'] } },
			},
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: 100 },
				default: 50,
				description: 'Max number of results to return',
				displayOptions: { show: { operation: ['listEvents'] } },
			},
			{
				displayName: 'Additional Fields',
				name: 'additionalFields',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				displayOptions: { show: { operation: ['evaluate'] } },
				options: [
					{
						displayName: 'Action Class',
						name: 'actionClass',
						type: 'options',
						options: [
							{ name: 'Export', value: 'EXPORT' },
							{ name: 'External Side Effect', value: 'EXTERNAL_SIDE_EFFECT' },
							{ name: 'Read', value: 'READ' },
							{ name: 'Write', value: 'WRITE' },
						],
						default: 'WRITE',
					},
					{
						displayName: 'Agent ID',
						name: 'agentId',
						type: 'string',
						default: '',
						description: 'UUID of the registered agent',
					},
					{
						displayName: 'Data Class',
						name: 'dataClass',
						type: 'string',
						default: '',
						placeholder: 'CONFIDENTIAL',
					},
					{
						displayName: 'Irreversible',
						name: 'irreversible',
						type: 'boolean',
						default: false,
					},
					{
						displayName: 'Require Registered Agent',
						name: 'requireRegisteredAgent',
						type: 'boolean',
						default: false,
						description:
							'Whether to deny unless Agent ID is an active agent of this workspace',
					},
					{
						displayName: 'Session Risk',
						name: 'sessionRisk',
						type: 'options',
						options: [
							{ name: 'Low', value: 'LOW' },
							{ name: 'Medium', value: 'MEDIUM' },
							{ name: 'High', value: 'HIGH' },
						],
						default: 'LOW',
					},
				],
			},
			{
				displayName: 'Approval Fields',
				name: 'approvalFields',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				displayOptions: { show: { operation: ['requestApproval'] } },
				options: [
					{
						displayName: 'Correlation ID',
						name: 'correlationId',
						type: 'string',
						default: '',
					},
					{
						displayName: 'Irreversible',
						name: 'irreversible',
						type: 'boolean',
						default: false,
					},
					{
						displayName: 'Reason Code',
						name: 'reasonCode',
						type: 'string',
						default: '',
						placeholder: 'HIGH_STAKES_WRITE',
					},
					{
						displayName: 'Session ID',
						name: 'sessionId',
						type: 'string',
						default: '',
					},
					{
						displayName: 'Work Item ID',
						name: 'workItemId',
						type: 'string',
						default: '',
						description:
							'UUID binding the approval to one unit of work. Empty: derived from the arguments hash, the same way the KYA SDK does.',
					},
				],
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Max Attempts',
						name: 'maxAttempts',
						type: 'number',
						typeOptions: { minValue: 1, maxValue: 6 },
						default: 4,
						description:
							'Attempts on HTTP 429 (and 5xx for Evaluate and Get Approval) before the node fails',
					},
					{
						displayName: 'Max Wait Seconds',
						name: 'maxWaitSeconds',
						type: 'number',
						typeOptions: { minValue: 1, maxValue: 120 },
						default: 30,
						description:
							'Longest single wait between attempts. A Retry-After above this fails at once.',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const out: INodeExecutionData[] = [];
		const creds = await this.getCredentials('shieldKyaApi');
		const apiKey = String(creds.apiKey ?? '');
		const origin = planeOrigin(creds.plane, creds.loopbackPort);
		if (!origin) {
			throw new NodeOperationError(this.getNode(), 'Unknown control plane in the Shield KYA credential');
		}

		for (let i = 0; i < items.length; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;
				const options = this.getNodeParameter('options', i, {}) as IDataObject;
				const maxAttempts = Number(options.maxAttempts ?? 4);
				const maxDelayMs = Number(options.maxWaitSeconds ?? 30) * 1000;

				const call = async (
					method: IHttpRequestMethods,
					path: string,
					body: IDataObject | undefined,
					retryServerErrors: boolean,
					query?: Record<string, string | number | undefined>,
				): Promise<unknown> => {
					const url = apiUrl(origin, path, query);
					if (!url) {
						throw new NodeOperationError(this.getNode(), 'Refusing to build a Shield KYA URL outside the API path', { itemIndex: i });
					}
					const outcome = await sendWithRetry(
						async () =>
							(await this.helpers.httpRequestWithAuthentication.call(this, 'shieldKyaApi', {
								method,
								url,
								// Never follow redirects: the API key header must not reach another origin.
								disableFollowRedirect: true,
								body,
								json: true,
								timeout: 30_000,
								returnFullResponse: true,
								ignoreHttpStatusErrors: true,
							})) as HttpResult,
						{ maxAttempts, maxDelayMs, retryServerErrors, sleep },
					);
					if (!outcome.ok) {
						const status = outcome.response.statusCode;
						const message = redact(describeFailure(status, outcome.reason, outcome.response.body), [apiKey]);
						throw new NodeApiError(this.getNode(), { message, httpCode: String(status) } as JsonObject, {
							message,
							httpCode: String(status),
							itemIndex: i,
						});
					}
					return outcome.response.body;
				};
				const callObject = async (
					method: IHttpRequestMethods,
					path: string,
					body: IDataObject | undefined,
					retryServerErrors: boolean,
				): Promise<IDataObject> => {
					const result = await call(method, path, body, retryServerErrors);
					if (result === null || typeof result !== 'object' || Array.isArray(result)) {
						throw new NodeOperationError(this.getNode(), 'Shield KYA returned a response that is not a JSON object', { itemIndex: i });
					}
					return result as IDataObject;
				};

				let json: IDataObject;
				if (operation === 'evaluate') {
					const fields = this.getNodeParameter('additionalFields', i, {}) as IDataObject;
					const argsHash = computeArgsHash(parseArgs(this, this.getNodeParameter('toolArguments', i, '{}'), i));
					const body: IDataObject = {
						toolId: requireText(this, this.getNodeParameter('toolId', i), 'Tool ID', i),
						host: this.getNodeParameter('host', i),
						argsHash,
						product: 'n8n',
					};
					for (const key of ['actionClass', 'dataClass', 'sessionRisk'] as const) {
						if (fields[key]) body[key] = fields[key];
					}
					if (fields.agentId) body.agentId = requireUuid(this, fields.agentId, 'Agent ID', i);
					if (fields.irreversible) body.irreversible = true;
					if (fields.requireRegisteredAgent) body.requireRegisteredAgent = true;
					json = await callObject('POST', '/api/v1/kya/policy/evaluate', body, true);
					// Fail closed: no verdict means no verdict, never a default.
					if (!['ALLOW', 'DENY', 'REQUIRE_APPROVE'].includes(String(json.verdict))) {
						throw new NodeOperationError(this.getNode(), 'Shield KYA response has no valid verdict', { itemIndex: i });
					}
					json.argsHash = json.argsHash ?? argsHash;
				} else if (operation === 'requestApproval') {
					const fields = this.getNodeParameter('approvalFields', i, {}) as IDataObject;
					const argsHash = computeArgsHash(parseArgs(this, this.getNodeParameter('toolArguments', i, '{}'), i));
					const body: IDataObject = {
						agentId: requireUuid(this, this.getNodeParameter('agentId', i), 'Agent ID', i),
						disputeId: fields.workItemId
							? requireUuid(this, fields.workItemId, 'Work Item ID', i)
							: factoryWorkItemId(argsHash),
						toolId: requireText(this, this.getNodeParameter('toolId', i), 'Tool ID', i),
						argsHash,
						host: this.getNodeParameter('host', i),
					};
					for (const key of ['sessionId', 'correlationId', 'reasonCode'] as const) {
						if (fields[key]) body[key] = fields[key];
					}
					if (fields.irreversible) body.irreversible = true;
					// Creating an approval is not idempotent: retry only 429 (rejected before it ran).
					json = await callObject('POST', '/api/v1/kya/approvals', body, false);
					json.argsHash = argsHash;
				} else if (operation === 'getApproval') {
					const id = requireUuid(this, this.getNodeParameter('approvalId', i), 'Approval ID', i);
					json = await callObject('GET', `/api/v1/kya/approvals/${id}`, undefined, true);
				} else if (operation === 'listEvents') {
					const types = (this.getNodeParameter('eventTypes', i, []) as string[]).filter((t) => EVENT_TYPES.has(t));
					const after = String(this.getNodeParameter('afterEventId', i, '') ?? '').trim();
					if (after && !EVENT_ID_RE.test(after)) {
						throw new NodeOperationError(this.getNode(), 'After Event ID must look like evt_kya_...', { itemIndex: i });
					}
					const limit = Number(this.getNodeParameter('limit', i, 50));
					// Page back with `before` while a page is full, so a burst of more than one page of
					// new events between two polls leaves no gap. MAX_PAGES bounds one execution.
					const events: IDataObject[] = [];
					let before: string | undefined;
					for (let page = 0; page < MAX_PAGES; page++) {
						const result = await call('GET', '/api/v1/kya/events', undefined, true, {
							types: types.join(',') || undefined,
							after: after || undefined,
							before,
							limit,
						});
						if (!Array.isArray(result)) {
							throw new NodeOperationError(this.getNode(), 'Shield KYA returned a response that is not a JSON array', { itemIndex: i });
						}
						const valid = result.filter((e) => e && typeof e === 'object' && !Array.isArray(e)) as IDataObject[];
						events.push(...valid);
						const oldest = valid.length ? String(valid[valid.length - 1].id ?? '') : '';
						// Only page on when after is set: without it, the newest page is the whole answer.
						if (!after || result.length < limit || !EVENT_ID_RE.test(oldest)) break;
						before = oldest;
					}
					// One item per event, newest first. Each is the same envelope the webhook sends.
					for (const event of events) {
						out.push({ json: event, pairedItem: { item: i } });
					}
					continue;
				} else {
					throw new NodeOperationError(this.getNode(), `Unknown operation ${operation}`, { itemIndex: i });
				}
				out.push({ json, pairedItem: { item: i } });
			} catch (error) {
				if (this.continueOnFail()) {
					// No verdict field on purpose: an IF on verdict == ALLOW must never pass on an error.
					out.push({ json: { error: (error as Error).message, failedClosed: true }, pairedItem: { item: i } });
					continue;
				}
				throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
			}
		}
		return [out];
	}
}

function parseArgs(ctx: IExecuteFunctions, raw: unknown, itemIndex: number): unknown {
	if (typeof raw !== 'string') return raw ?? {};
	if (raw.trim() === '') return {};
	try {
		return JSON.parse(raw);
	} catch {
		// Fixed message: V8's parse error quotes the input, which may be a secret argument value.
		throw new NodeOperationError(ctx.getNode(), 'Tool Arguments must be valid JSON', { itemIndex });
	}
}

function requireText(ctx: IExecuteFunctions, value: unknown, label: string, itemIndex: number): string {
	const s = String(value ?? '').trim();
	if (!s) throw new NodeOperationError(ctx.getNode(), `${label} is required`, { itemIndex });
	return s;
}

function requireUuid(ctx: IExecuteFunctions, value: unknown, label: string, itemIndex: number): string {
	const s = String(value ?? '').trim();
	if (!UUID_RE.test(s)) throw new NodeOperationError(ctx.getNode(), `${label} must be a UUID`, { itemIndex });
	return s;
}

function describeFailure(status: number, reason: string, body: unknown): string {
	const serverMessage =
		body && typeof body === 'object' && 'error' in body
			? String(((body as { error?: { message?: unknown } }).error ?? {}).message ?? '')
			: '';
	const suffix = serverMessage ? `: ${serverMessage.slice(0, 200)}` : '';
	if (status === 401) return `Shield KYA rejected the API key (401). Check the credential${suffix}`;
	if (status === 403) return `The API key lacks the scope for this operation (403)${suffix}`;
	if (status === 429) return `Shield KYA rate limit (${reason}). Nothing was evaluated; treat as not allowed${suffix}`;
	if (status >= 500) return `Shield KYA server error (${reason}). Nothing was evaluated; treat as not allowed${suffix}`;
	return `Shield KYA request failed (${reason})${suffix}`;
}
