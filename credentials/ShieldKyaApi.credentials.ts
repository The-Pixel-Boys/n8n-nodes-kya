import type {
	IAuthenticateGeneric,
	Icon,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class ShieldKyaApi implements ICredentialType {
	name = 'shieldKyaApi';

	displayName = 'Shield KYA API';

	icon: Icon = { light: 'file:../nodes/ShieldKya/shieldKya.svg', dark: 'file:../nodes/ShieldKya/shieldKya.svg' };

	documentationUrl = 'https://shield-agent.com/docs';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			required: true,
			default: '',
			description:
				'Workspace API key minted in the hosted Shield KYA console. Scopes: kya.evaluate for Evaluate, kya.write for Request Approval and the trigger, kya.read for Get Approval and the credential test.',
		},
		{
			displayName: 'Control Plane',
			name: 'plane',
			type: 'options',
			options: [
				{ name: 'Shield KYA Cloud (https://shield-agent.com)', value: 'cloud' },
				{ name: 'Local Test Only (http://127.0.0.1)', value: 'loopbackTest' },
			],
			default: 'cloud',
			description:
				'The API key is only ever sent to https://shield-agent.com. Local Test Only sends it over plain http to this machine (127.0.0.1) and exists for automated tests against a local mock; never use it with a real key.',
		},
		{
			displayName: 'Local Test Port',
			name: 'loopbackPort',
			type: 'number',
			typeOptions: { minValue: 1, maxValue: 65535 },
			default: 18787,
			displayOptions: { show: { plane: ['loopbackTest'] } },
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				'X-API-Key': '={{$credentials.apiKey}}',
			},
		},
	};

	// Mirrors planeOrigin() in nodes/ShieldKya/kya.ts: only the fixed cloud origin or 127.0.0.1:<number>.
	test: ICredentialTestRequest = {
		request: {
			baseURL:
				'={{$credentials.plane === "loopbackTest" ? "http://127.0.0.1:" + Math.trunc(Number($credentials.loopbackPort)) : "https://shield-agent.com"}}',
			url: '/api/v1/kya/entitlement',
			disableFollowRedirect: true,
		},
	};
}
