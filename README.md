# @shield-agent/n8n-nodes-kya

n8n community nodes for the hosted [Shield KYA](https://shield-agent.com) plane (Know Your Agent):

- **Shield KYA** (action): **Evaluate** a tool call (ALLOW, DENY or REQUIRE_APPROVE), **Request Approval** (open a pending human approval), **Get Approval** (read its status), **List Events** (recent signed events, for polling without a public URL).
- **Shield KYA Trigger**: start a workflow on signed KYA events: `kya.approval.pending`, `kya.approval.approved`, `kya.approval.rejected`, `kya.approval.expired`, `kya.policy.evaluated` (DENY and REQUIRE_APPROVE only) and `kya.incident.opened`.

These nodes talk to the **hosted** plane, which enforces policy and fails closed: an approval is decided by a human in Shield KYA, and a missing APPROVED blocks the side effect. The free OSS `kya` CLI is a different product surface: it runs locally, is advisory and fails open. Nothing in this package makes the OSS CLI enforce anything.

The hosted console is live and open for sign-up at [shield-agent.com](https://shield-agent.com).

## Install

In n8n: **Settings > Community Nodes > Install**, package name `@shield-agent/n8n-nodes-kya`. Self-hosted only until the package is verified by n8n. The source is public at [The-Pixel-Boys/n8n-nodes-kya](https://github.com/The-Pixel-Boys/n8n-nodes-kya).

## Credentials

Create a **Shield KYA API** credential:

| Field | Value |
|---|---|
| API Key | A workspace API key minted in the hosted console. Scopes: `kya.evaluate` (Evaluate), `kya.write` (Request Approval, Trigger), `kya.read` (Get Approval, List Events and the credential test). |
| Control Plane | **Shield KYA Cloud** (default): the key is only ever sent to `https://shield-agent.com`. **Local Test Only** sends it over plain http to `127.0.0.1:<port>` and exists for automated tests against a local mock; never use it with a real key. There is no free-form URL field. |

The key is sent as the `X-API-Key` header and is never written to node output or error messages. Every request URL is built once with WHATWG `URL` from the fixed origin and a constant API path and must keep exactly that origin and path; ids from input or from the server must be UUIDs; redirects are never followed (a 3xx is an error), so the key cannot be forwarded to another origin.

## Evaluate

Inputs: Tool ID, Tool Arguments (JSON), Host (`runtime` or `ide`), plus optional action class, agent id, irreversible, session risk, data class.

- **Tool arguments never leave n8n.** The node computes `argsHash = sha256(canonical JSON)` (same as the KYA SDK) and sends only the hash.
- The node does not block anything by itself. **Gate positively:** an IF node `verdict` equals `ALLOW` in front of the action, everything else to the stop branch. Never gate on `verdict` not equal to `DENY`: a failed call has no `verdict` at all and would pass. Send REQUIRE_APPROVE to Request Approval.
- With **Use as Tool** (`usableAsTool`), an AI agent decides itself whether to call Evaluate. The gate must then be an IF in the workflow around the action, not the agent's own choice. Agents can open approvals but never approve them.
- **Errors never produce a verdict.** A 401, 403, exhausted 429 or 5xx stops the workflow. With "Continue On Fail" the error item carries `failedClosed: true` and no `verdict` field, so an IF on `verdict == ALLOW` cannot pass on an error.
- **Rate limits:** on 429 the node waits for `Retry-After` (seconds or HTTP date) plus jitter and retries, up to **Max Attempts** (default 4). A `Retry-After` longer than **Max Wait Seconds** (default 30) fails at once. Evaluate and Get Approval also retry 5xx; Request Approval retries only 429, because creating an approval is not idempotent.

## Request Approval / Get Approval

Request Approval opens a PENDING approval bound to the agent, tool id and arguments hash. **Work Item ID** defaults to the same UUID the KYA SDK derives from the arguments hash, so an SDK-wrapped tool and this workflow agree on the intent. Get Approval returns `status` (`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`).

## List Events

`GET /api/v1/kya/events`: the workspace's events of the last 30 days, newest first, one output item per event. Each item is the exact envelope a webhook delivery carries. Inputs: Event Types (empty = all), After Event ID (only newer events; must look like `evt_kya_<type>_<32 hex>`, else the node fails before any request), Limit (1..100, the page size). With After Event ID, the node reads more pages with `before` while a page is full (up to 20 pages), so a burst between two polls leaves no gap. The query is built only in code with `URLSearchParams`; origin and path stay exact. Use it with a Schedule Trigger when n8n has no public HTTPS URL, keep the newest processed id, and dedupe on `id`.

This package has no Approve or Reject operation on purpose: a workflow must not approve its own request.

## Trigger

On activation the trigger registers its webhook URL with Shield KYA (`POST /api/v1/kya/webhooks`). On deactivation it deletes the registration and wipes what it stored. The signing secret is derived from the API key and the webhook URL, so it is never stored in workflow static data. The stored subscription (id, workspace id from the authenticated registration response, and a binding hash over the credential id, workspace, key-derived secret and URL) is never reused for another credential, key, workspace or URL: activation deletes and re-registers a stale one, and deliveries are refused (`subscription_not_bound`) until it is re-registered. Each delivery is checked before anything runs:

- `X-Shield-Agent-Signature: t=<unix>,v1=<hmac>` is verified over the raw body with a constant-time compare.
- Timestamps outside the replay window (default 300 s) are rejected.
- The event's `tenantId` must equal the workspace stored at registration; the workspace is never taken from the payload.
- Missing, tampered or stale signatures, a delivery signed for another subscription, a swapped or rotated credential, or another workspace get HTTP 401 and the workflow does not run.
- Redelivered event ids are acknowledged and not run twice. This works within one n8n process: a restart or a multi-process queue-mode setup can run a redelivered event again, so make side effects idempotent on the event `id`. Static data is per workflow: several n8n instances each register their own subscription, and queue-mode workers share the same workflow static data. If you rotate the API key or swap the credential while the workflow is active, deactivate and activate it again to re-register; until then deliveries are refused, never accepted with the old secret.

Shield KYA delivers only to public **HTTPS** URLs. A local, private-network or http-only n8n cannot receive events: poll with List Events instead. Receiving an event never approves anything.

## Example workflow

[`examples/pending-approval-evaluate.json`](examples/pending-approval-evaluate.json): trigger on `kya.approval.pending`, evaluate the tool, then an IF node `verdict` equals `ALLOW` in front of the action; DENY, REQUIRE_APPROVE and failed calls all take the stop branch. Import it via **Workflows > Import from File**, then pick your credential.

## Development

```bash
npm ci --ignore-scripts
npm run build && npm run lint && npm test
```

The real-n8n end-to-end tests live in the Shield Agent monorepo (`integrations/e2e`). Use Node 24: n8n 2.43.4 does not install on Node 26 (native Kafka module build).

## Release

This folder is mirrored to the public repo `The-Pixel-Boys/n8n-nodes-kya` by the Shield Agent release pipeline. Do not edit that repo by hand: the next mirror run overwrites it.

- The package has its own version line (starts at 0.1.0). Change `version` in `package.json` and merge to `main`. The mirror pipeline then tags `vX.Y.Z` in the public repo. Only stable `X.Y.Z` versions are tagged. An existing tag is never moved.
- `.github/workflows/npm-publish.yml` (mirrored with the source) runs on that tag. Job `build` has no id-token: it runs `scripts/publish-check.mjs` (the tag must equal the `package.json` version, and npm must not serve the version yet), then install, build, lint, test and pack. Job `publish` has the id-token and runs `npm publish --provenance --access public` with npm trusted publishing (OIDC, no token). A version that npm already serves is skipped and the run passes.
- Package e2e (needs podman): `node integrations/e2e/n8n-package-e2e.mjs <out-dir>` in the monorepo. It packs the node, runs the publish gate against the tarball (a wrong tag must fail), and loads the tarball into a real n8n container as a community node.

### Owner one-time steps

1. Publish a placeholder 0.0.1 once (`npm publish --access public --tag bootstrap` from an empty package). npm can set a trusted publisher only for a package that exists. Do not publish 0.1.0 by hand: it would have no provenance and n8n could not verify it.
2. On npmjs.com, set the trusted publisher of `@shield-agent/n8n-nodes-kya`: GitHub Actions, organization `The-Pixel-Boys`, repository `n8n-nodes-kya`, workflow `npm-publish.yml`, environment empty, direct publish allowed. Do step 3 within 2 days.
3. Run the `kya-n8n-mirror` Woodpecker pipeline by hand on `main`. It mirrors the source and tags `v0.1.0`. The public workflow publishes 0.1.0 with provenance. Check: `npm view @shield-agent/n8n-nodes-kya dist.attestations --json`.
4. Deprecate the placeholder: `npm deprecate @shield-agent/n8n-nodes-kya@0.0.1 "Placeholder. Use 0.1.0 or later."`.
5. Submit the package in the n8n Creator Portal after the first provenance publish.

## License

MIT
