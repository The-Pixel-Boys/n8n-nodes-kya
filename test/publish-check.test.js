'use strict';
// The publish gate of .github/workflows/npm-publish.yml (scripts/publish-check.mjs): a local fake
// registry stands in for npmjs.org. Denied paths: tag differs from package.json, wrong tag form,
// wrong name, wrong repository, registry error or down.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const root = path.join(__dirname, '..');
const script = path.join(root, 'scripts', 'publish-check.mjs');
const real = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const NAME_PATH = '/@shield-agent%2fn8n-nodes-kya/';

function registry(status) {
	const seen = [];
	const server = http.createServer((req, res) => {
		seen.push(req.url);
		res.writeHead(status).end('{}');
	});
	return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, url: `http://127.0.0.1:${server.address().port}` })));
}

async function run(tag, pkg, status) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'publish-check-'));
	try {
		fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
		const out = path.join(dir, 'gh-output');
		const env = { ...process.env, GITHUB_OUTPUT: out };
		let reg;
		if (status === 'down') env.NPM_REGISTRY = 'http://127.0.0.1:9';
		else {
			reg = await registry(status);
			env.NPM_REGISTRY = reg.url;
		}
		// Async spawn: the fake registry lives in this process and must keep answering.
		const r = await new Promise((resolve) => {
			const p = spawn(process.execPath, [script, tag], { cwd: dir, env });
			let stdout = '';
			let stderr = '';
			p.stdout.on('data', (d) => (stdout += d));
			p.stderr.on('data', (d) => (stderr += d));
			p.on('close', (status) => resolve({ status, stdout, stderr }));
		});
		reg?.server.close();
		return { ...r, seen: reg?.seen ?? [], output: fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '' };
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

const good = { ...real, version: '1.2.3' };

test('registry has no such version: publish=true, looks up exactly that version', async () => {
	const r = await run('v1.2.3', good, 404);
	assert.equal(r.status, 0, r.stderr);
	assert.equal(r.output, 'publish=true\n');
	assert.deepEqual(r.seen, [`${NAME_PATH}1.2.3`]);
});

test('version already on npm: skip and pass (publish=false)', async () => {
	const r = await run('v1.2.3', good, 200);
	assert.equal(r.status, 0, r.stderr);
	assert.equal(r.output, 'publish=false\n');
	assert.match(r.stdout, /already on npm: skip/);
});

test('the real package.json passes for its own version tag', async () => {
	const r = await run(`v${real.version}`, real, 404);
	assert.equal(r.status, 0, r.stderr);
});

test('denied: tag version differs from package.json', async () => {
	for (const tag of ['v1.2.4', 'v1.2.2', 'v2.2.3']) {
		const r = await run(tag, good, 404);
		assert.equal(r.status, 1, tag);
		assert.match(r.stderr, /package\.json version is 1\.2\.3, tag is /);
		assert.equal(r.output, '', 'no publish=true line');
		assert.deepEqual(r.seen, [], 'the registry is not even asked');
	}
});

test('denied: tag is not vX.Y.Z', async () => {
	for (const tag of ['1.2.3', 'v1.2', 'v1.2.3-rc.1', 'v1.2.3;id', 'refs/tags/v1.2.3', '']) {
		const r = await run(tag, good, 404);
		assert.equal(r.status, 1, `'${tag}'`);
		assert.match(r.stderr, /is not vX\.Y\.Z/);
	}
});

test('denied: wrong package name or repository', async () => {
	let r = await run('v1.2.3', { ...good, name: '@shield-agent/other' }, 404);
	assert.equal(r.status, 1);
	assert.match(r.stderr, /package name is '@shield-agent\/other'/);
	r = await run('v1.2.3', { ...good, repository: { type: 'git', url: 'https://github.com/The-Pixel-Boys/n8n-nodes-shield-kya.git' } }, 404);
	assert.equal(r.status, 1);
	assert.match(r.stderr, /provenance would not match/);
	r = await run('v1.2.3', { ...good, repository: undefined }, 404);
	assert.equal(r.status, 1);
});

test('denied: registry error or registry down never means publish', async () => {
	let r = await run('v1.2.3', good, 500);
	assert.equal(r.status, 1);
	assert.match(r.stderr, /HTTP 500/);
	assert.equal(r.output, '');
	r = await run('v1.2.3', good, 'down');
	assert.equal(r.status, 1);
	assert.match(r.stderr, /cannot read the registry/);
	r = await run('v1.2.3', good, 302);
	assert.equal(r.status, 1, 'a redirect is an error');
});
