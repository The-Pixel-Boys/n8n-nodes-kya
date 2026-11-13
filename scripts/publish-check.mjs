// Gate of .github/workflows/npm-publish.yml: decides if the tag may publish.
//   node scripts/publish-check.mjs <tag>
// Exit 1 (refuse): tag is not vX.Y.Z, package name or repository is not the expected one, or the
// package.json version differs from the tag. Exit 0 otherwise and print `publish=true` (the
// registry has no such version) or `publish=false` (already on npm: skip, the run still passes).
// With GITHUB_OUTPUT set, the same line is appended there. Env NPM_REGISTRY (default
// https://registry.npmjs.org) is for tests. Run from the package root.
import { readFileSync, appendFileSync } from 'node:fs';

const NAME = '@shield-agent/n8n-nodes-kya';
const REPO = 'github.com/The-Pixel-Boys/n8n-nodes-kya';
const fail = (m) => {
	console.error(`publish-check: ${m}`);
	process.exit(1);
};

const tag = process.argv[2] ?? '';
const m = /^v(\d+\.\d+\.\d+)$/.exec(tag);
if (!m) fail(`tag '${tag}' is not vX.Y.Z (prereleases are not published by this workflow)`);
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
if (pkg.name !== NAME) fail(`package name is '${pkg.name}', expected ${NAME}`);
if (!String(pkg.repository?.url ?? '').includes(`${REPO}.git`)) {
	fail(`repository.url '${pkg.repository?.url}' does not name ${REPO}: npm provenance would not match`);
}
if (pkg.version !== m[1]) fail(`package.json version is ${pkg.version}, tag is ${tag}: refusing to publish`);

const registry = (process.env.NPM_REGISTRY ?? 'https://registry.npmjs.org').replace(/\/$/, '');
const res = await fetch(`${registry}/${NAME.replace('/', '%2f')}/${pkg.version}`, { redirect: 'error' }).catch((e) => fail(`cannot read the registry: ${e.cause ?? e.message}`));
if (res.status !== 200 && res.status !== 404) fail(`registry answered HTTP ${res.status}`);
const line = `publish=${res.status === 404}`;
console.log(res.status === 404 ? `${NAME}@${pkg.version} is not on npm: publish` : `${NAME}@${pkg.version} is already on npm: skip (pass)`);
console.log(line);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${line}\n`);
