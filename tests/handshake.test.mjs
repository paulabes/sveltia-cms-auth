// Handshake test: drives /auth and /callback, then runs the callback page's
// inline script against a fake opener from different origins, to prove the
// token only ever reaches the site that started the sign-in.
// Run with: node tests/handshake.test.mjs (no dependencies, Node 20+).
import assert from 'node:assert/strict';
import vm from 'node:vm';
import worker from '../src/index.js';
const env = {
  ALLOWED_DOMAINS: 'foard.co.uk,www.foard.co.uk,*.example.org',
  GITHUB_CLIENT_ID: 'id',
  GITHUB_CLIENT_SECRET: 'secret',
};
const BASE = 'https://auth.example.workers.dev';

const cookiesOf = (res) =>
  res.headers
    .getSetCookie()
    .map((c) => c.split(';')[0])
    .join('; ');

async function signIn(siteId, { tamperSite } = {}) {
  const auth = await worker.fetch(new Request(`${BASE}/auth?provider=github&site_id=${siteId}`), env);
  if (auth.status !== 302) return { auth };
  const state = new URL(auth.headers.get('Location')).searchParams.get('state');
  let cookie = cookiesOf(auth);
  if (tamperSite) cookie = cookie.replace(/auth-site=[^;]+/, `auth-site=${tamperSite}`);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ access_token: 'gho_TESTTOKEN</script>"x' });
  const cb = await worker.fetch(
    new Request(`${BASE}/callback?code=abc&state=${state}`, { headers: { Cookie: cookie } }),
    env,
  );
  globalThis.fetch = realFetch;
  return { auth, cb, html: await cb.text() };
}

// Run the page script; the "opener" answers the hello from `openerOrigin`.
function runPage(html, openerOrigin) {
  const script = html.match(/<script>([\s\S]*)<\/script><\/body>/)[1];
  const received = [];
  let listener;
  const window = {
    addEventListener: (_t, fn) => (listener = fn),
    opener: { postMessage: (msg, target) => received.push({ msg, target }) },
  };
  vm.runInNewContext(script, { window, URL });
  const hello = received.shift();
  listener({ data: hello.msg, origin: openerOrigin });
  return { hello, received };
}

// 1. /auth sets both cookies and redirects to GitHub
{
  const { auth } = await signIn('foard.co.uk');
  assert.equal(auth.status, 302);
  assert.match(auth.headers.get('Location'), /^https:\/\/github\.com\/login\/oauth\/authorize/);
  assert.match(cookiesOf(auth), /csrf-token=github_[0-9a-f]{32}; auth-site=foard\.co\.uk/);
}

// 2. The genuine site gets the token, intact, and only at its own origin
{
  const { html } = await signIn('foard.co.uk');
  const { hello, received } = runPage(html, 'https://foard.co.uk');
  assert.deepEqual(hello, { msg: 'authorizing:github', target: '*' });
  assert.equal(received.length, 1);
  assert.equal(received[0].target, 'https://foard.co.uk');
  const [, json] = received[0].msg.match(/^authorization:github:success:(.*)$/s);
  assert.deepEqual(JSON.parse(json), { provider: 'github', token: 'gho_TESTTOKEN</script>"x' });
  assert.ok(!html.includes('</script>"x'), 'token must not be able to close the script tag');
}

// 3. Any other opener gets nothing: hostile site, http, another allowed site, lookalikes
for (const origin of [
  'https://evil.example',
  'http://foard.co.uk',
  'https://www.foard.co.uk',
  'https://foard.co.uk.evil.example',
  'https://evilfoard.co.uk',
  'null',
  '',
]) {
  const { html } = await signIn('foard.co.uk');
  assert.equal(runPage(html, origin).received.length, 0, `leaked to ${origin}`);
}

// 4. Wildcard entries still work, bound to the exact host that asked
{
  const { html } = await signIn('cms.example.org');
  assert.equal(runPage(html, 'https://cms.example.org').received.length, 1);
  assert.equal(runPage(html, 'https://other.example.org').received.length, 0);
}

// 5. Not on the list, missing, or not a hostname: refused at /auth, no redirect
for (const id of ['evil.example', '', 'foard.co.uk%3Bx%3D1', 'foard.co.uk/x']) {
  const { auth } = await signIn(id);
  assert.equal(auth.status, 200, `site_id "${id}" should not redirect`);
  assert.match(await auth.text(), /UNSUPPORTED_DOMAIN/);
}

// 6. A hand-edited site cookie naming an unlisted host gets an error, never a token
{
  const { html } = await signIn('foard.co.uk', { tamperSite: 'evil.example' });
  assert.match(html, /UNSUPPORTED_DOMAIN/);
  assert.ok(!html.includes('gho_TESTTOKEN'));
}

// 7. Errors (no secret in them) still reach the opener so the CMS can show them
{
  const { auth } = await signIn('evil.example');
  const res = await worker.fetch(new Request(`${BASE}/auth?provider=github&site_id=evil.example`), env);
  const { received } = runPage(await res.text(), 'https://anything.example');
  assert.equal(received.length, 1);
  assert.match(received[0].msg, /^authorization:github:error:/);
  void auth;
}

console.log('all auth worker checks passed');
