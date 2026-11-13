import test from 'node:test';
import assert from 'node:assert/strict';
import { validateSession, guardedFetch } from '../runbox/resources/node-session.mjs';

const proxy = 'http://synthetic:session@127.0.0.1:8283';
const env = {
  NODE_ENV: 'development', NODE_USE_ENV_PROXY: '1',
  AGENTBRIDGE_BASE_URL: 'http://127.0.0.1:8082/api/v1',
  AGENTBRIDGE_API_KEY: 'agentbridge_public_placeholder',
  HTTP_PROXY: proxy, HTTPS_PROXY: proxy, NO_PROXY: '', no_proxy: '',
};
const value = {
  root: '/synthetic/repo', runtime: {},
  profile: {
    environment: { NODE_ENV: env.NODE_ENV, NODE_USE_ENV_PROXY: '1',
      AGENTBRIDGE_BASE_URL: env.AGENTBRIDGE_BASE_URL, AGENTBRIDGE_API_KEY: env.AGENTBRIDGE_API_KEY },
    session: { proxy: '127.0.0.1:8283' },
    http: { 'base-url': env.AGENTBRIDGE_BASE_URL, 'credential-variable': 'AGENTBRIDGE_API_KEY',
      placeholder: env.AGENTBRIDGE_API_KEY, routes: [
        { method: 'GET', path: '/api/v1/models' },
        { method: 'POST', path: '/api/v1/chat/completions' },
        { method: 'GET', path: '/api/v1/openrouter/key', 'forward-host': 'localhost:8082' },
      ] },
  },
};
for (const name of ['OPENROUTER_API_KEY','SENTRY_AUTH_TOKEN','VERCEL_ENV','http_proxy','https_proxy']) delete process.env[name];
Object.assign(process.env, env);

test('requires the reviewed placeholder and scoped authenticated proxy', () => {
  validateSession(value, env);
  for (const change of [
    { AGENTBRIDGE_API_KEY: '' }, { AGENTBRIDGE_API_KEY: 'synthetic-unreviewed-key' },
    { OPENROUTER_API_KEY: 'synthetic-provider-key' }, { SENTRY_AUTH_TOKEN: 'synthetic-provider-key' },
    { NODE_ENV: 'production' }, { VERCEL_ENV: 'preview' }, { NODE_USE_ENV_PROXY: '0' },
    { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { NO_PROXY: '*' },
    { HTTP_PROXY: 'http://127.0.0.1:8283' }, { HTTPS_PROXY: 'http://other:other@127.0.0.1:8283' },
    { http_proxy: 'http://other:other@127.0.0.1:8283' },
    { AGENTBRIDGE_BASE_URL: 'https://unreviewed.invalid/api/v1' },
  ]) assert.throws(() => validateSession(value, { ...env, ...change }));
});

test('preserves JSON requests and streaming response bodies', async () => {
  let calls = 0;
  const fetch = guardedFetch(async (url, init) => {
    calls++;
    assert.equal(String(url), `${env.AGENTBRIDGE_BASE_URL}/chat/completions`);
    assert.equal(init.redirect, 'error');
    assert.equal(init.body, '{"stream":true}');
    return new Response('data: synthetic\n\n', { headers: { 'Content-Type': 'text/event-stream' } });
  }, value);
  const response = await fetch(`${env.AGENTBRIDGE_BASE_URL}/chat/completions`, {
    method: 'POST', headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` }, body: '{"stream":true}',
  });
  assert.equal(await response.text(), 'data: synthetic\n\n');
  assert.equal(calls, 1);
});

test('preserves Request objects and their payloads', async () => {
  const fetch = guardedFetch(async request => {
    assert.equal(request.method, 'POST');
    assert.equal(await request.text(), 'synthetic body');
    return new Response('synthetic response');
  }, value);
  const request = new Request(`${env.AGENTBRIDGE_BASE_URL}/chat/completions`, {
    method: 'POST', headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` }, body: 'synthetic body',
  });
  assert.equal(await (await fetch(request)).text(), 'synthetic response');
});

test('sanitizes service failures without an automatic retry', async () => {
  let calls = 0;
  const fetch = guardedFetch(async () => { calls++; return new Response('synthetic-private-provider-key', { status: 401 }); }, value);
  const response = await fetch(`${env.AGENTBRIDGE_BASE_URL}/models`, { headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` } });
  assert.equal(response.status, 401);
  assert.doesNotMatch(await response.text(), /synthetic-private/);
  await assert.rejects(fetch(`${env.AGENTBRIDGE_BASE_URL}/models`, { headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` } }));
  assert.equal(calls, 1);
});

test('a failed network request blocks every later dispatch in that session', async () => {
  let calls = 0;
  const fetch = guardedFetch(async () => { calls++; throw new Error('synthetic-private-network-detail'); }, value);
  const invoke = () => fetch(`${env.AGENTBRIDGE_BASE_URL}/models`, { headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` } });
  await assert.rejects(invoke(), error => !error.message.includes('synthetic-private'));
  await assert.rejects(invoke());
  assert.equal(calls, 1);
});

test('rejects unreviewed destinations, methods, queries and extra authentication before transport', async () => {
  let calls = 0;
  const fetch = guardedFetch(async () => { calls++; return new Response('unexpected'); }, value);
  for (const [url, method, headers] of [
    ['https://unreviewed.invalid/api/v1/chat/completions', 'POST', {}],
    [`${env.AGENTBRIDGE_BASE_URL}/keys`, 'POST', {}],
    [`${env.AGENTBRIDGE_BASE_URL}/models?token=synthetic`, 'GET', {}],
    [`${env.AGENTBRIDGE_BASE_URL}/models`, 'DELETE', {}],
    [`${env.AGENTBRIDGE_BASE_URL}/models`, 'GET', { Authorization: 'Bearer synthetic-unreviewed-key' }],
    [`${env.AGENTBRIDGE_BASE_URL}/models`, 'GET', { Cookie: 'synthetic' }],
  ]) await assert.rejects(fetch(url, { method, headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}`, ...headers } }));
  assert.equal(calls, 0);
});

test('keeps the reviewed metadata alias GET-only', async () => {
  const fetch = guardedFetch(async url => { assert.equal(String(url), 'http://localhost:8082/api/v1/openrouter/key'); return new Response('{}'); }, value);
  await fetch(`${env.AGENTBRIDGE_BASE_URL}/openrouter/key`, { headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` } });
  await assert.rejects(fetch(`${env.AGENTBRIDGE_BASE_URL}/openrouter/key`, { method: 'POST', headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` } }));
});

test('composes explicit service origins without crossing authentication headers', async () => {
  const combined = structuredClone(value);
  combined.profile.environment.STORAGE_TOKEN = 'storage_public_placeholder';
  process.env.STORAGE_TOKEN = 'storage_public_placeholder';
  combined.profile.http.routes.push({ method: 'POST', path: '/v1/r2/check',
    origin: 'http://127.0.0.1:60763', 'credential-header': 'Example-Storage-Credential',
    placeholder: 'storage_public_placeholder' });
  let calls = 0;
  const fetch = guardedFetch(async (input, init) => {
    calls++;
    const url = new URL(input instanceof Request ? input.url : input);
    const headers = new Headers(init.headers);
    if (url.port === '60763') {
      assert.equal(headers.get('Example-Storage-Credential'), 'storage_public_placeholder');
      assert.equal(headers.get('Authorization'), null);
      assert.equal(await input.text(), '{"synthetic":true}');
    } else {
      assert.equal(headers.get('Authorization'), `Bearer ${env.AGENTBRIDGE_API_KEY}`);
      assert.equal(headers.get('Example-Storage-Credential'), null);
    }
    assert.equal(init.redirect, 'error');
    return new Response('{"ok":true}');
  }, combined);
  await fetch(new Request('http://127.0.0.1:60763/v1/r2/check', {
    method: 'POST', headers: { 'Example-Storage-Credential': 'storage_public_placeholder' },
    body: '{"synthetic":true}',
  }));
  await fetch(`${env.AGENTBRIDGE_BASE_URL}/models`, { headers: { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` } });
  for (const [url, method, headers] of [
    ['http://127.0.0.1:60763/v1/r2/check', 'POST', { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` }],
    ['http://127.0.0.1:60763/v1/r2/check', 'POST', { 'Example-Storage-Credential': 'synthetic-unreviewed' }],
    ['http://127.0.0.1:60763/v1/r2/check', 'POST', { 'Example-Storage-Credential': 'storage_public_placeholder', Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}` }],
    ['http://127.0.0.1:60763/v1/r2/check', 'GET', { 'Example-Storage-Credential': 'storage_public_placeholder' }],
    ['http://127.0.0.1:60763/v1/r2/other', 'POST', { 'Example-Storage-Credential': 'storage_public_placeholder' }],
    ['http://127.0.0.1:60763/v1/r2/check?token=synthetic', 'POST', { 'Example-Storage-Credential': 'storage_public_placeholder' }],
    ['http://127.0.0.1:60764/v1/r2/check', 'POST', { 'Example-Storage-Credential': 'storage_public_placeholder' }],
    [`${env.AGENTBRIDGE_BASE_URL}/models`, 'GET', { Authorization: `Bearer ${env.AGENTBRIDGE_API_KEY}`, 'Example-Storage-Credential': 'storage_public_placeholder' }],
    ['http://127.0.0.1:60763/v1/r2/check', 'POST', { 'Example-Storage-Credential': 'storage_public_placeholder', Cookie: 'synthetic' }],
  ]) await assert.rejects(fetch(url, { method, headers }));
  assert.equal(calls, 2);
});
