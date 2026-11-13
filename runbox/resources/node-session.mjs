import { pathToFileURL } from 'node:url';

export function context() {
  const value = JSON.parse(Buffer.from(process.env.RUNBOX_POLICY ?? '', 'base64url').toString('utf8'));
  if (!value.profile || !value.runtime || typeof value.root !== 'string') throw new Error('Missing reviewed Runbox policy.');
  return value;
}

export function validateSession(value = context(), env = process.env) {
  const { profile } = value;
  if (!process.versions.node.startsWith('24.') || env.NODE_TLS_REJECT_UNAUTHORIZED === '0'
      || (env.NO_PROXY ?? '').trim() || (env.no_proxy ?? '').trim()) throw new Error('Unexpected client runtime or proxy bypass.');
  for (const [name, expected] of Object.entries(profile.environment)) {
    // Machine substitutions are public paths resolved by the trusted parent.
    if (!expected.includes('{') && env[name] !== expected) throw new Error('Expected public environment or placeholder is missing.');
  }
  const proxies = ['HTTP_PROXY', 'HTTPS_PROXY'].map(name => new URL(env[name]));
  if (proxies.some(proxy => proxy.protocol !== 'http:' || proxy.host !== profile.session.proxy || !proxy.username || !proxy.password)
      || proxies[0].href !== proxies[1].href) throw new Error('Expected scoped native proxy is missing.');
  for (const name of ['http_proxy', 'https_proxy']) {
    if (env[name] && new URL(env[name]).href !== proxies[0].href) throw new Error('Conflicting proxy session.');
  }
  const http = profile.http;
  if (http && env[http['credential-variable']] !== http.placeholder) throw new Error('Expected placeholder is missing.');
  for (const name of ['OPENROUTER_API_KEY', 'SENTRY_AUTH_TOKEN', 'VERCEL_ENV']) {
    if (env[name] && !(name in profile.environment)) throw new Error('Unexpected ambient client configuration.');
  }
  return value;
}

export async function application(value = validateSession()) {
  const client = value.profile.execution.client;
  if (!client.adapter) return null;
  const adapter = await import(pathToFileURL(`${value.root}/${client.adapter}`).href);
  const env = process.env;
  if (client['provider-export']) {
    const provider = adapter[client['provider-export']]?.(env);
    if (!provider || provider.apiKey !== value.profile.http.placeholder
        || provider.endpoint !== `${value.profile.http['base-url']}/chat/completions`) throw new Error('Unexpected application provider.');
    return { module: adapter, model: provider.model };
  }
  const base = adapter.providerBaseUrl?.(env) ?? adapter.agentBridgeBaseUrl?.(env);
  const key = adapter.providerApiKey?.(env) ?? env[value.profile.http['credential-variable']];
  if (base !== value.profile.http['base-url'] || key !== value.profile.http.placeholder) throw new Error('Unexpected application routing.');
  if (client['default-model']) {
    const model = adapter.agentBridgeModel?.(client['default-model']);
    if (typeof model !== 'string' || (client['expected-model'] && model !== client['expected-model'])) throw new Error('Unexpected application model routing.');
  }
  return { module: adapter, model: client['default-model'] ? adapter.agentBridgeModel(client['default-model']) : undefined };
}

export function guardedFetch(fetchImpl, value = validateSession()) {
  const policy = value.profile.http;
  const base = new URL(policy['base-url']);
  const credentialHeaders = new Set(['authorization', 'api-key', 'x-api-key',
    ...policy.routes.filter(route => route['credential-header']).map(route => route['credential-header'].toLowerCase())]);
  let failed = false;
  return async (input, init) => {
    if (failed) throw new Error('Session stopped after a service request failure.');
    validateSession(value);
    const target = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const method = (init?.method ?? input.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers ?? input.headers);
    const route = policy.routes.find(route => (route.origin ?? base.origin) === target.origin
      && route.method === method && route.path === target.pathname
      && (route.queries ?? ['']).includes(target.search.slice(1)));
    const credentialHeader = (route?.['credential-header'] ?? 'authorization').toLowerCase();
    const expected = route?.origin ? route.placeholder : `Bearer ${policy.placeholder}`;
    if (target.hash || target.username || target.password || !route
        || headers.get(credentialHeader) !== expected
        || ['cookie', 'proxy-authorization'].some(name => headers.has(name))
        || [...credentialHeaders].some(name => name !== credentialHeader && headers.has(name))) throw new Error('Request is outside the reviewed route.');
    if (route['forward-host']) target.host = route['forward-host'];
    let response;
    try {
      const options = { ...init, headers, redirect: 'error' };
      if (typeof input !== 'string' && !(input instanceof URL)) {
        response = await fetchImpl(new Request(target, input), options);
      } else {
        response = await fetchImpl(target, options);
      }
    } catch {
      failed = true;
      throw new Error('Service connection failed; private diagnostics withheld.');
    }
    if (!response.ok) {
      failed = true;
      await response.body?.cancel();
      return new Response(JSON.stringify({ error: { message: 'Service request failed; provider details withheld.' } }),
        { status: response.status, headers: { 'Content-Type': 'application/json' } });
    }
    return response;
  };
}
