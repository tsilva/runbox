import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const api = 'https://sentry.io';
const marker = 'sentry_read_public_placeholder';
const responseLimit = 2 * 1024 * 1024;

class DeliveryError extends Error {}

function requireMatch(value, message) {
  if (!value) throw new DeliveryError(message);
}

function origin(value) {
  const url = new URL(value);
  requireMatch(url.protocol === 'https:' && !url.username && !url.password, 'Expected a secure site origin');
  return url.origin;
}

function binding({ organization, project, site, eventId, release, dsnHash }) {
  const slug = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
  requireMatch(slug.test(organization ?? '') && slug.test(project ?? '') &&
    /^[a-f0-9]{32}$/.test(eventId ?? '') && /^[a-f0-9]{40}$/.test(release ?? '') &&
    /^[a-f0-9]{64}$/.test(dsnHash ?? '') && typeof site === 'string' && site === origin(site),
  'Invalid Sentry receipt binding');
}

async function readJson(path, transport) {
  const response = await transport(api + path, {
    method: 'GET', redirect: 'error', signal: AbortSignal.timeout(15000),
    headers: { Accept: 'application/json', Authorization: `Bearer ${marker}` },
  });
  if (response.status !== 200 || response.headers.get('x-agent-vault-decision') !== 'brokered') {
    await response.body?.cancel();
    const status = Number.isInteger(response.status) && response.status >= 400 && response.status <= 599
      ? ` (HTTP ${response.status})` : '';
    throw new DeliveryError('Sentry receipt request failed' + status);
  }
  requireMatch(response.body, 'Sentry receipt response was empty');
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.length;
      if (size > responseLimit) {
        await reader.cancel();
        throw new DeliveryError('Sentry receipt response exceeded the size limit');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
}

export async function readReceipt(policy, transport = fetch) {
  binding(policy);
  const { organization, project, site, eventId, release, dsnHash } = policy;
  const projectPath = `/api/0/projects/${organization}/${project}`;
  const keys = await readJson(`${projectPath}/keys/`, transport);
  requireMatch(Array.isArray(keys) && keys.some(key => key?.isActive === true &&
    typeof key.dsn?.public === 'string' && createHash('sha256').update(key.dsn.public).digest('hex') === dsnHash),
  'The deployed public DSN did not match an active Sentry key');

  const event = await readJson(`${projectPath}/events/${eventId}/`, transport);
  const tags = Object.fromEntries((event.tags ?? []).map(tag => [tag.key, tag.value]));
  const url = event.entries?.find(entry => entry.type === 'request')?.data?.url ?? tags.url;
  const received = Date.parse(event.dateCreated);
  requireMatch(event.eventID?.toLowerCase() === eventId && tags.environment === 'production' &&
    (event.release?.version ?? tags.release) === release && origin(url) === site && Number.isFinite(received),
  'Sentry receipt did not match the reviewed event');
  return { status: 'delivery-verified', project: `${organization}/${project}`, eventId, site,
    environment: 'production', release, receivedAt: new Date(received).toISOString() };
}

function session() {
  const env = process.env;
  const approved = JSON.parse(Buffer.from(env.RUNBOX_POLICY, 'base64url').toString());
  const verified = approved.profile.environment;
  const proxy = new URL(env.HTTPS_PROXY);
  const expectedProxy = new URL(`http://${approved.profile.session.proxy}`);
  requireMatch(env.SENTRY_VAULT_TRANSPORT === 'agent-vault' && env.SENTRY_AUTH_TOKEN === marker &&
    proxy.protocol === 'http:' && proxy.host === expectedProxy.host && proxy.username && proxy.password &&
    proxy.pathname === '/' && !proxy.search && !proxy.hash && env.HTTP_PROXY === env.HTTPS_PROXY &&
    !env.NO_PROXY && !env.no_proxy && env.NODE_USE_ENV_PROXY === '1' &&
    env.NODE_TLS_REJECT_UNAUTHORIZED !== '0' && env.NODE_EXTRA_CA_CERTS === approved.runtime['ca-file'] &&
    process.execArgv.includes('--use-env-proxy') &&
    ['http_proxy', 'https_proxy'].every(key => !env[key] || env[key] === env.HTTPS_PROXY),
  'Expected the reviewed Sentry proxy session');
  const names = {
    organization: 'SENTRY_ORG', project: 'SENTRY_PROJECT', site: 'SENTRY_DELIVERY_SITE',
    eventId: 'SENTRY_DELIVERY_EVENT_ID', release: 'SENTRY_DELIVERY_RELEASE', dsnHash: 'SENTRY_DELIVERY_DSN_SHA256',
  };
  return Object.fromEntries(Object.entries(names).map(([name, key]) => {
    requireMatch(env[key] === verified[key], 'Sentry receipt binding differs from the approved profile');
    return [name, verified[key]];
  }));
}

async function main() {
  const [mode, ...rest] = process.argv.slice(2);
  requireMatch(['check', 'read'].includes(mode) && rest.length === 0, 'Invalid receipt command');
  const receipt = await readReceipt(session());
  const output = mode === 'check'
    ? { ok: true, read_only: true, credential_mode: 'public-placeholder', item_count: 1 }
    : receipt;
  console.log(JSON.stringify(output));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await main();
  } catch (error) {
    console.error(error instanceof DeliveryError ? error.message : 'Sentry delivery check failed; details withheld');
    process.exitCode = 1;
  }
}
