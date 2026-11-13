import { copyFileSync, unlinkSync } from 'node:fs';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateSession, application } from './node-session.mjs';

let stage = 'startup';
function probeFailure(response) {
  const error = new Error('Read-only probe failed.');
  error.httpStatus = response.status;
  return error;
}

async function main() {
  const value = validateSession();
  const adapter = await application(value);
  const action = process.argv[2];
  if (action === 'probe') {
    if (process.argv.length !== 3) throw new Error('Read-only probe accepts no arguments.');
    const policy = value.profile.http;
    const target = new URL(policy['base-url']);
    target.pathname = policy.probe;
    stage = 'catalog';
    const response = await fetch(target, { headers: { Authorization: `Bearer ${policy.placeholder}` },
      redirect: 'error', signal: AbortSignal.timeout(15_000) });
    if (!response.ok) { await response.body?.cancel(); throw probeFailure(response); }
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value: chunk } = await reader.read();
      if (done) break;
      size += chunk.byteLength;
      if (size > 4 * 1024 * 1024) { await reader.cancel(); throw new Error('Probe response exceeds size limit.'); }
      chunks.push(chunk);
    }
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!Array.isArray(body.data) || !body.data.length || !body.data.every(row => typeof row.id === 'string')) throw new Error('Invalid model catalog.');
    if (value.profile.execution.client['require-model'] && !body.data.some(row => row.id === adapter?.model)) throw new Error('Configured model is unavailable.');
    for (const path of policy['additional-probes'] ?? []) {
      stage = 'additional-probe';
      target.pathname = path;
      const extra = await fetch(target, { headers: { Authorization: `Bearer ${policy.placeholder}` },
        redirect: 'error', signal: AbortSignal.timeout(15_000) });
      if (!extra.ok) { await extra.body?.cancel(); throw probeFailure(extra); }
      await extra.body?.cancel();
    }
    console.log(JSON.stringify({ ok: true, read_only: true, credential_mode: 'public-placeholder', model_count: body.data.length }));
    return;
  }
  const supplied = process.argv.slice(3);
  if (action === 'script') {
    const script = value.profile.execution.client.script;
    if (!script || supplied[0] !== script) throw new Error('Unexpected application entrypoint.');
    const target = join(value.root, script);
    process.argv = [process.execPath, target, ...supplied.slice(1)];
    await import(pathToFileURL(target).href);
    return;
  }
  const portArguments = supplied[0] === 'dev' ? supplied.slice(1) : supplied;
  if (action !== 'next' || portArguments.join(' ') !== '--port auto') throw new Error('Use the reviewed app command with --port auto.');
  const client = value.profile.execution.client;
  for (const prepare of client.prepare ?? []) {
    const result = spawnSync(process.execPath, [join(value.root, prepare)], { stdio: 'inherit', env: process.env, cwd: value.root });
    if (result.status !== 0) throw new Error('Application preparation failed.');
  }
  if (client['temporary-tsconfig']) {
    const name = `.tsconfig.agent-vault-${process.pid}.json`;
    const target = join(value.root, name);
    copyFileSync(join(value.root, 'tsconfig.json'), target);
    process.env.AGENTBRIDGE_VAULT_TSCONFIG = name;
    process.on('exit', () => { try { unlinkSync(target); } catch {} });
  }
  const require = createRequire(join(value.root, 'package.json'));
  const cli = require.resolve('next/dist/bin/next');
  process.argv = [process.execPath, cli, 'dev', '--webpack', '--hostname', client.hostname ?? '127.0.0.1', '--port', '0'];
  await import(pathToFileURL(cli).href);
}

main().catch(error => {
  const codes = new Set(['EPERM', 'EACCES', 'ENOENT', 'ERR_MODULE_NOT_FOUND', 'ERR_ACCESS_DENIED', 'EADDRINUSE',
    'ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ENOTFOUND', 'ECONNREFUSED', 'ETIMEDOUT']);
  const operations = new Set(['open', 'scandir', 'realpath', 'listen', 'bind', 'connect', 'read', 'write', 'stat']);
  const diagnostic = [stage, codes.has(error?.code) ? error.code : '', operations.has(error?.syscall) ? error.syscall : '',
    Number.isInteger(error?.httpStatus) && error.httpStatus >= 100 && error.httpStatus <= 599 ? `HTTP${error.httpStatus}` : ''].filter(Boolean).join('/');
  console.error(`Runbox client failed${diagnostic ? ` (${diagnostic})` : ''}; private diagnostics withheld.`);
  process.exitCode = 1;
});
