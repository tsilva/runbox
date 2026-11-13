/** Shared startup for an explicitly reviewed, proxy-compatible local Next app. */
import { chmodSync, constants, copyFileSync, unlinkSync } from 'node:fs';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { application, validateSession } from './node-session.mjs';

async function main() {
  const value = JSON.parse(Buffer.from(process.env.RUNBOX_POLICY, 'base64url').toString());
  const client = value.profile.execution.client;
  if (client.type !== 'node-next') throw new Error('Unexpected application profile.');
  if (value.profile.http) {
    // Install the reviewed transport here and in every Next worker. Repository
    // modules never import Runbox or compose its authentication guards.
    const preload = new URL('./node-preload.mjs', import.meta.url).href;
    const option = `--import=${preload}`;
    const inherited = process.env.NODE_OPTIONS ?? '';
    if (!inherited.split(' ').includes(option)) process.env.NODE_OPTIONS = `${option} ${inherited}`.trim();
    await import(preload);
  }
  if (client.adapter) await application(validateSession(value));
  const supplied = process.argv.slice(2);
  const expected = value.profile.execution.command === 'pnpm'
    ? ['dev', '--port', 'auto'] : ['--port', 'auto'];
  if (supplied.join('\0') !== expected.join('\0')) throw new Error('Use the reviewed auto-port command.');
  const root = resolve(value.root, client.root ?? '.');
  if (root !== value.root && !root.startsWith(value.root + '/')) throw new Error('Unexpected application root.');
  const proxy = new URL(process.env.HTTP_PROXY);
  if (proxy.protocol !== 'http:' || proxy.host !== value.profile.session.proxy || !proxy.username || !proxy.password
      || process.env.HTTPS_PROXY !== proxy.href.replace(/\/$/, '') && process.env.HTTPS_PROXY !== proxy.href
      || process.env.HTTP_PROXY !== process.env.HTTPS_PROXY || process.env.NO_PROXY || process.env.no_proxy
      || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('Expected the reviewed native proxy session.');
  for (const script of client.prepare ?? []) {
    if (!value.profile.execution.integrity.files.includes(script)) throw new Error('Unreviewed preparation script.');
    const result = spawnSync(process.execPath, [join(value.root, script)], {
      cwd: root, env: process.env, stdio: 'inherit',
    });
    if (result.status !== 0) throw new Error('Application preparation failed.');
  }
  if (client['temporary-tsconfig']) {
    if (!Number.isSafeInteger(value.pid) || value.pid < 1) throw new Error('Missing owned session identity.');
    const name = `.tsconfig.runbox-${value.pid}.json`;
    const target = join(root, name);
    copyFileSync(join(root, 'tsconfig.json'), target, constants.COPYFILE_EXCL);
    chmodSync(target, 0o600);
    process.env[client['tsconfig-variable'] ?? 'RUNBOX_TSCONFIG'] = name;
    process.on('exit', () => { try { unlinkSync(target); } catch {} });
  }
  const require = createRequire(join(root, 'package.json'));
  const cli = require.resolve('next/dist/bin/next');
  process.chdir(root);
  process.argv = [process.execPath, cli, 'dev', '--webpack', '--hostname', client.hostname ?? '127.0.0.1', '--port', '0'];
  await import(pathToFileURL(cli).href);
}

main().catch(error => {
  const codes = new Set(['EPERM', 'EACCES', 'ENOENT', 'ERR_MODULE_NOT_FOUND', 'EADDRINUSE']);
  const diagnostic = codes.has(error?.code) ? ` (${error.code})` : '';
  console.error(`Runbox application startup failed${diagnostic}; private diagnostics withheld.`);
  process.exitCode = 1;
});
