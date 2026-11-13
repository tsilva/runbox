import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const resources = fileURLToPath(new URL('../runbox/resources/', import.meta.url));

test('Next installs the external HTTP guard before app startup and in child workers', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'runbox-node-next-'));
  try {
    const root = resolve(temporary, 'repo');
    const release = resolve(temporary, 'release');
    mkdirSync(join(release, 'resources'), { recursive: true });
    mkdirSync(join(root, 'node_modules/next/dist/bin'), { recursive: true });
    for (const name of ['next-client.mjs', 'node-session.mjs', 'node-preload.mjs']) {
      copyFileSync(join(resources, name), join(release, 'resources', name));
    }
    writeFileSync(join(root, 'package.json'), '{"name":"synthetic-next-app"}');
    writeFileSync(join(root, 'node_modules/next/package.json'), '{"name":"next","type":"module"}');
    const check = `import assert from 'node:assert/strict';
      await assert.rejects(fetch('https://synthetic:synthetic@unreviewed.invalid/'),
        /outside the reviewed route/);`;
    writeFileSync(join(root, 'node_modules/next/dist/bin/next'), `
      import {spawnSync} from 'node:child_process';
      ${check}
      assert.equal(process.argv.at(-1), '0');
      assert.match(process.env.NODE_OPTIONS, /--import=file:.*node-preload[.]mjs/);
      const worker=spawnSync(process.execPath,['--input-type=module','--eval',${JSON.stringify(check)}],
        {env:process.env,encoding:'utf8',timeout:10000});
      assert.equal(worker.status,0,worker.stderr);
      console.log('external parent and worker guards passed');
    `);
    const publicEnvironment = {
      NODE_ENV: 'development', NODE_USE_ENV_PROXY: '1',
      AGENTBRIDGE_API_KEY: 'agentbridge_public_placeholder',
      AGENTBRIDGE_BASE_URL: 'http://127.0.0.1:8082/api/v1',
      STORAGE_TOKEN: 'storage_public_placeholder',
    };
    const payload = { root, release, pid: process.pid, runtime: {}, profile: {
      environment: publicEnvironment, session: { proxy: '127.0.0.1:8283' },
      execution: { command: 'example-next', client: { type: 'node-next' } },
      http: { 'base-url': publicEnvironment.AGENTBRIDGE_BASE_URL,
        'credential-variable': 'AGENTBRIDGE_API_KEY', placeholder: publicEnvironment.AGENTBRIDGE_API_KEY,
        routes: [{ method: 'GET', path: '/api/v1/models' },
          { method: 'POST', path: '/v1/r2/check', origin: 'http://127.0.0.1:60763',
            'credential-header': 'Example-Storage-Credential', placeholder: publicEnvironment.STORAGE_TOKEN }],
        probe: '/api/v1/models' },
    } };
    const proxy = 'http://synthetic:synthetic@127.0.0.1:8283';
    const result = spawnSync(process.execPath, ['--use-env-proxy', join(release, 'resources/next-client.mjs'), '--port', 'auto'], {
      cwd: root, env: { ...publicEnvironment, HOME: temporary, PATH: '/usr/bin:/bin',
        HTTP_PROXY: proxy, HTTPS_PROXY: proxy, NO_PROXY: '', no_proxy: '',
        RUNBOX_POLICY: Buffer.from(JSON.stringify(payload)).toString('base64url') },
      encoding: 'utf8', timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /external parent and worker guards passed/);
    // The repository's fake Next entry imports no Runbox implementation.
    assert.doesNotMatch(readFileSync(join(root, 'node_modules/next/dist/bin/next'), 'utf8'), /runbox.*import|RUNBOX_POLICY/);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
