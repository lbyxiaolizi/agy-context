import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { inspectBinary, patchBinary } from './binary-patcher.mjs';

const checkpoint = 'google3/third_party/jetski/cortex/utils/utils.GetCheckpointConfig';
const serializer = 'google3/third_party/oneharness/internal/core/serializers/serializers.DefaultSerializer.populateContextWindowMetadata';
const prefix = 'google3/third_party/jetski/prompt/template_provider/templates/system_prompts/';
const main = [0xb94057e3, 0xd29d0004, 0xf2a00064, 0x6b04007f, 0xd29d0004, 0xf2a00064, 0x9a843063, 0xb9005be3];
function putWords(buf, offset, values) {
  values.forEach((v, i) => buf.writeUInt32LE(v >>> 0, offset + i * 4));
}

// A small Mach-O/Go image with the actual instruction windows, including the
// serializer's unreachable alignment word. No host binary is written by tests.
export function binaryFixture() {
  const buf = Buffer.alloc(0x6000);
  const va = 0x100000000;
  buf.writeUInt32LE(0xfeedfacf);
  buf.writeUInt32LE(0x100000c, 4);
  buf.writeUInt32LE(1, 16);
  buf.writeUInt32LE(152, 20);
  buf.writeUInt32LE(0x19, 32);
  buf.writeUInt32LE(152, 36);
  buf.writeBigUInt64LE(BigInt(va), 56);
  buf.writeBigUInt64LE(BigInt(buf.length), 64);
  buf.writeBigUInt64LE(0n, 72);
  buf.writeBigUInt64LE(BigInt(buf.length), 80);
  buf.writeUInt32LE(5, 92);
  buf.writeUInt32LE(1, 96);
  buf.write('__text', 104);
  buf.writeBigUInt64LE(BigInt(va + 0x1000), 136);
  putWords(buf, 0x1000, main);
  putWords(buf, 0x1040, [0x7100007f, 0x5400008c, 0xd29d0003, 0xf2a00063, 0xb9000c03]);
  putWords(buf, 0x1100, [0xf90043e0, 0xf940dfe1, 0xb9000001, 0xb27c07e0]);
  // Unconditional branch back to function start, followed by 4 padding bytes.
  putWords(buf, 0x11f8, [0x14000000 | ((-0xf8 / 4) & 0x3ffffff), 0]);
  const pcl = 0x2000;
  Buffer.from('f1ffffff00000408', 'hex').copy(buf, pcl);
  [2, 0, 0, 72, 0, 0, 0, 0x400].forEach((n, i) => buf.writeBigUInt64LE(BigInt(n), pcl + 8 + i * 8));
  buf.write(checkpoint + '\0' + serializer + '\0', pcl + 72);
  putWords(buf, pcl + 0x400, [0, 0x40, 0x100, 0x60, 0x200, 0]);
  putWords(buf, pcl + 0x440, [0, 0]);
  putWords(buf, pcl + 0x460, [0x100, checkpoint.length + 1]);
  const templates = ['identity.tmpl', 'guidelines.tmpl', 'function_call.tmpl'];
  templates.forEach((name, i) => {
    const nameOffset = 0x3000 + i * 256, data = 0x4000 + i * 256, entry = 0x3800 + i * 48;
    buf.write(prefix + name, nameOffset);
    buf.fill(' ', data, data + 128);
    buf.write(`Original ${name}`, data);
    [va + nameOffset, (prefix + name).length, va + data, 128].forEach((n, j) => buf.writeBigUInt64LE(BigInt(n), entry + j * 8));
  });
  return buf;
}

test('context mode changes all gates and restores exactly without altering prompts', () => {
  const original = binaryFixture();
  const before = inspectBinary(original);
  assert.equal(before.context.mode, 'stock');
  assert.equal(before.context.supported, true);
  let changed = patchBinary(original, { contextMode: '512k' }, original);
  assert.equal(inspectBinary(changed).context.mode, '512k');
  assert.equal(changed.readUInt32LE(0x11fc), 512000);
  assert.deepEqual(inspectBinary(changed).templates, before.templates);
  changed = patchBinary(changed, { contextMode: '900k' }, original);
  assert.equal(inspectBinary(changed).context.mode, '900k');
  assert.equal(changed.readUInt32LE(0x11fc), 983040);
  assert.equal(changed.readUInt32LE(0x1018), 0xd503201f);
  assert.equal(changed.length, original.length);
  assert.deepEqual(patchBinary(changed, { contextMode: 'stock' }, original), original);
});

test('prompt edits preserve other prompts and context; independent restore works', () => {
  const original = binaryFixture();
  const context = patchBinary(original, { contextMode: '900k' }, original);
  let changed = patchBinary(context, { templates: { 'guidelines.tmpl': '先读取文件，再修改。' } }, original);
  changed = patchBinary(changed, { templates: { 'function_call.tmpl': '' } }, original);
  const state = inspectBinary(changed);
  assert.equal(state.templates.find(s => s.name === 'guidelines.tmpl').content, '先读取文件，再修改。');
  assert.equal(state.templates.find(s => s.name === 'function_call.tmpl').content, '');
  assert.equal(state.context.mode, '900k');
  assert.deepEqual(patchBinary(changed, { restorePrompts: true }, original), context);
  assert.deepEqual(patchBinary(changed, { restoreAll: true }, original), original);
});

test('invalid template edits fail before any bytes change', () => {
  const original = binaryFixture(), snapshot = Buffer.from(original);
  for (const templates of [
    { 'identity.tmpl': 'override' }, { 'missing.tmpl': 'text' },
    { 'guidelines.tmpl': '中'.repeat(43) }, { 'guidelines.tmpl': '{{bad syntax' },
    { 'guidelines.tmpl': 'ok', 'function_call.tmpl': '\0' }
  ]) {
    assert.throws(() => patchBinary(original, { templates }, snapshot));
    assert.deepEqual(original, snapshot);
  }
});

test('missing or ambiguous instruction windows never produce a partial context unlock', () => {
  for (const damage of ['missing', 'duplicate', 'cave']) {
    const original = binaryFixture();
    if (damage === 'missing') original.writeUInt32LE(0, 0x1040);
    if (damage === 'duplicate') putWords(original, 0x1080, main);
    if (damage === 'cave') original.writeUInt32LE(1, 0x11fc);
    assert.equal(inspectBinary(original).context.supported, false);
    assert.throws(() => patchBinary(original, { contextMode: '512k' }, original));
  }
});

test('unknown headers and unmapped template pointers are rejected', () => {
  assert.throws(() => inspectBinary(Buffer.alloc(64)));
  const buf = binaryFixture();
  buf.writeBigUInt64LE(0xffffffffffffffffn, 0x3810);
  assert.throws(() => inspectBinary(buf), /身份模板/);
});

test('an overlapping template cannot modify the protected identity bytes', () => {
  const buf = binaryFixture();
  buf.writeBigUInt64LE(0x100004000n, 0x3800 + 48 + 16);
  assert.throws(() => patchBinary(buf, { templates: { 'guidelines.tmpl': 'Replacement' } }, buf), /身份模板重叠/);
});

test('embedded Go metadata outside the designated Mach-O section is ignored', () => {
  const buf = binaryFixture();
  buf.writeUInt32LE(232, 36);
  buf.writeUInt32LE(2, 96);
  buf.write('__lrodata_gopcln', 184);
  buf.writeUInt32LE(0x2000, 232);
  buf.copy(buf, 0x5000, 0x2000, 0x2500);
  assert.equal(inspectBinary(buf).context.mode, 'stock');
});

function peFixture() {
  const buf = binaryFixture();
  buf.fill(0, 0, 0x1000);
  buf.write('MZ');
  buf.writeUInt32LE(0x80, 0x3c);
  buf.writeUInt32LE(0x4550, 0x80);
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(1, 0x86);
  buf.writeUInt16LE(0xf0, 0x94);
  buf.writeUInt16LE(0x20b, 0x98);
  buf.writeBigUInt64LE(0x100000000n, 0xb0);
  buf.write('.text', 0x188);
  buf.writeUInt32LE(0x5000, 0x190);
  buf.writeUInt32LE(0x1000, 0x194);
  buf.writeUInt32LE(0x5000, 0x198);
  buf.writeUInt32LE(0x1000, 0x19c);
  buf.writeUInt32LE(0x20000000, 0x1ac);
  buf[0x2006] = 1;
  buf.writeBigUInt64LE(0x100001000n, 0x2018);
  buf.fill(0, 0x1000, 0x1200);
  const patterns = [
    [0x1000, '8b54244c81fa00e80300be00e803000f42f289742450'],
    [0x1040, '837a14007f07c7400c00e80300'],
    [0x1100, '4889442470488b8c24a80100008908b830000000']
  ];
  patterns.forEach(([offset, bytes]) => Buffer.from(bytes, 'hex').copy(buf, offset));
  return buf;
}

test('PE64 reference patches switch both compression paths and the display limit', () => {
  const buf = peFixture();
  assert.equal(inspectBinary(buf).context.mode, 'stock');
  let patched = patchBinary(buf, { contextMode: '512k' }, buf);
  assert.equal(inspectBinary(patched).context.mode, '512k');
  assert.equal(patched.readUInt32LE(0x1000 + 6), 512000);
  patched = patchBinary(patched, { contextMode: '900k' }, buf);
  assert.equal(inspectBinary(patched).context.mode, '900k');
  assert.equal(patched.readUInt32LE(0x1100 + 7), 983040);
  assert.deepEqual(patchBinary(patched, { contextMode: 'stock' }, buf), buf);
});

test('HTTP settings apply, independent restore, conflicts and validation preserve user files', { timeout: 30000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-context-api-'));
  const binary = path.join(dir, 'language_server.exe');
  const configDir = path.join(dir, 'config');
  fs.mkdirSync(configDir);
  const configPath = path.join(configDir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({ contextWindow: '128K', unrelated: true }));
  const original = peFixture();
  fs.writeFileSync(binary, original, { mode: 0o755 });
  const reservation = net.createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const child = spawn(process.execPath, ['sidecars/context-panel/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, AGY_CONTEXT_BINARY: binary, AGY_CONTEXT_BACKUP_DIR: path.join(dir, 'backups'),
      AGY_CONTEXT_CONFIG_DIR: configDir, ANTIGRAVITY_SIDECAR_WEB_PORT: String(port), ANTIGRAVITY_SIDECAR_UI_TOKEN: 'test-sidecar-token' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let logs = '';
  child.stderr.on('data', chunk => { logs += chunk; });
  const base = `http://127.0.0.1:${port}`;
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Server startup timeout: ${logs}`)), 10000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); reject(new Error(`Server exited ${code}: ${logs}`)); });
      child.stdout.on('data', chunk => {
        logs += chunk;
        if (logs.includes('Background Sidecar daemon listening')) { clearTimeout(timer); resolve(); }
      });
    });
    const auth = { 'x-sidecar-token': 'test-sidecar-token' };
    assert.equal((await fetch(base + '/api/customization')).status, 401);
    const listingResponse = await fetch(base + '/api/customization', { headers: auth });
    assert.equal(listingResponse.status, 200);
    const listing = await listingResponse.json();
    const targetId = listing.targets.find(t => t.path === binary).id;
    const headers = { ...auth, 'content-type': 'application/json', 'x-context-settings-token': listing.token };
    const post = async (route, data, requestHeaders = headers) => {
      const response = await fetch(base + '/api/customization/' + route, { method: 'POST', headers: requestHeaders, body: JSON.stringify({ targetId, ...data }) });
      return { status: response.status, data: await response.json() };
    };
    assert.equal((await post('apply', {}, auth)).status, 403);
    assert.equal((await post('inspect', {}, { ...headers, origin: 'https://example.com' })).status, 403);
    assert.equal((await post('inspect', {}, { ...headers, origin: `http://127.0.0.1:${port + 1}` })).status, 403);
    // Sidecar requests proxied through Antigravity's local gateway preserve localhost:<gatewayPort> Host & Origin.
    const gatewayPort = port + 2;
    const proxiedGetStatus = await new Promise((resolve, reject) => {
      const req = http.get(base + '/api/customization', { headers: { ...auth, host: `localhost:${gatewayPort}` } }, res => {
        res.resume();
        resolve(res.statusCode);
      });
      req.on('error', reject);
    });
    assert.equal(proxiedGetStatus, 200);
    const proxiedPostStatus = await new Promise((resolve, reject) => {
      const payload = JSON.stringify({ targetId });
      const req = http.request(base + '/api/customization/inspect', {
        method: 'POST',
        headers: {
          ...headers,
          host: `localhost:${gatewayPort}`,
          origin: `http://localhost:${gatewayPort}`,
          'content-length': Buffer.byteLength(payload)
        }
      }, res => {
        res.resume();
        resolve(res.statusCode);
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
    assert.equal(proxiedPostStatus, 200);
    // fetch controls Host itself; use HTTP directly to exercise DNS rebinding.
    const foreignHostStatus = await new Promise((resolve, reject) => {
      const req = http.get(base + '/api/customization', { headers: { ...auth, host: 'example.com' } }, res => {
        res.resume();
        resolve(res.statusCode);
      });
      req.on('error', reject);
    });
    assert.equal(foreignHostStatus, 403);
    assert.equal((await fetch(base + '/api/customization/inspect', { method: 'POST', headers, body: 'null' })).status, 400);
    assert.equal((await fetch(base + '/api/customization/apply', { method: 'POST', headers,
      body: JSON.stringify({ targetId, padding: 'x'.repeat(2 * 1024 * 1024) }) })).status, 413);
    assert.equal((await fetch(base + '/api/customization/apply', { headers: auth })).status, 405);
    let state = (await post('inspect', {})).data;
    assert.equal(state.context.mode, 'stock');
    assert.equal((await post('apply', { expectedHash: '0'.repeat(64), contextMode: '512k' })).status, 409);
    const applied = await post('apply', { expectedHash: state.hash, contextMode: '512k' });
    assert.equal(applied.status, 200, JSON.stringify(applied.data));
    state = applied.data;
    assert.equal(state.context.mode, '512k');
    assert.equal(JSON.parse(fs.readFileSync(configPath)).contextWindow, '512K');
    const staleHash = state.hash;
    state = (await post('apply', { expectedHash: state.hash, templates: { 'guidelines.tmpl': 'Read first.' } })).data;
    assert.equal(state.templates.find(s => s.name === 'guidelines.tmpl').content, 'Read first.');
    assert.equal((await post('apply', { expectedHash: staleHash, restoreAll: true })).status, 409);
    const beforeInvalid = fs.readFileSync(binary);
    const invalid = await post('apply', { expectedHash: state.hash, templates: { 'identity.tmpl': 'Changed' } });
    assert.ok(invalid.status >= 400);
    assert.deepEqual(fs.readFileSync(binary), beforeInvalid);
    fs.writeFileSync(configPath, '{broken');
    const malformed = await post('apply', { expectedHash: state.hash, contextMode: '900k' });
    assert.ok(malformed.status >= 400);
    assert.deepEqual(fs.readFileSync(binary), beforeInvalid);
    fs.writeFileSync(configPath, JSON.stringify({ contextWindow: '512K', unrelated: 'newer user setting' }));
    state = (await post('apply', { expectedHash: state.hash, restorePrompts: true })).data;
    assert.equal(state.context.mode, '512k');
    assert.equal(state.templates.find(s => s.name === 'guidelines.tmpl').content, inspectBinary(original).templates.find(s => s.name === 'guidelines.tmpl').content);
    state = (await post('apply', { expectedHash: state.hash, restoreAll: true })).data;
    assert.equal(state.context.mode, 'stock');
    assert.deepEqual(fs.readFileSync(binary), original);
    assert.deepEqual(JSON.parse(fs.readFileSync(configPath)), { contextWindow: '128K', unrelated: 'newer user setting' });
    const altered = Buffer.from(original);
    altered[altered.length - 1] = 1;
    fs.writeFileSync(binary, altered);
    const externallyChanged = (await post('inspect', {})).data;
    const rejected = await post('apply', { expectedHash: externallyChanged.hash, restoreAll: true });
    assert.equal(rejected.status, 409);
    assert.deepEqual(fs.readFileSync(binary), altered);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await once(child, 'exit');
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
