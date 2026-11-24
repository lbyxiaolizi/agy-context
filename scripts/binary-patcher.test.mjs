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

const CHECKPOINT_SYM = 'google3/third_party/jetski/cortex/utils/utils.GetCheckpointConfig';
const EXP_CHECKPOINT_SYM = 'google3/third_party/jetski/cortex/config/config.applyFeatureProviderCheckpointOverrideConfig';
const SELECT_EXP_SYM = 'google3/third_party/jetski/cortex/config/config.selectCheckpointExperimentKey';
const OFFERS_SYM = 'google3/third_party/jetski/cli/model/model.SelectorModel.offersContextWindow';
const STORE_CW_SYM = 'google3/third_party/jetski/cli/store/store.(*Store).ContextWindow';
const STORE_CHOICE_SYM = 'google3/third_party/jetski/cli/store/store.(*Store).ContextWindowChoice';
const OVERRIDE_SYM = 'google3/third_party/jetski/cli/store/store.AutoCompactOverride';
const PREFIX = 'google3/third_party/jetski/prompt/template_provider/templates/system_prompts/';

// utils.GetCheckpointConfig 6-word arm64 clamp window (x3/w3 clamped against x4 = 256,000)
const ARM64_CLAMP_WINDOW = [0xb94057e3, 0xd29d0004, 0xf2a00064, 0x6b04007f, 0xd29d0004, 0xf2a00064, 0x9a843063, 0xb9005be3];

function putWords(buf, offset, values) {
  values.forEach((v, i) => buf.writeUInt32LE(v >>> 0, offset + i * 4));
}

function writePclntab(buf, pcl, textVa, funcs, arch) {
  buf.fill(0, pcl, pcl + 0x800);
  Buffer.from(arch === 'arm64' ? 'f1ffffff00000408' : 'f1ffffff00000108', 'hex').copy(buf, pcl);
  [funcs.length, 0, textVa, 72, 0, 0, 0, 0x400].forEach((n, i) => {
    buf.writeBigUInt64LE(BigInt(n), pcl + 8 + i * 8);
  });
  let nameCursor = 0;
  const table = pcl + 0x400;
  const recBase = (funcs.length + 1) * 8;
  funcs.forEach((fn, i) => {
    const startPc = fn.startOff - 0x1000;
    const funcoff = recBase + i * 8;
    buf.writeUInt32LE(startPc, table + i * 8);
    buf.writeUInt32LE(funcoff, table + i * 8 + 4);
    buf.writeUInt32LE(startPc, table + funcoff);
    buf.writeInt32LE(nameCursor, table + funcoff + 4);
    buf.write(fn.name + '\0', pcl + 72 + nameCursor);
    nameCursor += fn.name.length + 1;
  });
  const lastEndPc = funcs[funcs.length - 1].endOff - 0x1000;
  buf.writeUInt32LE(lastEndPc, table + funcs.length * 8);
  buf.writeUInt32LE(0, table + funcs.length * 8 + 4);
}

function writeMachoBase(funcs, arch = 'arm64') {
  const buf = Buffer.alloc(0x8000);
  const va = 0x100000000;
  buf.writeUInt32LE(0xfeedfacf);
  buf.writeUInt32LE(arch === 'arm64' ? 0x100000c : 0x1000007, 4);
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
  writePclntab(buf, 0x2000, va + 0x1000, funcs, arch);
  const templates = ['identity.tmpl', 'guidelines.tmpl', 'function_call.tmpl'];
  templates.forEach((name, i) => {
    const nameOffset = 0x3000 + i * 256, data = 0x4000 + i * 256, entry = 0x3800 + i * 48;
    buf.write(PREFIX + name, nameOffset);
    buf.fill(' ', data, data + 128);
    buf.write(`Original ${name}`, data);
    [va + nameOffset, (PREFIX + name).length, va + data, 128].forEach((n, j) => buf.writeBigUInt64LE(BigInt(n), entry + j * 8));
  });
  return buf;
}

// A small Mach-O/Go server image with Gate 3A and Gate 3B windows. No host binary is written by tests.
export function binaryFixture() {
  const funcs = [
    { name: CHECKPOINT_SYM, startOff: 0x1000, endOff: 0x1080 },
    { name: EXP_CHECKPOINT_SYM, startOff: 0x1100, endOff: 0x1180 }
  ];
  const buf = writeMachoBase(funcs, 'arm64');
  putWords(buf, 0x1000, ARM64_CLAMP_WINDOW);
  // Gate 3B primary pattern: bl + cbz x1, +24 + 5 words + (ldr x1,[sp,#0x48]; mov x2,x0)
  putWords(buf, 0x1110, [0x94000010, 0xb40000c1, 0xf9002be0, 0xaa0103e0, 0xaa0203e1, 0x97ffff00, 0xf9402be0, 0xf94027e1, 0xaa0003e2]);
  return buf;
}

// A small Mach-O/Go agy CLI image with Gate 1, Rich Gate 2, Gate 3A, and Gate 3B.
export function cliArm64Fixture() {
  const funcs = [
    { name: CHECKPOINT_SYM, startOff: 0x1000, endOff: 0x1080 },
    { name: EXP_CHECKPOINT_SYM, startOff: 0x1100, endOff: 0x1180 },
    { name: OVERRIDE_SYM, startOff: 0x1200, endOff: 0x1240 },
    { name: STORE_CHOICE_SYM, startOff: 0x1240, endOff: 0x1280 },
    { name: OFFERS_SYM, startOff: 0x1280, endOff: 0x12c0 },
    { name: STORE_CW_SYM, startOff: 0x1300, endOff: 0x1500 }
  ];
  const buf = writeMachoBase(funcs, 'arm64');
  putWords(buf, 0x1000, ARM64_CLAMP_WINDOW);
  putWords(buf, 0x1110, [0x94000010, 0xb40000c1, 0xf9002be0, 0xaa0103e0, 0xaa0203e1, 0x97ffff00, 0xf9402be0, 0xf94027e1, 0xaa0003e2]);
  putWords(buf, 0x1200, [0xd65f03c0]); // AutoCompactOverride
  putWords(buf, 0x1240, [0xd65f03c0]); // ContextWindowChoice
  putWords(buf, 0x1280, [0xf9400b90, 0xd10043f1, 0xeb10023f, 0xd65f03c0]); // offersContextWindow
  // Store.ContextWindow (0x1300..0x1500): prologue save, Argon tbnz, bl AutoCompactOverride, cbnz -> epilogue
  putWords(buf, 0x1300, [0xf9400b90, 0xeb3063ff, 0xf8180ffe, 0xf90047e0]); // +0x0c: str x0, [sp, #0x88]
  putWords(buf, 0x1350, [0x92800000, 0xb7f801c0]); // +0x50: mov x0,#-1 ; +0x54: tbnz x0,#0x3f,...
  const blDelta = (0x1200 - 0x1370) >> 2;
  const blWord = (0x94000000 | (blDelta & 0x03ffffff)) >>> 0;
  const cbnzWord = (0xb5000001 | (10 << 5)) >>> 0; // +0x74 -> +0x9c (10 words)
  putWords(buf, 0x1370, [blWord, cbnzWord, 0xd503201f, 0xf94047e2, 0xf9405c42, 0xb4000162, 0xf9400441]);
  putWords(buf, 0x139c, [0xf85f83fd, 0xf84807fe, 0xd65f03c0]); // epilogue: ldur x29 ; ldr x30 ; ret
  return buf;
}

function peFromMacho(funcs, patches) {
  const buf = writeMachoBase(funcs, 'x64');
  buf.fill(0, 0, 0x1000);
  buf.fill(0, 0x1000, 0x1800);
  buf.write('MZ');
  buf.writeUInt32LE(0x80, 0x3c);
  buf.writeUInt32LE(0x4550, 0x80);
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(1, 0x86);
  buf.writeUInt16LE(0xf0, 0x94);
  buf.writeUInt16LE(0x20b, 0x98);
  buf.writeBigUInt64LE(0x100000000n, 0xb0);
  buf.write('.text', 0x188);
  buf.writeUInt32LE(0x7000, 0x190);
  buf.writeUInt32LE(0x1000, 0x194);
  buf.writeUInt32LE(0x7000, 0x198);
  buf.writeUInt32LE(0x1000, 0x19c);
  buf.writeUInt32LE(0x20000000, 0x1ac);
  patches.forEach(([offset, bytes]) => Buffer.from(bytes, 'hex').copy(buf, offset));
  return buf;
}

function peFixture() {
  const funcs = [
    { name: CHECKPOINT_SYM, startOff: 0x1000, endOff: 0x1080 },
    { name: SELECT_EXP_SYM, startOff: 0x1080, endOff: 0x10c0 },
    { name: EXP_CHECKPOINT_SYM, startOff: 0x1100, endOff: 0x1180 }
  ];
  const callDisp = Buffer.alloc(4);
  callDisp.writeInt32LE(0x1080 - (0x1110 + 5), 0);
  return peFromMacho(funcs, [
    [0x1000, '8b54244c81fa00e80300be00e803000f42f289742450'],
    [0x1080, 'c3'],
    [0x1110, 'e8' + callDisp.toString('hex') + '4885c084c07512b801000000c3']
  ]);
}

function peCliFixture() {
  const funcs = [
    { name: CHECKPOINT_SYM, startOff: 0x1000, endOff: 0x1080 },
    { name: SELECT_EXP_SYM, startOff: 0x1080, endOff: 0x10c0 },
    { name: EXP_CHECKPOINT_SYM, startOff: 0x1100, endOff: 0x1180 },
    { name: OFFERS_SYM, startOff: 0x1200, endOff: 0x1240 },
    { name: STORE_CHOICE_SYM, startOff: 0x1240, endOff: 0x1280 },
    { name: STORE_CW_SYM, startOff: 0x1280, endOff: 0x1300 }
  ];
  const callDisp = Buffer.alloc(4);
  callDisp.writeInt32LE(0x1080 - (0x1110 + 5), 0);
  return peFromMacho(funcs, [
    [0x1000, '8b54244c81fa00e80300be00e803000f42f289742450'],
    [0x1080, 'c3'],
    [0x1110, 'e8' + callDisp.toString('hex') + '4885c084c00f8520000000c3'],
    [0x1200, '4883ec204889442410c3'],
    [0x1240, 'b800000000c3'],
    [0x1280, '4883ec384889442420c3']
  ]);
}

test('context modes transition across stock/512k/900k/dynamic and restore byte-for-byte on all targets', () => {
  const cases = [
    { label: 'arm64 server', make: binaryFixture, kind: 'server', gates: ['gate3a', 'gate3b'] },
    { label: 'arm64 cli', make: cliArm64Fixture, kind: 'cli', gates: ['gate1', 'gate2-whitelist', 'gate2-tail', 'gate3a', 'gate3b'] },
    { label: 'x64 server', make: peFixture, kind: 'server', gates: ['gate3a', 'gate3b'] },
    { label: 'x64 cli', make: peCliFixture, kind: 'cli', gates: ['gate1', 'gate2', 'gate3a', 'gate3b'] }
  ];
  for (const tc of cases) {
    const original = tc.make();
    const before = inspectBinary(original);
    assert.equal(before.context.supported, true, tc.label);
    assert.equal(before.context.targetKind, tc.kind, tc.label);
    assert.equal(before.context.mode, 'stock', tc.label);
    assert.deepEqual(before.context.gates.map(g => g.id), tc.gates, tc.label);

    let current = original;
    for (const mode of ['512k', '900k', 'dynamic', '512k']) {
      current = patchBinary(current, { contextMode: mode }, original);
      const state = inspectBinary(current);
      assert.equal(state.context.supported, true, `${tc.label} -> ${mode}`);
      assert.equal(state.context.mode, mode, `${tc.label} -> ${mode}`);
      assert.deepEqual(state.templates, before.templates, `${tc.label} templates preserved`);
      assert.equal(current.length, original.length);
    }
    const restored = patchBinary(current, { contextMode: 'stock' }, original);
    assert.equal(restored.equals(original), true, `${tc.label} byte-exact stock restore`);
  }
});

test('arm64 fallback Gate 3B and entry-jump Gate 2 work cleanly', () => {
  const funcs = [
    { name: CHECKPOINT_SYM, startOff: 0x1000, endOff: 0x1080 },
    { name: SELECT_EXP_SYM, startOff: 0x1080, endOff: 0x10c0 },
    { name: EXP_CHECKPOINT_SYM, startOff: 0x1100, endOff: 0x1180 },
    { name: STORE_CHOICE_SYM, startOff: 0x1240, endOff: 0x1280 },
    { name: OFFERS_SYM, startOff: 0x1280, endOff: 0x12c0 },
    { name: STORE_CW_SYM, startOff: 0x1300, endOff: 0x1340 } // < 0x100 triggers clean entry-jump fallback
  ];
  const buf = writeMachoBase(funcs, 'arm64');
  putWords(buf, 0x1000, ARM64_CLAMP_WINDOW);
  putWords(buf, 0x1080, [0xd65f03c0]);
  const blSel = (0x94000000 | (((0x1080 - 0x1110) >> 2) & 0x03ffffff)) >>> 0;
  // bl selectCheckpointExperimentKey ; blr x6 ; tbnz w0,#0,+0xc
  putWords(buf, 0x1110, [blSel, 0xd63f00c0, 0x37000060, 0xd65f03c0]);
  putWords(buf, 0x1240, [0xd65f03c0]);
  putWords(buf, 0x1280, [0xf9400b90, 0xd10043f1, 0xeb10023f, 0xd65f03c0]);
  putWords(buf, 0x1300, [0xf9400b90, 0xd10043f1, 0xeb10023f, 0xd65f03c0]);

  const patched = patchBinary(buf, { contextMode: 'dynamic' }, buf);
  const info = inspectBinary(patched);
  assert.equal(info.context.supported, true);
  assert.equal(info.context.mode, 'dynamic');
  assert.deepEqual(info.context.gates.map(g => g.id), ['gate1', 'gate2', 'gate3a', 'gate3b']);
  assert.equal(patchBinary(patched, { contextMode: 'stock' }, buf).equals(buf), true);
});

test('prompt edits preserve other prompts and context; independent restore works', () => {
  const original = binaryFixture();
  const context = patchBinary(original, { contextMode: 'dynamic' }, original);
  let changed = patchBinary(context, { templates: { 'guidelines.tmpl': '先读取文件，再修改。' } }, original);
  changed = patchBinary(changed, { templates: { 'function_call.tmpl': '' } }, original);
  const state = inspectBinary(changed);
  assert.equal(state.templates.find(s => s.name === 'guidelines.tmpl').content, '先读取文件，再修改。');
  assert.equal(state.templates.find(s => s.name === 'function_call.tmpl').content, '');
  assert.equal(state.context.mode, 'dynamic');
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

test('missing, ambiguous, inconsistent, or non-stock baselines fail closed', () => {
  // Missing Gate 3B
  const missing3b = binaryFixture();
  missing3b.writeUInt32LE(0, 0x1114);
  assert.equal(inspectBinary(missing3b).context.supported, false);
  assert.throws(() => patchBinary(missing3b, { contextMode: '512k' }, missing3b));

  // Duplicate Gate 3A
  const dup3a = binaryFixture();
  putWords(dup3a, 0x1040, ARM64_CLAMP_WINDOW);
  assert.equal(inspectBinary(dup3a).context.supported, false);
  assert.throws(() => patchBinary(dup3a, { contextMode: '512k' }, dup3a));

  // Mixed / inconsistent gate states (Gate 3A unlocked to 512k while Gate 3B remains stock)
  const mixed = binaryFixture();
  const patched512 = patchBinary(mixed, { contextMode: '512k' }, mixed);
  const g3bOffset = inspectBinary(mixed).context.gates.find(g => g.id === 'gate3b').offset;
  mixed.subarray(g3bOffset, g3bOffset + 24).copy(patched512, g3bOffset);
  const mixedInfo = inspectBinary(patched512);
  assert.equal(mixedInfo.context.supported, false);
  assert.equal(mixedInfo.context.mode, 'unknown');
  assert.throws(() => patchBinary(patched512, { contextMode: '900k' }, mixed));

  // Missing CLI companion symbol (offersContextWindow present, Store.ContextWindowChoice absent)
  const brokenCli = cliArm64Fixture();
  const choiceIdx = brokenCli.indexOf(Buffer.from(STORE_CHOICE_SYM + '\0'));
  brokenCli.write('X', choiceIdx + STORE_CHOICE_SYM.length - 1);
  assert.equal(inspectBinary(brokenCli).context.supported, false);
  assert.throws(() => patchBinary(brokenCli, { contextMode: '512k' }, brokenCli));

  // Calling contextMode: 'stock' without a stock baseline
  const baseline512 = patchBinary(binaryFixture(), { contextMode: '512k' }, binaryFixture());
  assert.throws(() => patchBinary(baseline512, { contextMode: 'stock' }, baseline512), /原生备份/);
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
  buf.copy(buf, 0x5000, 0x2000, 0x2800);
  assert.equal(inspectBinary(buf).context.mode, 'stock');
});

test('HTTP settings apply (including dynamic), independent restore, conflicts and validation preserve user files', { timeout: 30000 }, async () => {
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
    state = (await post('apply', { expectedHash: state.hash, contextMode: 'dynamic' })).data;
    assert.equal(state.context.mode, 'dynamic');
    assert.equal(JSON.parse(fs.readFileSync(configPath)).contextWindow, '');
    state = (await post('apply', { expectedHash: state.hash, restorePrompts: true })).data;
    assert.equal(state.context.mode, 'dynamic');
    assert.equal(state.templates.find(s => s.name === 'guidelines.tmpl').content, inspectBinary(original).templates.find(s => s.name === 'guidelines.tmpl').content);
    state = (await post('apply', { expectedHash: state.hash, restoreAll: true })).data;
    assert.equal(state.context.mode, 'stock');
    assert.deepEqual(fs.readFileSync(binary), original);
    assert.deepEqual(JSON.parse(fs.readFileSync(configPath)), { contextWindow: '128K', unrelated: 'newer user setting' });
    const altered = Buffer.from(original);
    altered[altered.length - 1] = 1;
    fs.writeFileSync(binary, altered);
    const externallyChanged = (await post('inspect', {})).data;
    assert.equal(externallyChanged.staleBackup, true);
    assert.equal(externallyChanged.canAutoRebaseline, true);
    assert.equal(externallyChanged.backupAvailable, false);
    assert.equal((await post('apply', { expectedHash: externallyChanged.hash, restoreAll: true })).status, 409);
    assert.equal((await post('apply', { expectedHash: externallyChanged.hash, restorePrompts: true })).status, 409);
    assert.deepEqual(fs.readFileSync(binary), altered);
    // Silent auto-rebaseline: applying forward change directly on updated stock binary succeeds and records new baseline
    const autoRebaselined = await post('apply', { expectedHash: externallyChanged.hash, contextMode: '900k' });
    assert.equal(autoRebaselined.status, 200, JSON.stringify(autoRebaselined.data));
    assert.equal(autoRebaselined.data.context.mode, '900k');
    assert.equal(autoRebaselined.data.backupAvailable, true);
    assert.equal(autoRebaselined.data.staleBackup, undefined);
    // Restoring after auto-rebaseline restores the new version's baseline (`altered`), not `original`
    const restoredNew = await post('apply', { expectedHash: autoRebaselined.data.hash, restoreAll: true });
    assert.equal(restoredNew.status, 200, JSON.stringify(restoredNew.data));
    assert.deepEqual(fs.readFileSync(binary), altered);
    // External modification into a non-stock state still refuses to overwrite existing backup
    state = (await post('apply', { expectedHash: restoredNew.data.hash, contextMode: '900k' })).data;
    const nonStockExternal = patchBinary(altered, { contextMode: '512k' }, altered);
    fs.writeFileSync(binary, nonStockExternal);
    const nonStockInspect = (await post('inspect', {})).data;
    assert.equal(nonStockInspect.staleBackup, true);
    assert.equal(nonStockInspect.canAutoRebaseline, false);
    assert.equal((await post('apply', { expectedHash: nonStockInspect.hash, contextMode: '900k' })).status, 409);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await once(child, 'exit');
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
