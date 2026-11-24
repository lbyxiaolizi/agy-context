/**
 * @fileoverview Customization Service for Antigravity kernel binaries (agy-context)
 * Discovers Antigravity language-server / agy binaries (macOS / Windows / Linux +
 * AGY_CONTEXT_BINARY override), inspects them, and applies transactional
 * context-window + system-prompt-template customizations with full original
 * backups kept OUTSIDE the plugin directory.
 *
 * Binary parsing/patching lives in ./binary-patcher.mjs (inspectBinary /
 * patchBinary). inspectBinary scans the whole ~200MB binary; apply re-inspects
 * the actual staged bytes (after signing, before commit) so the reported state
 * always reflects reality — correctness over scan count. This module owns:
 *   - server-side target discovery (clients only ever send targetId strings)
 *   - SHA-256 hashing + expectedHash freshness (optimistic concurrency)
 *   - serialized mutations, staging, macOS ad-hoc codesign, atomic replacement
 *     (restoreAll is never re-signed: exact original bytes & signature), with
 *     re-verification of target + config state right before the staged commit
 *   - original backups + per-path metadata (backup SHA / last applied SHA),
 *     rejecting externally upgraded binaries instead of restoring stale backups
 *   - contextWindow sync into ~/.gemini/config/config.json (+ CLI settings.json),
 *     preserving unrelated fields; malformed configs fail BEFORE any mutation
 *   - binary + config transaction rollback on failure (backups are always kept)
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { inspectBinary, patchBinary } from './binary-patcher.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(__dirname, '..');
const HOME = os.homedir();

/** Context window modes accepted by applyCustomization(). */
export const CONTEXT_MODES = ['stock', '512k', '900k', 'dynamic'];
const CONTEXT_WINDOW_CONFIG_VALUES = { '512k': '512K', '900k': '900K', 'dynamic': '' };
const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/**
 * Error carrying an HTTP status code; thrown for every user-facing failure.
 * 400 bad request · 404 unknown target · 409 stale hash / external change ·
 * 422 unanalyzable binary · 423 locked binary · 500 internal/state corruption.
 */
export class CustomizationError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'CustomizationError';
    this.status = status;
  }
}

/** Per-process random CSRF token required by all customization POST routes. */
let settingsToken = null;
export function getSettingsToken() {
  if (!settingsToken) settingsToken = crypto.randomBytes(24).toString('hex');
  return settingsToken;
}

/** Backup directory (outside the plugin): ~/.gemini/agy-context-backups or AGY_CONTEXT_BACKUP_DIR. */
export function getBackupDir() {
  return process.env.AGY_CONTEXT_BACKUP_DIR
    ? path.resolve(process.env.AGY_CONTEXT_BACKUP_DIR)
    : path.join(HOME, '.gemini', 'agy-context-backups');
}

/**
 * Config paths for contextWindow sync. AGY_CONTEXT_CONFIG_DIR overrides the
 * ~/.gemini/config directory (i.e. the directory CONTAINING config.json) and
 * fully isolates writes to <override>/config.json — the real
 * ~/.gemini/antigravity-cli/settings.json is never touched in that mode.
 */
export function getConfigPaths() {
  // Isolation: when the override is set, ONLY <override>/config.json is synced.
  if (process.env.AGY_CONTEXT_CONFIG_DIR) {
    const configDir = path.resolve(process.env.AGY_CONTEXT_CONFIG_DIR);
    return { configDir, main: path.join(configDir, 'config.json'), cliSettings: null };
  }
  const configDir = path.join(HOME, '.gemini', 'config');
  return {
    configDir,
    main: path.join(configDir, 'config.json'),
    cliSettings: path.join(HOME, '.gemini', 'antigravity-cli', 'settings.json')
  };
}

/** SHA-256 of a Buffer, hex encoded. */
export function computeSha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function pathExists(p) {
  try {
    fs.statSync(p);
    return true;
  } catch {
    return false;
  }
}

function safeUnlink(p) {
  try {
    if (pathExists(p)) fs.unlinkSync(p);
  } catch {}
}

// ============================================================================
// Target discovery (server-side only; clients reference targets by id)
// ============================================================================
let targetCache = null;

/** Clears the memoized discovery cache (tests / env changes). */
export function resetTargetDiscoveryCache() {
  targetCache = null;
}

function resolveSymlinkIfExists(p) {
  try {
    if (fs.lstatSync(p).isSymbolicLink()) return fs.realpathSync(p);
  } catch {}
  return p;
}

function findCommandOnPath(cmd) {
  const whichCmd = process.platform === 'win32' ? 'where.exe' : 'which';
  try {
    const out = execFileSync(whichCmd, [cmd], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000
    });
    for (const line of out.split(/\r?\n/)) {
      const p = line.trim();
      if (p && pathExists(p)) return p;
    }
  } catch {}
  return null;
}

/** Resolves the standalone Windows agy.exe across common install paths and PATH. */
function resolveWindowsStandaloneAgy(localAppData) {
  const candidates = [
    path.join(localAppData, 'agy', 'bin', 'agy.exe'),
    path.join(HOME, '.local', 'bin', 'agy.exe'),
    path.join(HOME, '.gemini', 'antigravity', 'bin', 'agy.exe'),
    findCommandOnPath('agy.exe')
  ].filter(Boolean);
  for (const p of candidates) {
    const resolved = resolveSymlinkIfExists(p);
    if (pathExists(resolved)) return resolved;
  }
  return candidates[0];
}

/**
 * Discovers candidate Antigravity binaries for this platform (memoized).
 * @returns {Array<{id: string, label: string, path: string}>}
 */
export function discoverTargets() {
  if (targetCache) return targetCache;
  const raw = [];
  const hubPath = resolveSymlinkIfExists(
    path.join(HOME, '.gemini', 'bin', process.platform === 'win32' ? 'agy.exe' : 'agy')
  );

  const custom = (process.env.AGY_CONTEXT_BINARY || '').trim();
  if (custom) {
    raw.push({ id: 'custom', label: 'Custom binary (AGY_CONTEXT_BINARY)', path: path.resolve(custom) });
  }

  if (process.platform === 'darwin') {
    const sysDesktop = '/Applications/Antigravity.app/Contents/Resources/bin/language_server';
    const userDesktop = path.join(HOME, 'Applications', 'Antigravity.app', 'Contents', 'Resources', 'bin', 'language_server');
    raw.push({
      id: 'desktop',
      label: 'Antigravity Desktop 内核 (language_server)',
      path: !pathExists(sysDesktop) && pathExists(userDesktop) ? userDesktop : sysDesktop
    });
    const cliCandidates = [
      findCommandOnPath('agy'),
      '/opt/homebrew/bin/agy',
      path.join(HOME, '.local', 'bin', 'agy'),
      path.join(HOME, '.gemini', 'antigravity', 'bin', 'agy'),
      '/usr/local/bin/agy'
    ].filter(Boolean);
    const existingCli = [];
    const seenCli = new Set();
    for (const cand of cliCandidates) {
      const resolved = resolveSymlinkIfExists(cand);
      if (!pathExists(resolved)) continue;
      const key = path.resolve(resolved);
      if (seenCli.has(key)) continue;
      seenCli.add(key);
      existingCli.push(resolved);
    }
    const primaryCli = existingCli[0] || (pathExists('/opt/homebrew/bin') ? '/opt/homebrew/bin/agy' : path.join(HOME, '.local', 'bin', 'agy'));
    raw.push({ id: 'cli', label: 'Antigravity CLI (agy)', path: primaryCli });
    existingCli.slice(1).forEach((p, idx) => {
      raw.push({ id: `cli_alt_${idx + 1}`, label: `Antigravity CLI (${p})`, path: p });
    });
    raw.push({ id: 'ide_hub', label: 'Antigravity IDE 2.6+ 后端 (~/.gemini/bin/agy)', path: hubPath });
  } else if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || path.join(HOME, 'AppData', 'Local');
    raw.push({
      id: 'desktop',
      label: 'Antigravity Desktop 内核 (language_server.exe)',
      path: path.join(localAppData, 'Programs', 'antigravity', 'resources', 'bin', 'language_server.exe')
    });
    const cliPath = resolveWindowsStandaloneAgy(localAppData);
    raw.push({ id: 'cli', label: 'Antigravity 独立版 CLI (agy.exe)', path: cliPath });
    const ideLegacyPath = path.join(
      localAppData, 'Programs', 'Antigravity IDE', 'resources', 'app', 'extensions',
      'antigravity', 'bin', 'language_server_windows_x64.exe'
    );
    if (pathExists(ideLegacyPath) || !pathExists(hubPath)) {
      raw.push({
        id: 'ide',
        label: 'Antigravity IDE 扩展内核 (language_server_windows_x64.exe)',
        path: ideLegacyPath
      });
    }
    if (pathExists(hubPath) && path.resolve(hubPath).toLowerCase() !== path.resolve(cliPath).toLowerCase()) {
      raw.push({ id: 'ide_hub', label: 'Antigravity IDE 2.6+ 后端 (~/.gemini/bin/agy.exe)', path: hubPath });
    }
  } else {
    raw.push({
      id: 'desktop',
      label: 'Antigravity Desktop 内核 (/opt/antigravity)',
      path: '/opt/antigravity/resources/bin/language_server'
    });
    raw.push({
      id: 'desktop_alt',
      label: 'Antigravity Desktop 内核 (/opt/Antigravity)',
      path: '/opt/Antigravity/resources/bin/language_server'
    });
    const pathAgy = findCommandOnPath('agy');
    if (pathAgy) {
      raw.push({ id: 'cli_path', label: `Antigravity CLI (${pathAgy})`, path: resolveSymlinkIfExists(pathAgy) });
    }
    raw.push({ id: 'cli', label: 'Antigravity CLI (/usr/bin/agy)', path: resolveSymlinkIfExists('/usr/bin/agy') });
    raw.push({ id: 'cli_local', label: 'Antigravity CLI (/usr/local/bin/agy)', path: resolveSymlinkIfExists('/usr/local/bin/agy') });
    raw.push({ id: 'cli_user', label: 'Antigravity CLI (~/.local/bin/agy)', path: resolveSymlinkIfExists(path.join(HOME, '.local', 'bin', 'agy')) });
    raw.push({ id: 'cli_agy', label: 'Antigravity CLI (~/.gemini/antigravity/bin/agy)', path: resolveSymlinkIfExists(path.join(HOME, '.gemini', 'antigravity', 'bin', 'agy')) });
    raw.push({ id: 'ide_hub', label: 'Antigravity IDE 2.6+ 后端 (~/.gemini/bin/agy)', path: hubPath });
  }

  const seen = new Set();
  targetCache = raw.filter((t) => {
    const resolved = path.resolve(t.path);
    const k = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return targetCache;
}

/** Cheap target list for the UI (no binary reads, existsSync only). */
export function listTargets() {
  return discoverTargets().map((t) => ({ id: t.id, label: t.label, path: t.path, exists: pathExists(t.path) }));
}

/** @returns {{id: string, label: string, path: string}|undefined} */
export function getTargetById(targetId) {
  return discoverTargets().find((t) => t.id === targetId);
}

// ============================================================================
// Backup metadata ({backupDir}/metadata.json)
// ============================================================================
function targetKey(target) {
  const pathHash = crypto.createHash('sha256').update(target.path).digest('hex').slice(0, 16);
  return `${target.id}--${pathHash}`;
}

function ensureBackupDir() {
  const dir = getBackupDir();
  if (dir === PLUGIN_ROOT || dir.startsWith(PLUGIN_ROOT + path.sep)) {
    throw new CustomizationError(500, `Backup directory must live outside the plugin directory: ${dir}`);
  }
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function readMetadata() {
  const metaPath = path.join(getBackupDir(), 'metadata.json');
  if (!pathExists(metaPath)) return { version: 1, targets: {}, configs: {} };
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  } catch (err) {
    throw new CustomizationError(500, `Customization metadata is corrupt: ${metaPath} (${err.message})`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || parsed.version !== 1) {
    throw new CustomizationError(500, `Customization metadata has an unsupported structure: ${metaPath}`);
  }
  if (!parsed.targets || typeof parsed.targets !== 'object') parsed.targets = {};
  if (!parsed.configs || typeof parsed.configs !== 'object') parsed.configs = {};
  return parsed;
}

function writeMetadata(meta) {
  const dir = ensureBackupDir();
  const tmp = path.join(dir, `.metadata-${process.pid}-${crypto.randomBytes(4).toString('hex')}.tmp`);
  try {
    fs.writeFileSync(tmp, JSON.stringify(meta, null, 2) + '\n', 'utf8');
    fs.renameSync(tmp, path.join(dir, 'metadata.json'));
  } catch (err) {
    safeUnlink(tmp);
    throw new CustomizationError(500, `Failed to persist customization metadata: ${err.message}`);
  }
}

// ============================================================================
// Inspection (exactly one inspectBinary scan per call)
// ============================================================================
function inspectBuffer(target, buffer) {
  const info = inspectBinary(buffer);
  const out = {
    targetId: target.id,
    path: target.path,
    hash: computeSha256(buffer),
    format: info.format,
    arch: info.arch,
    context: info.context,
    templates: info.templates
  };
  if (info.warning) out.warning = info.warning;
  return out;
}

/**
 * Full read-only inspection of one target: hash, context gates, templates,
 * backup availability and warnings (external change / core scanner issues).
 * @param {string} targetId
 */
export function inspectTarget(targetId) {
  if (typeof targetId !== 'string' || !targetId) {
    throw new CustomizationError(400, 'targetId is required');
  }
  const target = getTargetById(targetId);
  if (!target) throw new CustomizationError(404, `Unknown customization target: ${targetId}`);
  if (!pathExists(target.path)) throw new CustomizationError(404, `Target binary not found: ${target.path}`);

  const buffer = fs.readFileSync(target.path);
  let base;
  try {
    base = inspectBuffer(target, buffer);
  } catch (err) {
    throw new CustomizationError(422, `Binary analysis failed for ${target.path}: ${err.message}`);
  }
  const { warning: coreWarning, ...rest } = base;

  const meta = readMetadata();
  const entry = meta.targets[targetKey(target)];
  let backupAvailable = false;
  let backupPath;
  let serviceWarning;
  let staleBackup = false;
  const canAutoRebaseline = !rest.context.supported || rest.context.mode === 'stock';
  if (entry) {
    const candidate = path.join(getBackupDir(), entry.backupFile);
    const matchesTargetPath = entry.path === target.path;
    const backupExists = pathExists(candidate);
    const backupIntact = backupExists && computeSha256(fs.readFileSync(candidate)) === entry.backupSha;
    const binaryChanged = Boolean(entry.lastAppliedSha && entry.lastAppliedSha !== rest.hash);
    if (!matchesTargetPath || !backupExists || !backupIntact || binaryChanged) {
      staleBackup = true;
      if (backupIntact) backupPath = candidate;
      if (canAutoRebaseline) {
        serviceWarning = '检测到客户端已更新，当前文件为新版原厂状态；下次应用修改时将自动为新版创建备份（旧版备份不可用于恢复）。';
      } else {
        serviceWarning = '检测到目标二进制在外部被修改且非原版状态，为避免覆盖原有备份已阻止修改；请先恢复官方原版程序。';
      }
    } else {
      backupAvailable = true;
      backupPath = candidate;
    }
  }
  const warning = [coreWarning, serviceWarning].filter(Boolean).join(' | ') || undefined;
  return {
    ...rest,
    backupAvailable,
    ...(staleBackup ? { staleBackup: true, canAutoRebaseline } : {}),
    ...(backupPath ? { backupPath } : {}),
    ...(warning ? { warning } : {})
  };
}

// ============================================================================
// Apply / restore (serialized, transactional)
// ============================================================================
let applyChain = Promise.resolve();

function withApplyLock(fn) {
  const result = applyChain.then(fn, fn);
  applyChain = result.then(
    () => {},
    () => {}
  );
  return result;
}

function validateApplyRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new CustomizationError(400, 'Request body must be a JSON object');
  }
  if (typeof request.targetId !== 'string' || !request.targetId) {
    throw new CustomizationError(400, 'targetId is required');
  }
  if (typeof request.expectedHash !== 'string' || !/^[0-9a-f]{64}$/i.test(request.expectedHash)) {
    throw new CustomizationError(400, 'expectedHash must be a 64-character SHA-256 hex string');
  }
  const opts = {};
  if (request.contextMode !== undefined && request.contextMode !== null) {
    if (!CONTEXT_MODES.includes(request.contextMode)) {
      throw new CustomizationError(400, `Invalid contextMode: ${request.contextMode} (expected ${CONTEXT_MODES.join(' | ')})`);
    }
    opts.contextMode = request.contextMode;
  }
  if (request.templates !== undefined && request.templates !== null) {
    if (typeof request.templates !== 'object' || Array.isArray(request.templates)) {
      throw new CustomizationError(400, 'templates must be an object of { [templateName]: content }');
    }
    const names = Object.keys(request.templates);
    if (!names.length) throw new CustomizationError(400, 'templates must not be empty');
    const clean = {};
    for (const name of names) {
      const content = request.templates[name];
      if (typeof content !== 'string') throw new CustomizationError(400, `Template "${name}" content must be a string`);
      // Size/NUL/Go-template-syntax limits are enforced against the real slot
      // capacity by the patch core; the HTTP body bound caps the rest.
      clean[name] = content;
    }
    opts.templates = clean;
  }
  if (request.restorePrompts !== undefined && request.restorePrompts !== null) {
    if (typeof request.restorePrompts !== 'boolean') throw new CustomizationError(400, 'restorePrompts must be a boolean');
    if (request.restorePrompts) opts.restorePrompts = true;
  }
  if (request.restoreAll !== undefined && request.restoreAll !== null) {
    if (typeof request.restoreAll !== 'boolean') throw new CustomizationError(400, 'restoreAll must be a boolean');
    if (request.restoreAll) opts.restoreAll = true;
  }
  if (request.rebaseline !== undefined && request.rebaseline !== null) {
    if (typeof request.rebaseline !== 'boolean') throw new CustomizationError(400, 'rebaseline must be a boolean');
    if (request.rebaseline) opts.rebaseline = true;
  }
  if (!opts.contextMode && !opts.templates && !opts.restorePrompts && !opts.restoreAll && !opts.rebaseline) {
    throw new CustomizationError(400, 'Nothing to apply: provide contextMode, templates, restorePrompts, restoreAll, or rebaseline');
  }
  if (opts.restoreAll && (opts.contextMode || opts.templates || opts.restorePrompts || opts.rebaseline)) {
    throw new CustomizationError(400, 'restoreAll cannot be combined with other options');
  }
  if (opts.rebaseline && (opts.contextMode || opts.templates || opts.restorePrompts || opts.restoreAll)) {
    throw new CustomizationError(400, 'rebaseline cannot be combined with other options');
  }
  return opts;
}

function extractCodesignIdentifier(referencePath) {
  const res = spawnSync('codesign', ['-d', '--verbose=2', referencePath], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10000
  });
  const combined = `${res.stderr || ''}\n${res.stdout || ''}`;
  const m = combined.match(/^Identifier=(.+)$/m);
  return (m && m[1].trim()) || path.basename(referencePath);
}

function extractSafeEntitlementsPlist(referencePath) {
  const res = spawnSync('codesign', ['-d', '--entitlements', ':-', referencePath], {
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10000
  });
  if (res.status !== 0 || !res.stdout) return null;
  if (!res.stdout.toString('utf8').trimStart().startsWith('<?xml')) return null;

  const jsonRes = spawnSync('plutil', ['-convert', 'json', '-o', '-', '-'], {
    input: res.stdout,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 5000
  });
  if (jsonRes.status !== 0 || !jsonRes.stdout) return null;

  let parsed;
  try {
    parsed = JSON.parse(jsonRes.stdout);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

  const filtered = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (
      !k.startsWith('com.apple.developer.') &&
      k !== 'keychain-access-groups' &&
      k !== 'com.apple.application-identifier'
    ) {
      filtered[k] = v;
    }
  }
  if (Object.keys(filtered).length === 0) return null;

  const tmpPath = path.join(os.tmpdir(), `agy-ent-${process.pid}-${crypto.randomBytes(4).toString('hex')}.plist`);
  const xmlOut = spawnSync('plutil', ['-convert', 'xml1', '-o', tmpPath, '-'], {
    input: JSON.stringify(filtered),
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 5000
  });
  if (xmlOut.status !== 0) {
    safeUnlink(tmpPath);
    return null;
  }
  return tmpPath;
}

function codesignStaged(stagedPath, referencePath) {
  const identifier = extractCodesignIdentifier(referencePath);
  const entPath = extractSafeEntitlementsPlist(referencePath);
  try {
    const args = ['--force', '--sign', '-', '--options', 'runtime', '--identifier', identifier];
    if (entPath) args.push('--entitlements', entPath);
    args.push(stagedPath);
    execFileSync('codesign', args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60000
    });
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString().trim() : '';
    throw new CustomizationError(
      500,
      `macOS ad-hoc codesign failed on staged binary ${stagedPath}${stderr ? `: ${stderr}` : ` (${err.message})`}`
    );
  } finally {
    if (entPath) safeUnlink(entPath);
  }
}

function translateStageError(err, targetPath) {
  if (['EBUSY', 'EPERM', 'EACCES', 'ETXTBSY'].includes(err.code)) {
    const hint = process.platform === 'win32'
      ? 'the file is locked by a running Antigravity process. Close Antigravity (IDE / Desktop / CLI) and retry'
      : 'the file is locked or not writable. Stop the running Antigravity process and check permissions, then retry';
    return new CustomizationError(
      423,
      `Cannot replace ${targetPath}: ${hint}. No host process was terminated (${err.message}).`
    );
  }
  return new CustomizationError(500, `Failed to stage/replace ${targetPath}: ${err.message}`);
}

/** Writes buffer to a staged sibling file (+optional ad-hoc codesign) without touching the target yet. */
function stageBinary(targetPath, buffer, mode, adhocSign) {
  const dir = path.dirname(targetPath);
  const stagedPath = path.join(
    dir,
    `.${path.basename(targetPath)}.agy-stage-${process.pid}-${crypto.randomBytes(4).toString('hex')}`
  );
  try {
    fs.writeFileSync(stagedPath, buffer);
    fs.chmodSync(stagedPath, mode & 0o777);
    if (adhocSign) codesignStaged(stagedPath, targetPath);
    return { stagedPath, finalBuffer: fs.readFileSync(stagedPath) };
  } catch (err) {
    safeUnlink(stagedPath);
    throw err instanceof CustomizationError ? err : translateStageError(err, targetPath);
  }
}

function cleanupStaleOldFiles(dir, base) {
  const prefix = `.${base}.agy-old-`;
  try {
    for (const name of fs.readdirSync(dir)) {
      if (name.startsWith(prefix)) safeUnlink(path.join(dir, name));
    }
  } catch {}
}

/** Atomically moves a staged file over the target (with Windows running-binary rename-away fallback). */
function commitStaged(staged, targetPath) {
  try {
    fs.renameSync(staged.stagedPath, targetPath);
  } catch (err) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(err.code)) {
      const dir = path.dirname(targetPath);
      const base = path.basename(targetPath);
      cleanupStaleOldFiles(dir, base);
      const oldPath = path.join(dir, `.${base}.agy-old-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
      try {
        fs.renameSync(targetPath, oldPath);
        try {
          fs.renameSync(staged.stagedPath, targetPath);
        } catch (innerErr) {
          try { fs.renameSync(oldPath, targetPath); } catch {}
          throw innerErr;
        }
        safeUnlink(oldPath);
        return;
      } catch (winErr) {
        safeUnlink(staged.stagedPath);
        throw translateStageError(winErr, targetPath);
      }
    }
    safeUnlink(staged.stagedPath);
    throw translateStageError(err, targetPath);
  }
}

/**
 * Pre-validates config files BEFORE any mutation: malformed JSON anywhere → hard fail.
 * Builds the write plan (set value / restore original / skip files we never touched).
 */
function prepareContextWindowConfigs(opts, meta) {
  const { main, cliSettings } = getConfigPaths();
  const restoring = Boolean(opts.restoreAll) || opts.contextMode === 'stock';
  const candidates = [
    { file: main, allowCreate: true },
    ...(cliSettings ? [{ file: cliSettings, allowCreate: false }] : [])
  ];
  const entries = [];
  for (const cand of candidates) {
    const fileExisted = pathExists(cand.file);
    if (!fileExisted) {
      if (!cand.allowCreate || !pathExists(path.dirname(cand.file))) continue;
    }
    let obj = {};
    let raw = null;
    if (fileExisted) {
      try {
        raw = fs.readFileSync(cand.file, 'utf8');
      } catch (err) {
        throw new CustomizationError(400, `Cannot read config file ${cand.file}: ${err.message}`);
      }
      try {
        obj = JSON.parse(raw);
      } catch (err) {
        throw new CustomizationError(
          400,
          `Config file is malformed JSON — refusing to modify anything: ${cand.file} (${err.message})`
        );
      }
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
        throw new CustomizationError(400, `Config file must contain a JSON object: ${cand.file}`);
      }
    }
    if (!restoring) {
      entries.push({
        file: cand.file,
        obj,
        raw: fileExisted ? raw : null,
        action: 'set',
        value: CONTEXT_WINDOW_CONFIG_VALUES[opts.contextMode]
      });
    } else {
      const recorded = meta.configs[cand.file];
      if (!recorded) continue;
      entries.push({ file: cand.file, obj, raw: fileExisted ? raw : null, action: 'restore', recorded });
    }
  }
  return { restoring, entries };
}

/** Applies the config plan; snapshots every touched file into the transaction for rollback. */
function applyContextWindowConfigs(plan, meta, txn) {
  for (const entry of plan.entries) {
    // entry.raw was verified unchanged right before the binary commit.
    txn.configSnapshots.push({ file: entry.file, raw: entry.raw });
    if (entry.action === 'set') {
      if (!meta.configs[entry.file]) {
        meta.configs[entry.file] = {
          hasOriginal: hasOwn(entry.obj, 'contextWindow'),
          originalContextWindow: hasOwn(entry.obj, 'contextWindow') ? entry.obj.contextWindow : null
        };
      }
      entry.obj.contextWindow = entry.value;
    } else {
      if (entry.recorded.hasOriginal) entry.obj.contextWindow = entry.recorded.originalContextWindow;
      else delete entry.obj.contextWindow;
      delete meta.configs[entry.file];
    }
    fs.mkdirSync(path.dirname(entry.file), { recursive: true });
    fs.writeFileSync(entry.file, JSON.stringify(entry.obj, null, 2) + '\n', 'utf8');
  }
}

function rollbackTransaction(targetPath, previousBuffer, mode, txn) {
  const problems = [];
  for (let i = txn.configSnapshots.length - 1; i >= 0; i--) {
    const snap = txn.configSnapshots[i];
    try {
      if (snap.raw === null) safeUnlink(snap.file);
      else fs.writeFileSync(snap.file, snap.raw, 'utf8');
    } catch (err) {
      problems.push(`config rollback failed for ${snap.file}: ${err.message}`);
    }
  }
  if (txn.binaryReplaced) {
    try {
      // previousBuffer holds the exact previous on-disk bytes (signature embedded) → no re-sign.
      const staged = stageBinary(targetPath, previousBuffer, mode, false);
      commitStaged(staged, targetPath);
    } catch (err) {
      problems.push(`binary rollback failed: ${err.message}`);
    }
  }
  return problems;
}

function buildApplyMessage(opts) {
  const parts = [];
  if (opts.restoreAll) {
    parts.push('restored the original binary (exact bytes and signature)');
    parts.push('reverted contextWindow settings changed by this plugin');
  } else {
    if (opts.contextMode) {
      parts.push(
        opts.contextMode === 'stock'
          ? 'context window restored to stock limits'
          : opts.contextMode === 'dynamic'
            ? 'context window unlocked to DYNAMIC (full model budget)'
            : `context window unlocked to ${opts.contextMode.toUpperCase()}`
      );
    }
    if (opts.templates) parts.push(`updated ${Object.keys(opts.templates).length} prompt template(s)`);
    if (opts.restorePrompts) parts.push('restored stock prompt templates');
  }
  return `Done: ${parts.join('; ')}. Restart Antigravity to take effect.`;
}

async function applyLocked(request) {
  const opts = validateApplyRequest(request);

  const target = getTargetById(request.targetId);
  if (!target) throw new CustomizationError(404, `Unknown customization target: ${request.targetId}`);
  if (!pathExists(target.path)) throw new CustomizationError(404, `Target binary not found: ${target.path}`);

  const meta = readMetadata();
  const key = targetKey(target);
  const currentBuffer = fs.readFileSync(target.path);
  const currentSha = computeSha256(currentBuffer);

  // Freshness: the hash the client inspected must still match the on-disk binary.
  if (currentSha !== request.expectedHash.toLowerCase()) {
    throw new CustomizationError(
      409,
      `Binary changed since inspection (expected ${String(request.expectedHash).slice(0, 12)}…, found ${currentSha.slice(0, 12)}…). Re-inspect the target and retry.`
    );
  }

  // External version change (e.g. Antigravity update): allow explicit re-baseline if stock,
  // otherwise refuse instead of patching/restoring a stale backup.
  let entry = meta.targets[key];
  if (opts.rebaseline) {
    let currentInfo;
    try {
      currentInfo = inspectBinary(currentBuffer);
    } catch (err) {
      throw new CustomizationError(422, `Binary analysis failed for ${target.path}: ${err.message}`);
    }
    if (currentInfo.context && currentInfo.context.supported && currentInfo.context.mode !== 'stock') {
      throw new CustomizationError(400, '当前磁盘文件并非原版 (stock) 状态，无法重置为原始备份基线');
    }
    if (entry) {
      safeUnlink(path.join(getBackupDir(), entry.backupFile));
      delete meta.targets[key];
      writeMetadata(meta);
    }
    return {
      ...inspectTarget(target.id),
      message: '已清理旧版备份记录，当前原版文件将在下次修改时自动作为新基线备份。',
      restartRequired: false
    };
  }

  let entryStale = false;
  if (entry) {
    const candPath = path.join(getBackupDir(), entry.backupFile);
    if (
      entry.path !== target.path ||
      (entry.lastAppliedSha && entry.lastAppliedSha !== currentSha) ||
      !pathExists(candPath) ||
      computeSha256(fs.readFileSync(candPath)) !== entry.backupSha
    ) {
      entryStale = true;
    }
  }

  const restoreAll = Boolean(opts.restoreAll);
  if (entryStale && (restoreAll || opts.restorePrompts)) {
    throw new CustomizationError(
      409,
      'Binary was modified externally since the last customization (likely an Antigravity update) — refusing to restore a stale backup.'
    );
  }

  // 1) Core validation against the CURRENT binary.
  let currentInfo;
  if (!restoreAll) {
    try {
      currentInfo = inspectBinary(currentBuffer);
    } catch (err) {
      throw new CustomizationError(422, `Binary analysis failed for ${target.path}: ${err.message}`);
    }

    // Fail closed on unsupported requests.
    if (opts.contextMode && !(currentInfo.context && currentInfo.context.supported)) {
      throw new CustomizationError(
        400,
        `Context customization is not supported for this binary: ${(currentInfo.context && currentInfo.context.reason) || 'no supported context gates found'}`
      );
    }
    if (opts.templates) {
      for (const [name, content] of Object.entries(opts.templates)) {
        const slot = (currentInfo.templates || []).find((t) => t.name === name);
        if (!slot) throw new CustomizationError(400, `Unknown template: ${name}`);
        if (slot.editable === false) throw new CustomizationError(400, `Template is not editable: ${name}`);
        const size = Buffer.byteLength(content, 'utf8');
        if (size > slot.capacity) {
          throw new CustomizationError(400, `Template "${name}" content (${size}B) exceeds slot capacity (${slot.capacity}B)`);
        }
      }
    }

  }

  // 2) Config pre-flight BEFORE any mutation: malformed JSON anywhere → hard fail.
  const wantsConfigSync = Boolean(opts.contextMode) || restoreAll;
  const configPlan = wantsConfigSync ? prepareContextWindowConfigs(opts, meta) : null;

  // 3) Full original backup (first mutation or silent auto-rebaseline after official
  //    stock update, AFTER all validation passed), kept outside the plugin directory.
  const backupDir = ensureBackupDir();
  if (entryStale) {
    const canAutoRebaseline = !currentInfo.context || !currentInfo.context.supported || currentInfo.context.mode === 'stock';
    if (!canAutoRebaseline) {
      throw new CustomizationError(
        409,
        'Binary was modified externally and is not in stock state — refusing to overwrite the existing backup.'
      );
    }
    safeUnlink(path.join(backupDir, entry.backupFile));
    delete meta.targets[key];
    entry = null;
  }

  let backupBuffer;
  if (entry) {
    const backupPath = path.join(backupDir, entry.backupFile);
    if (!pathExists(backupPath)) throw new CustomizationError(500, `Backup file missing: ${backupPath}`);
    backupBuffer = fs.readFileSync(backupPath);
    if (computeSha256(backupBuffer) !== entry.backupSha) {
      throw new CustomizationError(500, `Backup integrity check failed: ${backupPath}`);
    }
  } else {
    const backupFile = `${key}.bin`;
    const backupPath = path.join(backupDir, backupFile);
    try {
      fs.writeFileSync(backupPath, currentBuffer, { flag: 'wx', mode: 0o600 });
    } catch (err) {
      if (err.code !== 'EEXIST') throw new CustomizationError(500, `Failed to write backup: ${err.message}`);
      // Orphan from an earlier crashed attempt: adopt only the same baseline.
      const existing = fs.readFileSync(backupPath);
      if (computeSha256(existing) !== currentSha) {
        throw new CustomizationError(500, `Conflicting backup already exists: ${backupPath}`);
      }
    }
    backupBuffer = currentBuffer;
    entry = {
      path: target.path,
      backupFile,
      backupSha: currentSha,
      backupSize: currentBuffer.length,
      lastAppliedSha: currentSha,
      updatedAt: new Date().toISOString()
    };
    meta.targets[key] = entry;
    writeMetadata(meta);
  }

  // 4) Build the new binary (restoreAll = exact original bytes; otherwise core patch).
  let newBuffer;
  if (restoreAll) {
    newBuffer = backupBuffer; // exact original bytes & signature — never re-signed
  } else {
    try {
      newBuffer = patchBinary(currentBuffer, opts, backupBuffer);
    } catch (err) {
      throw new CustomizationError(400, `Patch rejected, binary left untouched: ${err.message}`);
    }
    if (!Buffer.isBuffer(newBuffer)) {
      throw new CustomizationError(500, 'Patch core returned invalid output; binary left untouched');
    }
    if (newBuffer.length !== currentBuffer.length) {
      throw new CustomizationError(500, 'Patch changed the binary size; refusing to write (binary left untouched)');
    }
  }

  const adhocSign =
    !restoreAll &&
    process.platform === 'darwin' &&
    String((currentInfo && currentInfo.format) || '').toLowerCase().includes('mach');

  const mode = fs.statSync(target.path).mode;
  const txn = { binaryReplaced: false, configSnapshots: [] };
  try {
    const staged = stageBinary(target.path, newBuffer, mode, adhocSign);

    // 5) Verify the ACTUAL staged bytes (after signing): the response reports what
    //    is really on disk, e.g. stock content after restorePrompts.
    let finalInspection;
    try {
      finalInspection = inspectBuffer(target, staged.finalBuffer);
    } catch (err) {
      safeUnlink(staged.stagedPath);
      throw new CustomizationError(500, `Post-patch verification failed; binary left untouched: ${err.message}`);
    }

    // 6) Target and config files must not have changed while we were staging
    //    (codesign can take seconds on a ~200MB binary).
    if (computeSha256(fs.readFileSync(target.path)) !== currentSha) {
      safeUnlink(staged.stagedPath);
      throw new CustomizationError(409, 'Binary changed externally while the patch was being prepared; nothing was written.');
    }
    if (configPlan) {
      for (const planned of configPlan.entries) {
        const now = pathExists(planned.file) ? fs.readFileSync(planned.file, 'utf8') : null;
        if (now !== planned.raw) {
          safeUnlink(staged.stagedPath);
          throw new CustomizationError(409, `Config file changed while the patch was being prepared: ${planned.file}`);
        }
      }
    }

    commitStaged(staged, target.path);
    txn.binaryReplaced = true;

    if (configPlan) applyContextWindowConfigs(configPlan, meta, txn);

    entry.lastAppliedSha = finalInspection.hash;
    entry.updatedAt = new Date().toISOString();
    writeMetadata(meta);
    return {
      ...finalInspection,
      backupAvailable: true,
      backupPath: path.join(backupDir, entry.backupFile),
      message: buildApplyMessage(opts),
      restartRequired: true
    };
  } catch (err) {
    const problems = rollbackTransaction(target.path, currentBuffer, mode, txn);
    const failure = err instanceof CustomizationError ? err : new CustomizationError(500, err.message || String(err));
    if (problems.length) {
      failure.message += ` | Rollback problem (original backup kept in ${backupDir}): ${problems.join('; ')}`;
    }
    throw failure;
  }
}

/**
 * Serialized, transactional apply / restore on one target.
 * @param {{targetId: string, expectedHash: string, contextMode?: string,
 *          templates?: Object<string, string>, restorePrompts?: boolean,
 *          restoreAll?: boolean}} request
 * @returns {Promise<object>} inspection + { message, restartRequired: true }
 */
export function applyCustomization(request) {
  return withApplyLock(() => applyLocked(request));
}
