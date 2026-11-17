/**
 * @fileoverview Sidecar Web Server for Antigravity Context Inspector
 * Runs in the background continuously when Antigravity starts, providing
 * live real-time context analytics embedded in the Antigravity Auxiliary Pane.
 */

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import os from 'node:os';
import { analyzeTranscript, analyzeGlobalTokens, resolveTranscriptPath } from '../../scripts/context-analyzer.mjs';
import { checkForUpdates, applyOneClickUpdate, getLocalVersion } from '../../scripts/updater.mjs';
import { listTargets, inspectTarget, applyCustomization, getSettingsToken, CustomizationError } from '../../scripts/customization-service.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.ANTIGRAVITY_SIDECAR_WEB_PORT || '5173', 10);
const TOKEN = process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN || '';
const HOST = '127.0.0.1';

// Read preload.js if available from sidecar_sdk, or use fallback
let preloadJs = '';
const sdkPreload = join(os.homedir(), '.gemini', 'antigravity', 'lib', 'node_modules', 'sidecar_sdk', 'preload.js');
if (existsSync(sdkPreload)) {
  preloadJs = readFileSync(sdkPreload, 'utf8');
} else {
  preloadJs = `
    window.sidecar = {
      conversationId: new URLSearchParams(window.location.search).get('conversationId') || '',
      fetch: (url, opts = {}) => fetch(url, opts)
    };
  `;
}

// Ensure preload.js adopts official Google Sans Flex & Google Sans Code typography
preloadJs = preloadJs.replace(
  /document\.body\.style\.fontFamily\s*=\s*['"][^'"]+['"]/g,
  `document.body.style.fontFamily = '"Google Sans Flex", "Google Sans", system-ui, sans-serif'`
);

function validateToken(req, url) {
  if (url.pathname === '/preload.js') return true;
  if (!TOKEN) return true;
  const provided = req.headers['x-sidecar-token'] || url.searchParams.get('token');
  return provided === TOKEN;
}

// ---------------------------------------------------------------------------
// Customization API helpers (CSRF / DNS-rebinding / bounded JSON bodies)
// ---------------------------------------------------------------------------
const MAX_CUSTOMIZATION_BODY_BYTES = 2 * 1024 * 1024;

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(payload));
}

/**
 * Validates a loopback Host header (DNS-rebinding guard).
 * When running standalone without a UI token, only our exact listening port is
 * accepted. When ANTIGRAVITY_SIDECAR_UI_TOKEN is active, Antigravity fronts the
 * sidecar with a local HTTP gateway on a sibling loopback port and preserves its
 * own `localhost:<gatewayPort>` Host header.
 */
function parseLoopbackHostHeader(rawValue) {
  if (!rawValue || typeof rawValue !== 'string') return null;
  const trimmed = rawValue.trim().toLowerCase();
  if (!trimmed || trimmed.includes('/') || trimmed.includes('@') || trimmed.includes('?') || trimmed.includes('#')) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(`http://${trimmed}`);
  } catch {
    return null;
  }
  const hostname = parsed.hostname.toLowerCase();
  if (hostname !== HOST && hostname !== 'localhost' && hostname !== '[::1]' && hostname !== '::1') {
    return null;
  }
  const effectivePort = parsed.port || '80';
  if (!TOKEN && effectivePort !== String(PORT)) {
    return null;
  }
  return {
    host: parsed.host.toLowerCase(),
    hostname,
    port: effectivePort
  };
}

/** Origin/Referer, when a browser sends one, must be a loopback http origin matching our Host. */
function isAllowedBrowserOrigin(rawValue, parsedHost) {
  if (!rawValue) return true;
  let origin;
  try {
    origin = new URL(rawValue);
  } catch {
    return false;
  }
  if (origin.protocol !== 'http:') return false;
  return origin.host.toLowerCase() === parsedHost.host;
}

/**
 * Enforces: POST-only handled by caller, valid loopback Host, no cross-site
 * browser Origin/Referer, per-process X-Context-Settings-Token, and
 * application/json content type. Native clients without Origin are allowed.
 */
function validateContextSettingsPost(req, res) {
  const parsedHost = parseLoopbackHostHeader(req.headers.host);
  if (!parsedHost) {
    sendJson(res, 403, { error: 'Rejected: Host header is not an allowed loopback address' });
    return false;
  }
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  if ((origin && !isAllowedBrowserOrigin(origin, parsedHost)) || (!origin && referer && !isAllowedBrowserOrigin(referer, parsedHost))) {
    sendJson(res, 403, { error: 'Rejected: cross-origin browser requests are not allowed' });
    return false;
  }
  const token = req.headers['x-context-settings-token'];
  if (!token || token !== getSettingsToken()) {
    sendJson(res, 403, { error: 'Rejected: missing or invalid X-Context-Settings-Token header' });
    return false;
  }
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (!contentType.startsWith('application/json')) {
    sendJson(res, 415, { error: 'Content-Type must be application/json' });
    return false;
  }
  return true;
}

/** Reads and parses a bounded JSON request body (413 over limit, 400 on bad JSON). */
function readJsonBody(req, limitBytes = MAX_CUSTOMIZATION_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let overLimit = false;
    req.on('data', (chunk) => {
      if (overLimit) return;
      total += chunk.length;
      if (total > limitBytes) {
        overLimit = true;
        chunks.length = 0;
        req.removeAllListeners('data');
        req.resume();
        reject(new CustomizationError(413, `Request body exceeds the ${limitBytes} byte limit`));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (overLimit) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      let parsed;
      try {
        parsed = raw ? JSON.parse(raw) : {};
      } catch (err) {
        reject(new CustomizationError(400, `Invalid JSON body: ${err.message}`));
        return;
      }
      resolve(parsed);
    });
    req.on('error', (err) => {
      if (!overLimit) reject(new CustomizationError(400, `Request body read error: ${err.message}`));
    });
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);

  // Token validation
  if (!validateToken(req, url)) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized sidecar request' }));
    return;
  }

  // Preload script route
  if (url.pathname === '/preload.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
    res.end(preloadJs);
    return;
  }

  // API: Get Global Tokens (Aggregated local metrics)
  if (url.pathname === '/api/global-tokens') {
    try {
      const range = url.searchParams.get('range') || '3d';
      const data = analyzeGlobalTokens(range);
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(JSON.stringify(data));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // API: Get Single Conversation Context Metrics
  if (url.pathname === '/api/context') {
    try {
      let convId = url.searchParams.get('conversationId') || process.env.ANTIGRAVITY_CONVERSATION_ID;
      const transcriptPath = resolveTranscriptPath(convId);
      if (!transcriptPath) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No active conversation transcript found' }));
        return;
      }
      if (!convId) {
        const m = transcriptPath.match(/brain[/\\]([^/\\]+)/);
        if (m) convId = m[1];
      }
      const data = await analyzeTranscript(transcriptPath, { conversationId: convId });
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(JSON.stringify(data));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // API: Check for Updates
  if (url.pathname === '/api/update/check') {
    try {
      const data = await checkForUpdates();
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(JSON.stringify(data));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // API: One-Click Apply Update
  if (url.pathname === '/api/update/apply' && req.method === 'POST') {
    try {
      const result = await applyOneClickUpdate();
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // API: List customization targets (cheap: existsSync only, no binary reads)
  if (url.pathname === '/api/customization') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'Content-Type': 'application/json; charset=utf-8', Allow: 'GET' });
      res.end(JSON.stringify({ error: 'Method not allowed; use GET' }));
      return;
    }
    const parsedHost = parseLoopbackHostHeader(req.headers.host);
    if (!parsedHost) {
      sendJson(res, 403, { error: 'Rejected: Host header is not an allowed loopback address' });
      return;
    }
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    if ((origin && !isAllowedBrowserOrigin(origin, parsedHost)) || (!origin && referer && !isAllowedBrowserOrigin(referer, parsedHost))) {
      sendJson(res, 403, { error: 'Rejected: cross-origin browser requests are not allowed' });
      return;
    }
    try {
      sendJson(res, 200, { targets: listTargets(), token: getSettingsToken() });
    } catch (err) {
      sendJson(res, 500, { error: err.message || 'Failed to list customization targets' });
    }
    return;
  }

  // API: Inspect / Apply binary customizations (POST-only, CSRF-protected,
  // bounded JSON bodies; GET never mutates any file)
  if (url.pathname === '/api/customization/inspect' || url.pathname === '/api/customization/apply') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json; charset=utf-8', Allow: 'POST' });
      res.end(JSON.stringify({ error: 'Method not allowed; use POST' }));
      return;
    }
    if (!validateContextSettingsPost(req, res)) return;
    let body;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      sendJson(res, err instanceof CustomizationError ? err.status : 400, { error: err.message });
      return;
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      sendJson(res, 400, { error: 'Request body must be a JSON object' });
      return;
    }
    try {
      if (url.pathname === '/api/customization/inspect') {
        sendJson(res, 200, inspectTarget(body.targetId));
      } else {
        sendJson(res, 200, await applyCustomization(body));
      }
    } catch (err) {
      if (err instanceof CustomizationError) {
        sendJson(res, err.status, { error: err.message });
      } else {
        sendJson(res, 500, { error: err.message || 'Internal customization error' });
      }
    }
    return;
  }

  // Serve Plugin Logo
  if (url.pathname === '/logo.svg' || url.pathname === '/assets/logo.svg') {
    try {
      const logoPath = join(__dirname, '..', '..', 'assets', 'logo.svg');
      res.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8' });
      res.end(readFileSync(logoPath));
    } catch (e) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Logo not found');
    }
    return;
  }

  // Serve Main Dashboard HTML
  if (url.pathname === '/' || url.pathname === '/index.html') {
    try {
      const htmlPath = join(__dirname, 'index.html');
      const html = readFileSync(htmlPath, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Error loading dashboard: ' + err.message);
    }
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, HOST, () => {
  console.log(`[agy-context] Background Sidecar daemon listening on http://${HOST}:${PORT}`);
  // Initial warm-up in background
  setTimeout(() => {
    try {
      analyzeGlobalTokens('today');
    } catch (e) {}
  }, 1000);
  // Periodic background refresh every 60s
  setInterval(() => {
    try {
      analyzeGlobalTokens('today');
    } catch (e) {}
  }, 60000);
});
