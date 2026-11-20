import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createService, AppError } from './service.js';
import { AuthStore, DEMO_ACCOUNTS } from './auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.RULEGATE_DATA_DIR ?? path.join(ROOT, 'data');
const PERSIST_DIR = process.env.RULEGATE_STATE_DIR ?? path.join(ROOT, '.state');
const AUDIT_DIR = process.env.RULEGATE_AUDIT_DIR ?? path.join(PERSIST_DIR, 'audit');
const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? '127.0.0.1';
const MAX_BODY = 512 * 1024;

const { service } = createService({ dataDir: DATA_DIR, persistDir: PERSIST_DIR, auditDir: AUDIT_DIR });
const auth = new AuthStore();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
};

function securityHeaders(res, { html = false } = {}) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', html
    ? "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    : "default-src 'none'; frame-ancestors 'none'");
}

function sendJson(res, status, body, _opts = {}) {
  const payload = JSON.stringify(body);
  securityHeaders(res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

function sendText(res, status, text, contentType, extra = {}) {
  securityHeaders(res);
  res.writeHead(status, { 'Content-Type': contentType, 'Content-Length': Buffer.byteLength(text), ...extra });
  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        const err = new AppError(413, 'BODY_TOO_LARGE', '请求体超过 512KB 上限');
        req.destroy();
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve(null);
      const raw = Buffer.concat(chunks).toString('utf8');
      try { resolve(JSON.parse(raw)); } catch { reject(new AppError(400, 'BODY_INVALID_JSON', '请求体不是合法 JSON')); }
    });
    req.on('error', reject);
  });
}

function cookies(req) {
  const out = {};
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function bearer(req) {
  const header = req.headers.authorization ?? '';
  if (header.startsWith('Bearer ')) return header.slice(7);
  return null;
}

function requireSession(req, res) {
  const token = bearer(req) ?? cookies(req).rl_session;
  const session = auth.resolve(token);
  if (!session) {
    const err = new AppError(401, 'AUTH_REQUIRED', '请先登录');
    throw err;
  }
  return session;
}

async function route(req, res, url) {
  const method = req.method;
  const pathname = url.pathname;

  if (pathname === '/api/health' && method === 'GET') {
    return sendJson(res, 200, { ok: true, service: 'rulegate', time: service.clock() });
  }

  if (pathname === '/api/login' && method === 'POST') {
    const body = await readBody(req) ?? {};
    const ip = req.socket.remoteAddress ?? 'unknown';
    try {
      const session = auth.login(String(body.username ?? ''), String(body.password ?? ''), { ip });
      res.setHeader('Set-Cookie', `rl_session=${encodeURIComponent(session.token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${8 * 60 * 60}${req.socket.encrypted ? '; Secure' : ''}`);
      return sendJson(res, 200, {
        ok: true,
        session: {
          username: session.username, displayName: session.displayName, roleId: session.roleId,
          expiresAt: new Date(session.expiresAt).toISOString(),
        },
        token: session.token,
      }, { setCookie: true });
    } catch (error) {
      throw new AppError(error.code === 'LOGIN_THROTTLED' ? 429 : 401, error.code, error.message);
    }
  }

  if (pathname === '/api/demo-accounts' && method === 'GET') {
    if (process.env.RULEGATE_EXPOSE_DEMO === '0') return sendJson(res, 404, { error: 'NOT_FOUND' });
    return sendJson(res, 200, {
      accounts: DEMO_ACCOUNTS.map((a) => ({ username: a.username, password: a.password, displayName: a.displayName, roleId: a.roleId })),
      warning: '仅演示环境：账号口令由服务端内置，生产部署必须替换为真实身份源。',
    });
  }

  if (pathname === '/api/logout' && method === 'POST') {
    const token = bearer(req) ?? cookies(req).rl_session;
    if (token) auth.logout(token);
    res.setHeader('Set-Cookie', 'rl_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }

  if (pathname === '/api/session' && method === 'GET') {
    const session = requireSession(req, res);
    const snapshot = service.currentSnapshot();
    return sendJson(res, 200, {
      ok: true,
      session: { username: session.username, displayName: session.displayName, roleId: session.roleId, expiresAt: new Date(session.expiresAt).toISOString() },
      role: snapshot.roles.find((r) => r.id === session.roleId) ?? null,
      registry: { label: snapshot.label, registryVersion: snapshot.registryVersion, publishedAt: snapshot.publishedAt },
    });
  }

  if (pathname === '/api/registry' && method === 'GET') {
    requireSession(req, res);
    return sendJson(res, 200, { ok: true, registry: service.currentSnapshot(), versions: service.listVersions() });
  }

  if (pathname === '/api/registry/versions' && method === 'GET') {
    requireSession(req, res);
    return sendJson(res, 200, { ok: true, versions: service.listVersions() });
  }

  const registryMatch = /^\/api\/registry\/([^/]+)$/.exec(pathname);
  if (registryMatch && method === 'GET') {
    requireSession(req, res);
    const registry = service.snapshot(decodeURIComponent(registryMatch[1]));
    if (!registry) throw new AppError(404, 'REGISTRY_VERSION_UNKNOWN', '找不到该规则版本');
    return sendJson(res, 200, { ok: true, registry });
  }

  if (pathname === '/api/roles' && method === 'GET') {
    requireSession(req, res);
    return sendJson(res, 200, { ok: true, roles: service.listRoles() });
  }

  if (pathname === '/api/query' && method === 'POST') {
    const session = requireSession(req, res);
    const body = await readBody(req) ?? {};
    const text = typeof body.text === 'string' ? body.text : '';
    const outcome = await service.runQuery({
      text,
      roleId: session.roleId,
      registryRef: body.registryRef ?? null,
      actor: session.username,
      cacheBypass: body.cacheBypass === true,
      correlationId: typeof body.correlationId === 'string' ? body.correlationId.slice(0, 64) : null,
    });
    return sendJson(res, outcome.status, outcome);
  }

  const replayMatch = /^\/api\/replay\/([^/]+)$/.exec(pathname);
  if (replayMatch && method === 'POST') {
    const session = requireSession(req, res);
    const replayAudit = await service.replayQuery({ queryId: decodeURIComponent(replayMatch[1]), roleId: session.roleId, actor: session.username });
    const { ok, queryId, snapshot, stored } = replayAudit;
    const body = await readBody(req) ?? {};
    const reexecuted = await service.runQuery({
      text: stored.text,
      roleId: stored.roleId,
      registryRef: stored.registryVersion,
      actor: session.username,
      cacheBypass: true,
      correlationId: `replay:${queryId}`,
    });
    const deterministic = reexecuted.ok
      && reexecuted.evidence.result.outputHash === stored.evidence.result.outputHash
      && reexecuted.evidence.registry.registryVersion === stored.evidence.registry.registryVersion;
    return sendJson(res, 200, {
      ok: ok && deterministic,
      queryId,
      requestedBy: session.username,
      replayedAs: stored.roleId,
      ruleLabel: snapshot.meta.label,
      registryVersion: snapshot.meta.registryVersion,
      evidence: stored.evidence,
      result: stored.result,
      reexecuted: reexecuted.ok ? {
        queryId: reexecuted.queryId,
        outputHash: reexecuted.evidence.result.outputHash,
        registryVersion: reexecuted.evidence.registry.registryVersion,
        rows: reexecuted.result.rows,
      } : { error: reexecuted.rejections },
      verification: {
        deterministic,
        originalOutputHash: stored.evidence.result.outputHash,
        replayOutputHash: reexecuted.ok ? reexecuted.evidence.result.outputHash : null,
        registryUnchanged: reexecuted.ok ? reexecuted.evidence.registry.registryVersion === stored.evidence.registry.registryVersion : false,
      },
      note: '复现固定使用原始 registryVersion，不读取当前最新规则。',
      replayedBy: session.username,
      audit: replayAudit?.audit ?? null,
      requestNote: typeof body.note === 'string' ? body.note.slice(0, 200) : null,
    });
  }

  const exportQueryMatch = /^\/api\/export\/query\/([^/]+)$/.exec(pathname);
  if (exportQueryMatch && method === 'POST') {
    const session = requireSession(req, res);
    const body = await readBody(req) ?? {};
    const out = service.exportQuery({ queryId: decodeURIComponent(exportQueryMatch[1]), roleId: session.roleId, format: body.format === 'csv' ? 'csv' : 'csv' });
    return sendText(res, 200, out.body, out.contentType, {
      'Content-Disposition': `attachment; filename="${out.filename}"`,
      'X-Export-Id': out.exportId,
      'X-Audit-Seq': String(out.record.seq),
    });
  }

  if (pathname === '/api/audit' && method === 'GET') {
    const session = requireSession(req, res);
    const snapshot = service.currentSnapshot();
    const role = snapshot.roles.find((r) => r.id === session.roleId);
    if (!role?.auditRead) throw new AppError(403, 'AUDIT_FORBIDDEN', '当前角色无审计读取权限');
    const limit = Math.min(Number(url.searchParams.get('limit') ?? 100) || 100, 500);
    return sendJson(res, 200, {
      ok: true,
      records: service.audit.list({ limit, type: url.searchParams.get('type') || null, queryId: url.searchParams.get('queryId') || null }),
      head: service.audit.head(),
      verification: service.audit.verify(),
    });
  }

  if (pathname === '/api/audit/verify' && method === 'GET') {
    requireSession(req, res);
    return sendJson(res, 200, { ok: true, verification: service.audit.verify() });
  }

  if (pathname === '/api/audit/export' && method === 'GET') {
    const session = requireSession(req, res);
    const format = url.searchParams.get('format') === 'csv' ? 'csv' : 'json';
    const fromSeq = Number(url.searchParams.get('fromSeq') ?? 1) || 1;
    const toSeqRaw = url.searchParams.get('toSeq');
    const out = service.exportAudit({ roleId: session.roleId, fromSeq, toSeq: toSeqRaw ? Number(toSeqRaw) : null, format });
    return sendText(res, 200, out.body, out.contentType, { 'Content-Disposition': `attachment; filename="${out.filename}"` });
  }

  if (pathname === '/api/rules/validate' && method === 'POST') {
    const session = requireSession(req, res);
    const snapshot = service.currentSnapshot();
    const role = snapshot.roles.find((r) => r.id === session.roleId);
    if (!role?.canPublish) throw new AppError(403, 'PUBLISH_FORBIDDEN', '当前角色无规则发布权限');
    const body = await readBody(req) ?? {};
    return sendJson(res, 200, { ok: true, validation: service.validateDraft(body.doc) });
  }

  if (pathname === '/api/rules/publish' && method === 'POST') {
    const session = requireSession(req, res);
    const body = await readBody(req) ?? {};
    const expectedVersion = req.headers['if-match']?.replaceAll('"', '') ?? body.expectedVersion;
    const out = service.publishRules({
      doc: body.doc,
      expectedVersion,
      actor: session.roleId,
      notes: typeof body.notes === 'string' ? body.notes : '',
      acknowledgeAmbiguities: Array.isArray(body.acknowledgeAmbiguities) ? body.acknowledgeAmbiguities : [],
    });
    return sendJson(res, 201, out);
  }

  if (pathname === '/api/cache' && method === 'GET') {
    requireSession(req, res);
    return sendJson(res, 200, { ok: true, stats: service.cache.stats(), entries: service.cache.describe() });
  }

  if (pathname === '/api/cache/clear' && method === 'POST') {
    const session = requireSession(req, res);
    const snapshot = service.currentSnapshot();
    const role = snapshot.roles.find((r) => r.id === session.roleId);
    if (!role?.canPublish) throw new AppError(403, 'CACHE_FORBIDDEN', '仅规则管理员可清空缓存');
    service.cache.clear();
    return sendJson(res, 200, { ok: true, clearedBy: session.username });
  }

  if (pathname === '/api/integrity' && method === 'GET') {
    requireSession(req, res);
    return sendJson(res, 200, { ok: true, integrity: await service.verifyDataIntegrity() });
  }

  throw new AppError(404, 'NOT_FOUND', `未知接口：${method} ${pathname}`);
}

function serveStatic(req, res, url) {
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/') pathname = '/index.html';
  const filePath = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    return sendText(res, 403, 'Forbidden', 'text/plain; charset=utf-8');
  }
  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === 'ENOENT') return sendText(res, 404, 'Not found', 'text/plain; charset=utf-8');
      return sendText(res, 500, 'Read error', 'text/plain; charset=utf-8');
    }
    const ext = path.extname(filePath).toLowerCase();
    securityHeaders(res, { html: ext === '.html' });
    res.writeHead(200, { 'Content-Type': MIME[ext] ?? 'application/octet-stream' });
    res.end(req.method === 'HEAD' ? undefined : content);
  });
}

const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
  } catch {
    return sendJson(res, 400, { ok: false, error: { code: 'BAD_URL', message: '非法请求地址' } });
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }
  try {
    if (url.pathname.startsWith('/api/')) return await route(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendText(res, 405, 'Method not allowed', 'text/plain; charset=utf-8');
    return serveStatic(req, res, url);
  } catch (error) {
    if (error instanceof AppError) {
      return sendJson(res, error.status, { ok: false, error: { code: error.code, message: error.message, details: error.details } });
    }
    console.error('[server] unhandled', error);
    return sendJson(res, 500, { ok: false, error: { code: 'INTERNAL', message: '服务内部错误' } });
  }
});

export function start() {
  return new Promise((resolve) => {
    server.listen(PORT, HOST, () => {
      const address = server.address();
      console.log(`RuleGate listening on http://${address.address}:${address.port}`);
      resolve(server);
    });
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  start();
}

export { server, service };
