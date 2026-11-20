import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const PORT = 4187;
const BASE = `http://127.0.0.1:${PORT}`;
let child;
let dir;

async function waitFor(url, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`server did not start: ${url}`);
}

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rulegate-http-'));
  child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1', RULEGATE_DATA_DIR: path.join(dir, 'data'), RULEGATE_STATE_DIR: path.join(dir, 'state'), RULEGATE_AUDIT_DIR: path.join(dir, 'audit') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitFor(`${BASE}/api/health`);
});

after(() => { child?.kill('SIGTERM'); });

async function login(username, password) {
  const res = await fetch(`${BASE}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const body = await res.json();
  return body.token;
}

async function query(token, text, extra = {}) {
  const res = await fetch(`${BASE}/api/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ text, ...extra }),
  });
  return { status: res.status, body: await res.json() };
}

test('unauthenticated API access is rejected', async () => {
  const res = await fetch(`${BASE}/api/query`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"text":"销售额"}' });
  assert.equal(res.status, 401);
  const body = await res.json();
  assert.equal(body.error.code, 'AUTH_REQUIRED');
});

test('bad credentials are rejected without leaking which part was wrong', async () => {
  const res = await fetch(`${BASE}/api/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'nope' }) });
  assert.equal(res.status, 401);
  const body = await res.json();
  assert.equal(body.error.code, 'LOGIN_FAILED');
  assert.match(body.error.message, /用户名或密码错误/);
});

test('login returns a usable session', async () => {
  const token = await login('alice', 'analyst-demo-2026');
  const res = await fetch(`${BASE}/api/session`, { headers: { Authorization: `Bearer ${token}` } });
  const body = await res.json();
  assert.equal(body.session.roleId, 'analyst');
});

test('query success carries result, evidence and audit metadata', async () => {
  const token = await login('alice', 'analyst-demo-2026');
  const { status, body } = await query(token, '最近30天各渠道的销售额');
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.evidence.schema, 'rulegate.evidence/v1');
  assert.ok(body.evidence.registry.registryVersion);
  assert.ok(body.evidence.result.outputHash);
  assert.ok(body.audit.seq > 0);
});

test('role is taken from the session, not the request body', async () => {
  const token = await login('wang', 'west-demo-2026');
  const { status, body } = await query(token, '最近30天各渠道的销售额', { roleId: 'analyst' });
  assert.equal(status, 200);
  assert.equal(body.evidence.role.id, 'sales_west');
  assert.deepEqual(body.evidence.authorization.appliedScopes[0].values, ['华东']);
});

test('non-query intent returns 422 with structured rejections', async () => {
  const token = await login('alice', 'analyst-demo-2026');
  const { status, body } = await query(token, '删除所有订单');
  assert.equal(status, 422);
  assert.equal(body.stage, 'parse');
  assert.equal(body.rejections[0].code, 'DANGEROUS_INTENT');
});

test('out-of-scope request returns 403', async () => {
  const token = await login('wang', 'west-demo-2026');
  const { status, body } = await query(token, '最近30天华南的销售额');
  assert.equal(status, 403);
  assert.equal(body.stage, 'authorize');
});

test('registry pins a historical version on request', async () => {
  const token = await login('alice', 'analyst-demo-2026');
  const v2res = await query(token, '最近30天的业绩', { registryRef: 'v2' });
  assert.equal(v2res.status, 422);
  assert.ok(v2res.body.rejections.some((r) => r.code === 'AMBIGUOUS_TERM'));
  const v3res = await query(token, '最近30天的业绩', { registryRef: 'v3' });
  assert.equal(v3res.status, 200);
});

test('replay endpoint reproduces the original output hash', async () => {
  const token = await login('alice', 'analyst-demo-2026');
  const { body } = await query(token, '最近30天各渠道的销售额', { cacheBypass: true });
  const res = await fetch(`${BASE}/api/replay/${encodeURIComponent(body.queryId)}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: '{}' });
  const payload = await res.json();
  assert.equal(payload.verification.deterministic, true);
  assert.equal(payload.verification.replayOutputHash, body.evidence.result.outputHash);
});

test('audit is readable only by audit roles', async () => {
  const sales = await login('wang', 'west-demo-2026');
  const denied = await fetch(`${BASE}/api/audit`, { headers: { Authorization: `Bearer ${sales}` } });
  assert.equal(denied.status, 403);
  const auditor = await login('audit', 'audit-demo-2026');
  const allowed = await fetch(`${BASE}/api/audit`, { headers: { Authorization: `Bearer ${auditor}` } });
  assert.equal(allowed.status, 200);
  const payload = await allowed.json();
  assert.equal(payload.verification.ok, true);
});

test('audit export verifies and is a downloadable bundle', async () => {
  const token = await login('audit', 'audit-demo-2026');
  const res = await fetch(`${BASE}/api/audit/export?format=json`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-disposition'), /attachment/);
  const payload = await res.json();
  assert.equal(payload.verification.ok, true);
  assert.ok(payload.bundle.records.length > 0);
});

test('CSV export requires permission and includes evidence rows', async () => {
  const alice = await login('alice', 'analyst-demo-2026');
  const { body } = await query(alice, '最近30天各渠道的销售额');
  const ok = await fetch(`${BASE}/api/export/query/${encodeURIComponent(body.queryId)}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${alice}` }, body: '{}' });
  assert.equal(ok.status, 200);
  const csv = await ok.text();
  assert.match(csv, /registryVersion/);
  assert.match(csv, /partitions/);

  const wang = await login('wang', 'west-demo-2026');
  const west = await query(wang, '最近30天华东的销售额');
  const forbidden = await fetch(`${BASE}/api/export/query/${encodeURIComponent(west.body.queryId)}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${wang}` }, body: '{}' });
  assert.equal(forbidden.status, 403);
});

test('publish requires If-Match and audit role, and conflicts return 409', async () => {
  const alice = await login('alice', 'analyst-demo-2026');
  const registry = await (await fetch(`${BASE}/api/registry`, { headers: { Authorization: `Bearer ${alice}` } })).json();
  const forbidden = await fetch(`${BASE}/api/rules/publish`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${alice}`, 'If-Match': registry.registry.registryVersion },
    body: JSON.stringify({ doc: {} }),
  });
  assert.equal(forbidden.status, 403);

  const admin = await login('admin', 'rules-demo-2026');
  const draft = await (await fetch(`${BASE}/api/registry/v3`, { headers: { Authorization: `Bearer ${admin}` } })).json();
  const doc = {
    schemaVersion: 1, label: 'v0', publishedAt: '2026-11-20T00:00:00.000Z', notes: 'http test',
    calendar: { timezone: 'UTC' }, timeGrains: draft.registry.timeGrains,
    fields: draft.registry.fields.map((f) => ({ id: f.id, label: f.label, table: 'orders', column: f.id, type: f.type, semantic: f.semantic, description: f.description, aliases: f.aliases, filterable: f.filterable, groupable: f.groupable, pii: f.pii, operators: f.operators, ...(f.enum ? { enum: f.enum } : {}) })),
    metrics: draft.registry.metrics.map((m) => ({ id: m.id, label: m.label, aliases: m.aliases, kind: m.kind, definition: m.definition, unit: m.unit, description: m.description })),
    roles: Object.fromEntries(draft.registry.roles.map((r) => [r.id, { label: r.label, description: r.description, allowedMetrics: r.metrics, allowedFields: r.fields, allowedOps: r.ops, rowScope: r.rowScope, maxRangeDays: r.maxRangeDays, defaultRangeDays: 30, defaultLimit: 20, maxLimit: r.maxLimit, minCohort: r.minCohort, canExport: r.canExport, auditRead: r.auditRead, canPublish: r.canPublish, canGroupBy: true, canSort: true, canReplay: true }])),
  };
  const expected = registry.registry.registryVersion;
  const publish = (body) => fetch(`${BASE}/api/rules/publish`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${admin}`, 'If-Match': expected },
    body: JSON.stringify(body),
  });
  const [a, b] = await Promise.all([publish({ doc: structuredClone(doc), notes: 'A' }), publish({ doc: structuredClone(doc), notes: 'B' })]);
  const statuses = [a.status, b.status].sort();
  assert.deepEqual(statuses, [201, 409]);
  const conflict = a.status === 409 ? await a.json() : await b.json();
  assert.equal(conflict.error.code, 'RULE_VERSION_CONFLICT');
});

test('path traversal on static files is rejected', async () => {
  const res = await fetch(`${BASE}/..%2f..%2fetc%2fpasswd`);
  assert.ok([403, 404].includes(res.status));
});

test('login is throttled after repeated failures', async () => {
  let last;
  for (let i = 0; i < 10; i += 1) {
    last = await fetch(`${BASE}/api/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'audit', password: `wrong-${i}` }) });
  }
  assert.equal(last.status, 429);
});
