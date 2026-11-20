import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { loadApp } from './fake-dom.js';
import { createService } from '../src/service.js';
import { tmpDir, AS_OF } from './helpers.js';

const appSource = fs.readFileSync(path.resolve(import.meta.dirname, '../public/app.js'), 'utf8');

/* Turn the in-process service into a fetch-compatible router so the real
   browser module talks to the real backend logic. */
function serviceFetch(built, { roleIdFor = () => 'analyst' } = {}) {
  return async function fetchImpl(input, init = {}) {
    const url = new URL(String(input), 'http://localhost');
    const method = (init.method ?? 'GET').toUpperCase();
    const body = init.body ? JSON.parse(init.body) : {};
    const json = (status, payload) => new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });

    if (url.pathname === '/api/demo-accounts') return json(200, { accounts: [{ username: 'alice', password: 'analyst-demo-2026', displayName: 'Alice', roleId: 'analyst' }] });
    if (url.pathname === '/api/session' && method === 'GET') {
      const roleId = roleIdFor();
      const snapshot = built.service.currentSnapshot();
      return json(200, {
        ok: true,
        session: { username: roleId, displayName: `${roleId} user`, roleId, expiresAt: AS_OF },
        role: snapshot.roles.find((r) => r.id === roleId),
        registry: { label: snapshot.label, registryVersion: snapshot.registryVersion, publishedAt: snapshot.publishedAt },
      });
    }
    if (url.pathname === '/api/registry' && method === 'GET') {
      return json(200, { ok: true, registry: built.service.currentSnapshot(), versions: built.service.listVersions() });
    }
    if (url.pathname.startsWith('/api/registry/') && method === 'GET') {
      const label = decodeURIComponent(url.pathname.split('/').at(-1));
      return json(200, { ok: true, registry: built.service.snapshot(label) });
    }
    if (url.pathname === '/api/query' && method === 'POST') {
      const outcome = await built.service.runQuery({ text: body.text ?? '', roleId: roleIdFor(), registryRef: body.registryRef ?? null, cacheBypass: body.cacheBypass === true });
      return json(outcome.status, outcome);
    }
    if (url.pathname === '/api/audit' && method === 'GET') {
      return json(200, { ok: true, records: built.service.audit.list({ limit: 50 }), head: built.service.audit.head(), verification: built.service.audit.verify() });
    }
    if (url.pathname.endsWith('/api/cache') || url.pathname === '/api/cache') {
      return json(200, { ok: true, stats: built.service.cache.stats(), entries: built.service.cache.describe() });
    }
    return json(404, { error: { code: 'NOT_FOUND', message: url.pathname } });
  };
}

function setup(roleId = 'analyst') {
  const dir = tmpDir();
  const built = createService({
    dataDir: path.join(dir, 'data'), persistDir: path.join(dir, 'state'), auditDir: path.join(dir, 'audit'),
    now: () => new Date(AS_OF),
  });
  return { built, fetchImpl: serviceFetch(built, { roleIdFor: () => roleId }) };
}

test('frontend has no eval/Function sinks', () => {
  assert.ok(!/eval\s*\(/.test(appSource), 'eval must not be used');
  assert.ok(!/new Function/.test(appSource), 'new Function must not be used');
  assert.ok(!/document\.write/.test(appSource), 'document.write must not be used');
  assert.ok(!/\.insertAdjacentHTML\s*\(\s*[^'"`]/.test(appSource), 'insertAdjacentHTML must not take computed input');
});

const HOSTILE = '<img src=x onerror=alert(1)>';
// The hostile payload may appear as escaped text; what must never appear is
// the payload verbatim or any tag it would create.
const HOSTILE_BITS = [HOSTILE, '<img', '<script', '<svg', 'javascript:alert'];

/* Serve the same endpoint shapes as serviceFetch but with hostile strings in
   every string field the frontend interpolates into markup. The registry and
   role payloads are the real snapshots with every string poisoned, so every
   render path sees structurally valid data carrying attacker-controlled text. */
function poison(value) {
  if (typeof value === 'string') return `${value}${HOSTILE}`;
  if (Array.isArray(value)) return value.map(poison);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, poison(v)]));
  return value;
}

function hostileFetch() {
  const dir = tmpDir();
  const built = createService({
    dataDir: path.join(dir, 'data'), persistDir: path.join(dir, 'state'), auditDir: path.join(dir, 'audit'),
    now: () => new Date(AS_OF),
  });
  const snapshot = poison(built.service.currentSnapshot());
  const role = snapshot.roles.find((r) => r.id.startsWith('auditor'));
  const rejected = {
    ok: false, stage: 'parse', registry: snapshot,
    rejections: [{ code: `CODE${HOSTILE}`, title: `拒绝${HOSTILE}`, message: `原因${HOSTILE}`, span: { start: 0, end: 2 }, hint: `提示${HOSTILE}`, suggestions: [HOSTILE] }],
    parse: { normalizedText: HOSTILE, mappings: [], warnings: [{ code: HOSTILE, message: HOSTILE }] },
    intent: null, result: null,
  };
  const cache = { hits: 1, misses: 2, denied: 3, size: 1, evictions: 0, coalesced: 0 };
  return async function fetchImpl(input, init = {}) {
    const url = new URL(String(input), 'http://localhost');
    const method = (init.method ?? 'GET').toUpperCase();
    const json = (status, payload) => new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
    if (url.pathname === '/api/demo-accounts') return json(200, { accounts: [{ username: HOSTILE, password: HOSTILE, displayName: HOSTILE }] });
    if (url.pathname === '/api/login') return json(200, { ok: true });
    if (url.pathname === '/api/session') return json(200, { ok: true, session: { username: HOSTILE, displayName: HOSTILE, roleId: role.id }, role, registry: snapshot });
    if (url.pathname === '/api/registry') {
      return json(200, {
        ok: true, registry: snapshot,
        versions: [{
          label: snapshot.label, registryVersion: snapshot.registryVersion, publishedAt: HOSTILE,
          notes: HOSTILE, builtin: false,
          ambiguities: snapshot.ambiguities.map((a) => ({ term: HOSTILE, targets: a.targets })),
          warnings: [{ code: HOSTILE, message: HOSTILE }],
        }],
      });
    }
    if (url.pathname.startsWith('/api/registry/')) return json(200, { ok: true, registry: snapshot });
    if (url.pathname === '/api/rules/validate') return json(200, { ok: false, validation: { ok: false, errors: [{ code: HOSTILE, path: HOSTILE, message: HOSTILE }], warnings: [{ code: HOSTILE, message: HOSTILE }] } });
    if (url.pathname === '/api/rules/publish') return json(409, { error: { code: `CONFLICT${HOSTILE}`, message: HOSTILE } });
    if (url.pathname === '/api/query' && method === 'POST') return json(422, rejected);
    if (url.pathname.startsWith('/api/replay/')) {
      return json(200, { ok: true, ruleLabel: HOSTILE, registryVersion: HOSTILE, note: HOSTILE, verification: { deterministic: false, originalOutputHash: HOSTILE, replayOutputHash: HOSTILE } });
    }
    if (url.pathname === '/api/audit') {
      return json(200, {
        ok: true,
        records: [{ seq: 1, type: `query.allowed${HOSTILE}`, actor: HOSTILE, hash: HOSTILE, payload: { queryId: HOSTILE } }],
        verification: { ok: false, records: 1, head: HOSTILE, problems: [HOSTILE] },
      });
    }
    if (url.pathname === '/api/audit/verify') return json(200, { ok: true, verification: { ok: true, records: 1 } });
    if (url.pathname === '/api/cache') {
      return json(200, { ok: true, stats: cache, entries: [{ roleId: HOSTILE, registryVersion: HOSTILE, queryId: HOSTILE, hits: 1 }] });
    }
    if (url.pathname === '/api/integrity') return json(200, { ok: true, integrity: { partitions: [{ month: HOSTILE, onDisk: HOSTILE, match: true }] } });
    return json(404, { error: { code: 'NOT_FOUND', message: url.pathname } });
  };
}

test('every rendered surface escapes hostile server strings', async () => {
  const { doc } = await loadApp({ fetchImpl: hostileFetch() });
  const click = async (sel) => { await doc.querySelector(sel).dispatch('click', {}); };
  const submit = async (text) => {
    doc.querySelector('#query-text').value = text;
    await doc.querySelector('#query-form').dispatch('submit', { target: { querySelector: () => ({ disabled: false, textContent: '' }) } });
  };

  // Login screen (demo accounts), then the main shell.
  const loginList = doc.querySelector('#demo-list').innerHTML;
  assert.doesNotMatch(loginList, /<img/, 'demo account list leaks markup');
  await submit(`最近30天${HOSTILE}`);
  await click('#replay-btn');
  await click('#audit-refresh');
  await click('#cache-stats-btn');
  await click('#integrity-btn');
  await click('#audit-export');

  // Tabs use event delegation on #tabs; drive the delegated handler directly.
  const openTab = async (name) => {
    const tab = doc.querySelector(`#tabs .tab[data-tab="${name}"]`);
    await doc.querySelector('#tabs').dispatch('click', { target: { closest: () => tab, dataset: { tab: name } } });
  };
  await openTab('rules');
  await click('#load-draft');
  await click('#validate-draft');
  assert.match(doc.querySelector('#publish-feedback').innerHTML, /issue-list/, 'validation feedback did not render');
  await click('#publish-btn');
  await openTab('drills');
  await click('#concurrent-btn');

  const surfaces = ['#demo-list', '#vocab', '#registry-pill', '#result-body', '#evidence-body', '#replay-output', '#audit-list', '#audit-chain', '#cache-output', '#version-list', '#registry-table', '#drill-list', '#publish-feedback', '#login-error', '#toast'];
  // Prove the rules/audit surfaces were actually populated before scanning them.
  assert.match(doc.querySelector('#version-list').innerHTML, /version-card/, 'rules tab did not render');
  assert.match(doc.querySelector('#registry-table').innerHTML, /reg-section/, 'registry table did not render');
  assert.match(doc.querySelector('#audit-list').innerHTML, /audit-row/, 'audit list did not render');
  assert.match(doc.querySelector('#drill-list').innerHTML, /drill-row/, 'drills did not render');
  for (const sel of surfaces) {
    const html = doc.querySelector(sel).innerHTML;
    for (const bit of HOSTILE_BITS) {
      assert.ok(!html.includes(bit), `${sel} rendered hostile markup ${bit}: ${html.slice(0, 200)}`);
    }
  }
  // The hostile text itself must survive as escaped text where it is shown.
  assert.match(doc.querySelector('#result-body').innerHTML, /&lt;img/, 'hostile text should be escaped, not dropped');
});

test('app boots, renders vocabulary limited to the role, and hides audit tab for non-auditors', async () => {
  const { fetchImpl } = setup('sales_west');
  const { doc } = await loadApp({ fetchImpl });
  const vocab = doc.querySelector('#vocab').innerHTML;
  assert.match(vocab, /销售额/);
  assert.doesNotMatch(vocab, /客户数/, 'sales role lacks 客户数');
  assert.doesNotMatch(vocab, /毛利额/, 'internal derived metric must not be listed');
  assert.doesNotMatch(vocab, /品类/, 'sales role lacks 品类 field');
  const auditTab = doc.querySelector('#tabs .tab[data-tab="audit"]');
  assert.equal(auditTab.classList.contains('hidden'), true);
});

test('submitting a query renders rows, evidence mappings and audit receipt', async () => {
  const { fetchImpl } = setup('analyst');
  const { doc } = await loadApp({ fetchImpl });
  doc.querySelector('#query-text').value = '最近30天各渠道的销售额';
  await doc.querySelector('#query-form').dispatch('submit', {
    target: { querySelector: () => ({ disabled: false, textContent: '' }) },
  });
  const html = doc.querySelector('#result-body').innerHTML;
  assert.match(html, /电商/);
  assert.match(html, /规则 v3/);
  const evidence = doc.querySelector('#evidence-body').innerHTML;
  assert.match(evidence, /registryVersion/);
  assert.match(evidence, /解析映射/);
});

test('a rejected query renders structured rejection reasons, not a stack trace', async () => {
  const { fetchImpl } = setup('analyst');
  const { doc } = await loadApp({ fetchImpl });
  doc.querySelector('#query-text').value = '最近30天各渠道的销售额排名';
  await doc.querySelector('#query-form').dispatch('submit', {
    target: { querySelector: () => ({ disabled: false, textContent: '' }) },
  });
  const html = doc.querySelector('#result-body').innerHTML;
  assert.match(html, /解析未通过/);
  assert.match(html, /UNRECOGNIZED_TERM/);
  assert.doesNotMatch(html, /TypeError|at Object\./);
});

test('authorization rejection surfaces scope violation in the UI', async () => {
  const { fetchImpl } = setup('sales_west');
  const { doc } = await loadApp({ fetchImpl });
  doc.querySelector('#query-text').value = '最近30天华南的销售额';
  await doc.querySelector('#query-form').dispatch('submit', {
    target: { querySelector: () => ({ disabled: false, textContent: '' }) },
  });
  const html = doc.querySelector('#result-body').innerHTML;
  assert.match(html, /授权未通过/);
  assert.match(html, /SCOPE_VIOLATION/);
});

test('drills evaluate expected outcomes against the real backend', async () => {
  const { fetchImpl } = setup('analyst');
  const { doc, mod } = await loadApp({ fetchImpl });
  const drillList = doc.querySelector('#drill-list').innerHTML;
  assert.match(drillList, /AMBIGUOUS_TERM/);
  assert.match(drillList, /需切换角色/, 'role-specific drills are disabled for other roles');
  void mod;
});

test('escaping helper neutralizes HTML in user-controlled text', async () => {
  const { fetchImpl } = setup('analyst');
  const { doc } = await loadApp({ fetchImpl });
  doc.querySelector('#query-text').value = '<img src=x onerror=alert(1)>销售额';
  await doc.querySelector('#query-form').dispatch('submit', {
    target: { querySelector: () => ({ disabled: false, textContent: '' }) },
  });
  const html = doc.querySelector('#result-body').innerHTML;
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /UNRECOGNIZED_TERM/);
});
