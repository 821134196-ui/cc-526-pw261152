import test from 'node:test';
import assert from 'node:assert/strict';
import { makeService, cloneDraft, AS_OF } from './helpers.js';

test('allowed query returns rows, evidence, registry version and audit receipt', async () => {
  const { service } = makeService();
  const run = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  assert.equal(run.ok, true);
  assert.equal(run.status, 200);
  assert.ok(run.result.rows.length > 0);
  assert.equal(run.evidence.registry.label, 'v3');
  assert.equal(run.evidence.registry.registryVersion, run.registry.registryVersion);
  assert.ok(run.evidence.data.partitions.length >= 1);
  assert.ok(run.evidence.data.partitions.every((p) => /^[0-9a-f]{64}$/.test(p.contentHash)));
  assert.match(run.evidence.result.outputHash, /^[0-9a-f]{64}$/);
  assert.ok(run.audit.seq >= 1);
  assert.deepEqual(run.rejections, []);
});

test('denied query is audited with the exact rejection codes and stores nothing', async () => {
  const { service } = makeService();
  const run = await service.runQuery({ text: '最近30天华南的销售额', roleId: 'sales_west' });
  assert.equal(run.ok, false);
  assert.equal(run.status, 403);
  assert.equal(run.stage, 'authorize');
  const record = service.audit.list({ limit: 1 })[0];
  assert.equal(record.type, 'query.denied');
  assert.ok(record.payload.rejections.some((r) => r.code === 'SCOPE_VIOLATION'));
  assert.equal(service.getReplay(run.queryId), null);
});

test('parse denial returns 422 and never touches the warehouse', async () => {
  const { service, dependencies } = makeService();
  const run = await service.runQuery({ text: '最近30天各渠道的销售额排名', roleId: 'analyst' });
  assert.equal(run.status, 422);
  assert.equal(run.stage, 'parse');
  assert.equal(dependencies.warehouse ? service.cache.stats().size : 0, 0);
});

test('identical queries are served from cache and keep identical output hash', async () => {
  const { service } = makeService();
  const first = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  const second = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  assert.equal(first.cache.hit, false);
  assert.equal(second.cache.hit, true);
  assert.equal(first.evidence.result.outputHash, second.evidence.result.outputHash);
  assert.deepEqual(first.result.rows, second.result.rows);
  // A cache hit must not be able to impersonate the original execution.
  assert.notEqual(second.evidence.queryId, first.evidence.queryId);
  assert.equal(second.evidence.cache.hit, true);
  assert.equal(second.evidence.cache.sourceQueryId, first.queryId);
  assert.notEqual(second.evidenceHash, first.evidenceHash);
  const records = service.audit.list({ limit: 10, type: 'query.allowed' });
  const cachedRecord = records.find((r) => r.payload.queryId === second.queryId);
  const originalRecord = records.find((r) => r.payload.queryId === first.queryId);
  assert.equal(cachedRecord.payload.fromCache, true);
  assert.equal(originalRecord.payload.fromCache, false);
  assert.notEqual(cachedRecord.payload.evidenceHash, originalRecord.payload.evidenceHash);
  assert.equal(cachedRecord.payload.outputHash, originalRecord.payload.outputHash);
});

test('cache never crosses roles even for identical intent', async () => {
  const { service } = makeService();
  const analyst = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  const west = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'sales_west' });
  assert.equal(west.cache.hit, false);
  assert.notEqual(west.cache.key, analyst.cache.key);
  assert.equal(west.evidence.role.id, 'sales_west');
  assert.deepEqual(west.evidence.authorization.appliedScopes[0].values, ['华东']);
  // The analyst total must not equal the west-scoped total.
  assert.notEqual(analyst.result.totals.revenue.value, west.result.totals.revenue.value);
});

test('cache refuses to serve an entry to a mismatched ACL fingerprint', async () => {
  const { service, dependencies } = makeService();
  const run = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  assert.equal(run.ok, true);
  const [entryKey] = [...dependencies.cache.entries.keys()];
  dependencies.cache.entries.get(entryKey).aclFingerprint = 'forged';
  const again = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  assert.equal(again.cache.hit, false);
  assert.ok(service.cache.stats().denied >= 1);
});

test('cache is bypassed on demand and is reported honestly', async () => {
  const { service } = makeService();
  await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  const rerun = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst', cacheBypass: true });
  assert.equal(rerun.cache.hit, false);
});

test('a rule change invalidates the cache key even when data is unchanged', async () => {
  const { service, dependencies } = makeService();
  const before = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  const draft = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  draft.notes = 'alias change';
  draft.metrics.find((m) => m.id === 'revenue').aliases.push('流水额');
  const published = service.publishRules({
    doc: draft, expectedVersion: dependencies.ruleRegistry.current(dependencies.ruleRegistry.now()).meta.registryVersion,
    actor: 'rules_admin', notes: 'add alias',
  });
  assert.equal(published.ok, true);
  const after = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  assert.equal(after.cache.hit, false);
  assert.notEqual(after.cache.key, before.cache.key);
  assert.notEqual(after.evidence.registry.registryVersion, before.evidence.registry.registryVersion);
});

test('replay is restricted to the owning role or an audit role', async () => {
  const { service } = makeService();
  const own = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'sales_west' });
  assert.equal(own.ok, true);
  await assert.rejects(
    () => service.replayQuery({ queryId: own.queryId, roleId: 'sales_east' }),
    (e) => e.code === 'REPLAY_FORBIDDEN' && e.status === 403,
  );
  const byAuditor = await service.replayQuery({ queryId: own.queryId, roleId: 'auditor' });
  assert.equal(byAuditor.ok, true);
  const record = service.audit.list({ limit: 1 })[0];
  assert.equal(record.type, 'query.replayed');
  assert.equal(record.payload.replayedBy, 'auditor');
  assert.equal(record.payload.registryVersion, own.registry.registryVersion);
});

test('historical replay pins the original rule version and reproduces byte-identical output', async () => {
  const { service, dependencies } = makeService();
  const original = await service.runQuery({ text: '最近30天的业绩', roleId: 'analyst', registryRef: 'v3' });
  assert.equal(original.ok, true);
  // Publish a v4 where 业绩 now means something else (or is removed).
  const draft = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  draft.metrics.find((m) => m.id === 'gross_margin').aliases = draft.metrics.find((m) => m.id === 'gross_margin').aliases.filter((a) => a !== '业绩');
  draft.metrics.find((m) => m.id === 'orders').aliases.push('业绩');
  const current = dependencies.ruleRegistry.current(dependencies.clock()).meta.registryVersion;
  service.publishRules({ doc: draft, expectedVersion: current, actor: 'rules_admin', notes: '业绩 改为指订单数' });

  const fresh = await service.runQuery({ text: '最近30天的业绩', roleId: 'analyst' });
  assert.equal(fresh.intent.metrics[0].id, 'orders', 'latest rules reinterpret the alias');

  const replay = await service.replayQuery({ queryId: original.queryId, roleId: 'auditor' });
  assert.equal(replay.snapshot.meta.label, 'v3');
  assert.equal(replay.stored.evidence.result.outputHash, original.evidence.result.outputHash);
  const reexecuted = await service.runQuery({
    text: replay.stored.text, roleId: 'analyst', registryRef: original.registry.registryVersion, cacheBypass: true,
  });
  assert.equal(reexecuted.intent.metrics[0].id, 'gross_margin');
  assert.equal(reexecuted.evidence.result.outputHash, original.evidence.result.outputHash);
  assert.deepEqual(reexecuted.result.rows, original.result.rows);
});

test('small-cohort suppression hides groups below the role minimum', async () => {
  const { service, dependencies } = makeService();
  const draft = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  draft.roles.analyst.minCohort = 500;
  const v = dependencies.ruleRegistry.current(dependencies.clock()).meta.registryVersion;
  service.publishRules({ doc: draft, expectedVersion: v, actor: 'rules_admin', notes: 'enforce cohort floor' });
  const run = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  assert.equal(run.ok, true);
  assert.equal(run.result.minCohort, 500);
  assert.equal(run.result.suppressedGroups, run.result.rows.length);
  assert.ok(run.result.rows.every((r) => r.suppressed && r.metrics.revenue.value === null));
});

test('export requires permission and produces a CSV with evidence header rows', async () => {
  const { service } = makeService();
  const run = await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  const out = service.exportQuery({ queryId: run.queryId, roleId: 'analyst' });
  assert.match(out.contentType, /text\/csv/);
  assert.match(out.body, /queryId/);
  assert.match(out.body, /registryVersion/);
  assert.match(out.body, /outputHash/);
  assert.match(out.body, /evidenceHash/);
  // CSV injection neutralisation
  assert.ok(!/^=/.test(out.body));
  const west = await service.runQuery({ text: '最近30天华东的销售额', roleId: 'sales_west' });
  assert.throws(() => service.exportQuery({ queryId: west.queryId, roleId: 'sales_west' }), (e) => e.code === 'EXPORT_FORBIDDEN');
});

test('audit export requires audit permission', async () => {
  const { service } = makeService();
  const out = service.exportAudit({ roleId: 'auditor' });
  const parsed = JSON.parse(out.body);
  assert.equal(parsed.verification.ok, true);
  assert.ok(parsed.bundle.records.length >= 1);
  assert.throws(() => service.exportAudit({ roleId: 'sales_west' }), (e) => e.code === 'AUDIT_FORBIDDEN');
});

test('audit chain detects tampering with an earlier record', async () => {
  const { service, dependencies } = makeService();
  await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  await service.runQuery({ text: '最近30天各品类的销售额', roleId: 'analyst' });
  assert.equal(service.audit.verify().ok, true);
  dependencies.audit.records[0].payload.text = 'tampered';
  const verification = service.audit.verify();
  assert.equal(verification.ok, false);
  assert.ok(verification.problems.some((p) => p.code === 'HASH_MISMATCH'));
});

test('concurrent rule publication: exactly one writer wins with the same expectedVersion', async () => {
  const { service, dependencies } = makeService();
  const base = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  const expectedVersion = dependencies.ruleRegistry.current(dependencies.clock()).meta.registryVersion;
  const attempts = await Promise.allSettled([
    (async () => service.publishRules({ doc: structuredClone(base), expectedVersion, actor: 'rules_admin', notes: 'writer A' }))(),
    (async () => service.publishRules({ doc: structuredClone(base), expectedVersion, actor: 'rules_admin', notes: 'writer B' }))(),
  ]);
  const fulfilled = attempts.filter((a) => a.status === 'fulfilled');
  const rejected = attempts.filter((a) => a.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.code, 'RULE_VERSION_CONFLICT');
  assert.equal(rejected[0].reason.status, 409);
});

test('stale expectedVersion cannot overwrite a newer rule version', async () => {
  const { service, dependencies } = makeService();
  const v3version = dependencies.ruleRegistry.current(dependencies.clock()).meta.registryVersion;
  const draft = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  service.publishRules({ doc: draft, expectedVersion: v3version, actor: 'rules_admin', notes: 'first' });
  assert.throws(
    () => service.publishRules({ doc: cloneDraft(dependencies.ruleRegistry.snapshot('v3')), expectedVersion: v3version, actor: 'rules_admin', notes: 'stale' }),
    (e) => e.code === 'RULE_VERSION_CONFLICT',
  );
});

test('publishing without expectedVersion is rejected', async () => {
  const { service, dependencies } = makeService();
  const draft = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  assert.throws(() => service.publishRules({ doc: draft, expectedVersion: null, actor: 'rules_admin', notes: 'x' }), (e) => e.code === 'PRECONDITION_REQUIRED');
});

test('roles without publish rights cannot publish', async () => {
  const { service, dependencies } = makeService();
  const draft = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  const v = dependencies.ruleRegistry.current(dependencies.clock()).meta.registryVersion;
  assert.throws(() => service.publishRules({ doc: draft, expectedVersion: v, actor: 'analyst', notes: 'x' }), (e) => e.code === 'PUBLISH_FORBIDDEN');
});

test('publishing an ambiguous alias requires explicit acknowledgement', async () => {
  const { service, dependencies } = makeService();
  const draft = cloneDraft(dependencies.ruleRegistry.snapshot('v3'));
  draft.metrics.find((m) => m.id === 'revenue').aliases.push('指标X');
  draft.metrics.find((m) => m.id === 'orders').aliases.push('指标X');
  draft.acknowledgedAmbiguities = [];
  const v = dependencies.ruleRegistry.current(dependencies.clock()).meta.registryVersion;
  assert.throws(() => service.publishRules({ doc: draft, expectedVersion: v, actor: 'rules_admin', notes: 'x' }), (e) => e.code === 'AMBIGUITY_ACK_REQUIRED');
  const ok = service.publishRules({ doc: draft, expectedVersion: v, actor: 'rules_admin', notes: 'x', acknowledgeAmbiguities: ['指标X'] });
  assert.equal(ok.ok, true);
  const run = await service.runQuery({ text: '最近30天的指标X', roleId: 'analyst' });
  assert.equal(run.ok, false);
  assert.ok(run.rejections.some((r) => r.code === 'AMBIGUOUS_TERM'));
});

test('published rules persist and reload with the same version hash', async () => {
  const first = makeService();
  const draft = cloneDraft(first.dependencies.ruleRegistry.snapshot('v3'));
  const v = first.dependencies.ruleRegistry.current(first.clock()).meta.registryVersion;
  const published = first.service.publishRules({ doc: draft, expectedVersion: v, actor: 'rules_admin', notes: 'persist me' });
  const { createService } = await import('../src/service.js');
  const reloaded = createService({
    dataDir: `${first.dir}/data`, persistDir: `${first.dir}/state`, auditDir: `${first.dir}/audit`, now: first.clock,
  });
  const versions = reloaded.service.listVersions();
  assert.ok(versions.some((x) => x.registryVersion === published.version.registryVersion));
  assert.equal(reloaded.service.currentSnapshot().registryVersion, published.version.registryVersion);
});

test('data integrity check reproduces partition hashes', async () => {
  const { service } = makeService();
  await service.runQuery({ text: '最近30天各渠道的销售额', roleId: 'analyst' });
  const integrity = await service.verifyDataIntegrity();
  assert.equal(integrity.ok, true);
});
