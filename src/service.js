import { RuleRegistry, validateRuleDoc, computeAmbiguities } from './registry.js';
import { RestrictedQueryParser } from './parser.js';
import { authorizeIntent } from './authorize.js';
import { executeIntent, buildEvidence, hashIntent } from './engine.js';
import { QueryCache, cacheKey, scopeFingerprint } from './cache.js';
import { AuditLedger } from './audit.js';
import { DataWarehouse } from './data.js';
import { canonicalJson, csvRows, sha256, toDateString } from './util.js';
import fs from 'node:fs';
import path from 'node:path';

export class AppError extends Error {
  constructor(status, code, message, details = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function createService({ dataDir, persistDir = null, auditDir = null, seed = 'rulegate-v1', now = () => new Date(), registry = null } = {}) {
  const clock = now;
  const ruleRegistry = registry ?? new RuleRegistry({ persistDir, now: clock });
  const warehouse = new DataWarehouse({ dataDir });
  const cache = new QueryCache();
  const audit = new AuditLedger({ auditDir, now: clock });
  const replayStore = new Map(); // queryId -> { evidence, result, registryVersion, roleId, intent }
  const queriesDir = persistDir ? path.join(persistDir, 'queries') : null;
  if (queriesDir) {
    fs.mkdirSync(queriesDir, { recursive: true });
    for (const file of fs.readdirSync(queriesDir).filter((f) => f.endsWith('.json'))) {
      try {
        const stored = JSON.parse(fs.readFileSync(path.join(queriesDir, file), 'utf8'));
        if (stored?.queryId && stored?.evidence) replayStore.set(stored.queryId, stored);
      } catch (error) {
        console.error(`[queries] failed to load ${file}: ${error.message}`);
      }
    }
  }
  let queryCounter = 0;

  const isoNow = () => clock().toISOString();
  const anchorDate = () => toDateString(clock());

  function roleOrThrow(snapshot, roleId) {
    const role = snapshot.doc.roles[roleId];
    if (!role) throw new AppError(403, 'ROLE_UNKNOWN', `未登记的角色：${roleId}`);
    return role;
  }

  function listRoles(snapshot) {
    return Object.entries(snapshot.doc.roles).map(([id, r]) => ({
      id, label: r.label, description: r.description,
      metrics: r.allowedMetrics, fields: r.allowedFields, ops: r.allowedOps,
      rowScope: r.rowScope, maxRangeDays: r.maxRangeDays, maxLimit: r.maxLimit,
      minCohort: r.minCohort, canExport: r.canExport, auditRead: r.auditRead, canPublish: r.canPublish,
    }));
  }

  function describeSnapshot(snapshot) {
    const doc = snapshot.doc;
    return {
      label: snapshot.meta.label,
      registryVersion: snapshot.meta.registryVersion,
      publishedAt: snapshot.meta.publishedAt,
      publishedBy: snapshot.meta.publishedBy,
      parentVersion: snapshot.meta.parentVersion,
      notes: snapshot.meta.notes,
      acknowledgedAmbiguities: snapshot.meta.acknowledgedAmbiguities ?? [],
      ambiguities: computeAmbiguities(doc),
      metrics: doc.metrics.map((m) => ({
        id: m.id, label: m.label, kind: m.kind, unit: m.unit, description: m.description,
        hidden: Boolean(m.hidden), aliases: m.aliases, definition: m.definition, pointer: `/metrics/${m.id}`,
      })),
      fields: doc.fields.map((f) => ({
        id: f.id, label: f.label, type: f.type, semantic: f.semantic, description: f.description,
        aliases: f.aliases, filterable: f.filterable, groupable: f.groupable, pii: f.pii,
        operators: f.operators, enum: f.enum, unit: f.unit, scale: f.scale, pointer: `/fields/${f.id}`,
      })),
      timeGrains: doc.timeGrains,
      roles: listRoles(snapshot),
      calendar: doc.calendar,
    };
  }

  function auditRecord(type, payload, { actor, snapshot } = {}) {
    return audit.append(type, payload, { actor, registryVersion: snapshot?.meta?.registryVersion ?? null });
  }

  function rejectionPayload(parse, authorization) {
    const items = [];
    if (parse && !parse.ok) items.push(...parse.rejections);
    if (authorization && !authorization.ok) items.push(...authorization.violations.map((v) => v.toJSON()));
    return items;
  }

  async function runQuery({ text, roleId, registryRef = null, actor = null, cacheBypass = false, correlationId = null, options = {} }) {
    const asOf = isoNow();
    const snapshot = registryRef ? ruleRegistry.snapshot(registryRef) : ruleRegistry.current(clock());
    if (!snapshot) throw new AppError(404, 'REGISTRY_VERSION_UNKNOWN', `找不到规则版本：${registryRef}`);
    const role = roleOrThrow(snapshot, roleId);
    const queryId = `q_${snapshot.meta.registryVersion.slice(0, 8)}_${(++queryCounter).toString(36).padStart(4, '0')}_${sha256(`${asOf}:${text}:${roleId}`).slice(0, 6)}`;
    const parser = new RestrictedQueryParser(snapshot, { asOf, today: new Date(`${anchorDate()}T00:00:00Z`) });
    const parse = parser.parse(text);

    if (!parse.ok) {
      const record = auditRecord('query.denied', {
        queryId, text, roleId, stage: 'parse', rejections: parse.rejections,
        registryLabel: snapshot.meta.label, correlationId,
      }, { actor: actor ?? roleId, snapshot });
      return {
        ok: false, status: 422, queryId, stage: 'parse',
        rejections: parse.rejections, parse,
        registry: parse.registry, audit: { seq: record.seq, hash: record.hash },
      };
    }

    const authorization = authorizeIntent({ snapshot, roleId, intent: parse.intent });
    if (!authorization.ok) {
      const record = auditRecord('query.denied', {
        queryId, text, roleId, stage: 'authorize',
        rejections: authorization.violations.map((v) => v.toJSON()),
        intent: parse.intent, registryLabel: snapshot.meta.label, correlationId,
      }, { actor: actor ?? roleId, snapshot });
      return {
        ok: false, status: 403, queryId, stage: 'authorize',
        rejections: authorization.violations.map((v) => v.toJSON()),
        parse, registry: parse.registry, audit: { seq: record.seq, hash: record.hash },
      };
    }

    const start = parse.intent.time.start;
    const end = parse.intent.time.end;
    const months = [];
    let cursor = new Date(`${start.slice(0, 7)}-01T00:00:00Z`);
    while (toDateString(cursor) <= end) {
      months.push(toDateString(cursor).slice(0, 7));
      cursor = new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() + 1, 1));
    }
    const partitions = await warehouse.materialize({ start, end, seed });
    const partitionHashes = partitions.map((p) => ({ month: p.month, contentHash: p.contentHash }));
    const aclFingerprint = scopeFingerprint(role);
    const key = cacheKey({
      registryVersion: snapshot.meta.registryVersion,
      roleId,
      aclFingerprint,
      intent: parse.intent,
      partitionHashes,
      anchorDate: anchorDate(),
    });

    const cached = cacheBypass ? null : cache.get(key, { aclFingerprint, roleId });

    let result;
    let evidence;
    let fromCache = false;
    if (cached) {
      result = cached.result;
      fromCache = true;
      // Cache reuse keeps the original output hash as proof of identity, but
      // the evidence record must describe THIS execution (its own queryId and
      // the cache provenance), otherwise the audit trail would misattribute it.
      evidence = structuredClone(cached.evidence);
      evidence.queryId = queryId;
      evidence.generatedAt = isoNow();
      evidence.cache = { hit: true, sourceQueryId: cached.evidence.queryId, cacheKey: sha256(key) };
    } else {
      if (!cacheBypass) cache.stats.misses += 1;
      result = executeIntent({
        snapshot, role: { ...role, ...authorization.role }, intent: parse.intent,
        partitions, policy: authorization, now: clock(), queryId,
      });
      evidence = buildEvidence({
        snapshot, roleId, intent: parse.intent, parse, authorization, result,
        dataCoverage: { start, end, partitions: partitionHashes }, asOf, queryId, executedAt: result.executedAt,
      });
      evidence.cache = { hit: false, sourceQueryId: null, cacheKey: sha256(key) };
      if (!cacheBypass) {
        cache.put(key, { result, evidence }, {
          aclFingerprint,
          registryVersion: snapshot.meta.registryVersion,
          roleId,
          meta: { queryId },
        });
      }
    }

    const storedQuery = {
      queryId, text, roleId,
      registryVersion: snapshot.meta.registryVersion,
      registryLabel: snapshot.meta.label,
      intent: parse.intent,
      evidence,
      result,
      audit: { seq: 0, hash: null },
      createdAt: result.executedAt,
      partitions: partitionHashes,
    };
    replayStore.set(queryId, storedQuery);
    if (queriesDir) {
      try {
        fs.writeFileSync(path.join(queriesDir, `${queryId}.json`), JSON.stringify(storedQuery));
      } catch (error) {
        console.error(`[queries] failed to persist ${queryId}: ${error.message}`);
        auditRecord('query.persist_failed', { queryId, error: String(error.message) }, { actor: actor ?? roleId, snapshot });
      }
    }

    const record = auditRecord('query.allowed', {
      queryId, text, roleId, stage: 'execute', fromCache,
      registryLabel: snapshot.meta.label, registryVersion: snapshot.meta.registryVersion,
      intentHash: hashIntent(parse.intent),
      outputHash: evidence.result.outputHash,
      evidenceHash: sha256(canonicalJson(evidence)),
      partitionHashes, correlationId,
      rowCount: result.rowCount,
    }, { actor: actor ?? roleId, snapshot });

    const storedAfter = replayStore.get(queryId);
    if (storedAfter) storedAfter.audit = { seq: record.seq, hash: record.hash };

    return {
      ok: true, status: 200, queryId, stage: 'execute',
      result: {
        columns: result.columns, rows: result.rows, totals: result.totals,
        truncated: result.truncated, groupsBeforeLimit: result.groupsBeforeLimit,
        suppressedGroups: result.suppressedGroups, minCohort: result.minCohort,
      },
      parse: {
        normalizedText: parse.normalizedText, mappings: parse.mappings, warnings: parse.warnings,
        today: parse.today, asOf: parse.asOf,
      },
      intent: parse.intent,
      authorization: { role: authorization.role, appliedScopes: authorization.appliedScopes },
      registry: parse.registry,
      evidence,
      evidenceHash: sha256(canonicalJson(evidence)),
      cache: { hit: fromCache, key: sha256(key).slice(0, 16) },
      audit: { seq: record.seq, hash: record.hash },
      rejections: [],
      canExport: role.canExport,
    };
  }

  function getReplay(queryId) {
    return replayStore.get(queryId) ?? null;
  }

  async function replayQuery({ queryId, roleId, actor = null }) {
    const stored = replayStore.get(queryId);
    if (!stored) throw new AppError(404, 'QUERY_NOT_FOUND', `找不到可复现的查询：${queryId}`);
    const snapshot = ruleRegistry.snapshot(stored.registryVersion);
    if (!snapshot) throw new AppError(409, 'REGISTRY_VERSION_MISSING', '原始规则版本已不可用，无法复现');
    if (!ruleRegistry.snapshot(stored.registryVersion)?.doc.roles[stored.roleId]) {
      throw new AppError(409, 'REPLAY_ROLE_MISSING', '原始角色在原始规则版本中已不存在，无法复现');
    }
    // A replay returns the stored result. Only the original role, or a role
    // with audit-wide visibility, may see it; otherwise replay would bypass
    // row-level scope and metric grants.
    const requester = snapshot.doc.roles[roleId];
    if (!requester) throw new AppError(403, 'REPLAY_FORBIDDEN', '当前角色未在当前规则版本中登记');
    if (roleId !== stored.roleId && !requester.auditRead) {
      throw new AppError(403, 'REPLAY_FORBIDDEN', '只能复现本角色执行的查询；跨角色复现需要审计权限');
    }
    const record = auditRecord('query.replayed', {
      queryId, replayedBy: roleId, originalRole: stored.roleId,
      registryVersion: stored.registryVersion,
      outputHash: stored.evidence.result.outputHash,
    }, { actor: actor ?? roleId, snapshot });
    return { ok: true, queryId, snapshot, stored, audit: { seq: record.seq, hash: record.hash } };
  }

  function exportAudit({ roleId, fromSeq = 1, toSeq = null, format = 'json' }) {
    const snapshot = ruleRegistry.current(clock());
    const role = roleOrThrow(snapshot, roleId);
    if (!role.auditRead) throw new AppError(403, 'AUDIT_FORBIDDEN', `角色“${role.label}”无审计读取权限`);
    const verify = audit.verify();
    // The export record is written first, then included in the bundle so the
    // bundle can prove its own issuance.
    const record = auditRecord('audit.export', {
      roleId, fromSeq, toSeq, verified: verify.ok, ledgerHeadAtVerify: verify.head,
    }, { actor: roleId, snapshot });
    const bundle = audit.exportBundle({ fromSeq, toSeq: toSeq ?? record.seq });
    if (format === 'csv') {
      const header = ['seq', 'at', 'type', 'actor', 'queryId', 'registryVersion', 'hash', 'prevHash'];
      const rows = [header, ...bundle.records.map((r) => [r.seq, r.at, r.type, r.actor, r.payload?.queryId ?? '', r.registryVersion ?? '', r.hash, r.prevHash])];
      return {
        body: csvRows(rows), contentType: 'text/csv; charset=utf-8',
        filename: `rulegate-audit-${bundle.range.fromSeq}-${bundle.range.toSeq}.csv`,
        bundle, record,
      };
    }
    return {
      body: JSON.stringify({ bundle, verification: verify }, null, 2), contentType: 'application/json; charset=utf-8',
      filename: `rulegate-audit-${bundle.range.fromSeq}-${bundle.range.toSeq}.json`,
      bundle, record,
    };
  }

  function exportQuery({ queryId, roleId, format = 'csv' }) {
    const stored = replayStore.get(queryId);
    if (!stored) throw new AppError(404, 'QUERY_NOT_FOUND', `找不到查询：${queryId}`);
    const snapshot = ruleRegistry.snapshot(stored.registryVersion) ?? ruleRegistry.current(clock());
    const role = roleOrThrow(snapshot, roleId);
    if (!role.canExport) throw new AppError(403, 'EXPORT_FORBIDDEN', `角色“${role.label}”无导出权限`);
    if (stored.evidence.role.id !== roleId) throw new AppError(403, 'EXPORT_NOT_OWNER', '只能导出以同一角色执行的查询');
    const canReplayAll = role.auditRead;
    if (!canReplayAll && (stored.evidence.role.id !== roleId || !stored.evidence.authorization.appliedScopes)) {
      throw new AppError(403, 'EXPORT_FORBIDDEN', '无权限导出该查询');
    }
    const result = stored.result;
    const exportId = `e_${sha256(`${queryId}:${roleId}:${isoNow()}`).slice(0, 12)}`;
    const header = ['组', ...result.columns.filter((c) => c.type === 'metric').map((c) => `${c.label}(${c.unit})`)];
    const rows = [header];
    for (const row of result.rows) {
      rows.push([row.group ?? '', ...result.columns.filter((c) => c.type === 'metric').map((c) => (row.suppressed ? '已抑制' : row.metrics[c.id]?.display ?? ''))]);
    }
    rows.push([]);
    rows.push(['queryId', queryId]);
    rows.push(['registryVersion', stored.evidence.registry.registryVersion]);
    rows.push(['ruleLabel', stored.evidence.registry.label]);
    rows.push(['role', `${stored.evidence.role.label} (${stored.evidence.role.id})`]);
    rows.push(['timeWindow', `${stored.evidence.intent.time.start}..${stored.evidence.intent.time.end}`]);
    rows.push(['filters', stored.evidence.intent.filters.map((f) => `${f.fieldLabel} ${f.op} ${f.displayValues.join('|')}`).join('; ') || '（无）']);
    rows.push(['rowScope', stored.evidence.authorization.appliedScopes.map((s) => `${s.fieldLabel} in ${s.values.join('|')}`).join('; ') || '（无）']);
    rows.push(['partitions', stored.evidence.data.partitions.map((p) => `${p.month}:${p.contentHash.slice(0, 12)}`).join('; ')]);
    rows.push(['outputHash', stored.evidence.result.outputHash]);
    rows.push(['evidenceHash', sha256(canonicalJson(stored.evidence))]);
    const record = auditRecord('query.exported', {
      queryId, exportId, roleId, format, outputHash: stored.evidence.result.outputHash,
      evidenceHash: sha256(canonicalJson(stored.evidence)),
    }, { actor: roleId, snapshot });
    return {
      body: csvRows(rows), contentType: 'text/csv; charset=utf-8',
      filename: `rulegate-${queryId}.csv`, exportId, record,
    };
  }

  function publishRules({ doc, expectedVersion, actor, notes, acknowledgeAmbiguities = [] }) {
    const snapshot = ruleRegistry.current(clock());
    const role = snapshot.doc.roles[actor];
    if (!role?.canPublish) throw new AppError(403, 'PUBLISH_FORBIDDEN', `角色“${role?.label ?? actor}”无规则发布权限`);
    try {
      const sealed = ruleRegistry.publish({ doc, expectedVersion, actor, notes, acknowledgeAmbiguities, now: clock() });
      const record = auditRecord('rules.published', {
        label: sealed.meta.label, registryVersion: sealed.meta.registryVersion,
        parentVersion: sealed.meta.parentVersion, acknowledgedAmbiguities: sealed.meta.acknowledgedAmbiguities,
        notes: sealed.meta.notes,
      }, { actor, snapshot: sealed });
      return { ok: true, version: describeSnapshot(sealed), audit: { seq: record.seq, hash: record.hash } };
    } catch (error) {
      if (error.code === 'RULE_VERSION_CONFLICT' || error.code === 'AMBIGUITY_ACK_REQUIRED' || error.code === 'RULE_VALIDATION_FAILED') {
        auditRecord('rules.publish_rejected', { code: error.code, details: error.details, expectedVersion }, { actor, snapshot: null });
        const status = error.code === 'RULE_VERSION_CONFLICT' ? 409 : 422;
        throw new AppError(status, error.code, error.message, error.details);
      }
      throw error;
    }
  }

  function validateDraft(doc) {
    return validateRuleDoc(doc);
  }

  async function verifyDataIntegrity() {
    const snapshot = ruleRegistry.current(clock());
    const fixedMonths = ['2026-09', '2026-10', '2026-11'];
    const out = [];
    for (const month of fixedMonths) {
      const disk = await warehouse.partition(month, { seed });
      const runtimeSeed = seed;
      const { generatePartition } = await import('./data.js');
      const regenerated = generatePartition(month, { seed: runtimeSeed });
      out.push({ month, onDisk: disk.contentHash, regenerated: regenerated.contentHash, match: disk.contentHash === regenerated.contentHash });
    }
    return { registryVersion: snapshot.meta.registryVersion, partitions: out, ok: out.every((x) => x.match) };
  }

  return {
    service: {
      runQuery,
      replayQuery,
      getReplay,
      exportAudit,
      exportQuery,
      publishRules,
      validateDraft,
      verifyDataIntegrity,
      listVersions: () => ruleRegistry.list(),
      currentSnapshot: () => describeSnapshot(ruleRegistry.current(clock())),
      snapshot: (ref) => { const s = ruleRegistry.snapshot(ref); return s ? describeSnapshot(s) : null; },
      listRoles: () => listRoles(ruleRegistry.current(clock())),
      audit: {
        list: (opts) => audit.list(opts),
        verify: () => audit.verify(),
        head: () => audit.head(),
      },
      cache: {
        describe: () => cache.describe(),
        stats: () => ({ ...cache.stats, size: cache.size() }),
        clear: () => cache.clear(),
      },
      clock: isoNow,
    },
    dependencies: { ruleRegistry, warehouse, cache, audit, replayStore, clock },
  };
}
