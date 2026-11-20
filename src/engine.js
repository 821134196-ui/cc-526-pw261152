import { canonicalJson, sha256, daysBetween, addDays } from './util.js';

/*
 * Execution engine.
 *
 * The engine only ever sees a validated, authorized intent. It never interpolates
 * user text into a query: filtering is performed by column id against an
 * allow-listed predicate list built from the registry.
 */

function grainKey(date, grain) {
  if (grain === 'day') return date;
  if (grain === 'month') return date.slice(0, 7);
  if (grain === 'quarter') {
    const d = new Date(`${date}T00:00:00Z`);
    return `${d.getUTCFullYear()}-Q${Math.floor(d.getUTCMonth() / 3) + 1}`;
  }
  if (grain === 'year') return date.slice(0, 4);
  if (grain === 'week') {
    const d = new Date(`${date}T00:00:00Z`);
    const day = d.getUTCDay() || 7;
    return addDays(date, -(day - 1));
  }
  return date;
}

function grainSortKey(key, grain) {
  if (grain === 'quarter') {
    const [y, q] = key.split('-Q');
    return `${y}-${String((Number(q) - 1) * 3 + 1).padStart(2, '0')}`;
  }
  return key;
}

export function compilePredicates(intent, scope) {
  const preds = [];
  for (const f of intent.filters) {
    preds.push({ column: f.column, field: f.field, op: f.op, values: f.values, type: f.type, source: 'query' });
  }
  for (const s of scope) {
    preds.push({ column: s.column, field: s.field, op: s.op, values: s.values, type: 'enum', source: s.source });
  }
  return preds;
}

export function rowMatches(row, preds) {
  for (const p of preds) {
    const v = row[p.column];
    switch (p.op) {
      case 'eq': if (v !== p.values[0]) return false; break;
      case 'neq': if (v === p.values[0]) return false; break;
      case 'in': if (!p.values.includes(v)) return false; break;
      case 'not_in': if (p.values.includes(v)) return false; break;
      case 'gt': if (!(v > p.values[0])) return false; break;
      case 'gte': if (!(v >= p.values[0])) return false; break;
      case 'lt': if (!(v < p.values[0])) return false; break;
      case 'lte': if (!(v <= p.values[0])) return false; break;
      case 'between': if (!(v >= p.values[0] && v <= p.values[1])) return false; break;
      case 'contains': if (typeof v !== 'string' || !v.includes(String(p.values[0]))) return false; break;
      default: return false;
    }
  }
  return true;
}

function metricAccumulator(metricDef) {
  if (metricDef.kind === 'count') return { count: 0 };
  if (metricDef.kind === 'sum') return { sum: 0 };
  if (metricDef.kind === 'count_distinct') return { set: new Set() };
  return null;
}

function accumulate(acc, metricDef, row) {
  const field = metricDef.definition.field;
  if (metricDef.kind === 'count') acc.count += 1;
  else if (metricDef.kind === 'sum') {
    const base = row[field] ?? 0;
    acc.sum += base;
    if (metricDef.definition.minusField) acc.sum -= row[metricDef.definition.minusField] ?? 0;
  } else if (metricDef.kind === 'count_distinct') acc.set.add(row[field]);
}

function finalizeRaw(acc, metricDef) {
  if (metricDef.kind === 'count') return acc.count;
  if (metricDef.kind === 'sum') return acc.sum;
  if (metricDef.kind === 'count_distinct') return acc.set.size;
  return null;
}

function resolveMetrics(doc, metricIds) {
  // Expand ratios into their base metrics so one pass over rows is enough.
  const base = new Map();
  const ratios = new Map();
  const visit = (id) => {
    const def = doc.metrics.find((m) => m.id === id);
    if (!def) return;
    if (def.kind === 'ratio') {
      if (!ratios.has(id)) ratios.set(id, def);
      const num = def.definition.numeratorMetric ?? def.definition.numerator;
      const den = def.definition.denominatorMetric ?? def.definition.denominator;
      visit(num); visit(den);
    } else if (!base.has(id)) {
      base.set(id, def);
    }
  };
  for (const id of metricIds) visit(id);
  return { base: [...base.values()], ratios: [...ratios.values()] };
}

function gatherBuckets(rows, intent, doc) {
  const { base, ratios } = resolveMetrics(doc, intent.metrics.map((m) => m.id));
  const buckets = new Map();
  const group = intent.group;
  const add = (key, label, row) => {
    if (!buckets.has(key)) {
      const accs = new Map();
      for (const def of base) accs.set(def.id, metricAccumulator(def));
      buckets.set(key, { key, label, accs, order: buckets.size, cohort: 0 });
    }
    const bucket = buckets.get(key);
    bucket.cohort += 1;
    for (const def of base) accumulate(bucket.accs.get(def.id), def, row);
  };
  const allAccs = new Map();
  for (const def of base) allAccs.set(def.id, metricAccumulator(def));

  for (const row of rows) {
    for (const def of base) accumulate(allAccs.get(def.id), def, row);
    if (group) {
      if (group.kind === 'field') add(String(row[doc.fields.find((f) => f.id === group.field).column] ?? '（空）'), String(row[doc.fields.find((f) => f.id === group.field).column] ?? '（空）'), row);
      else add(grainKey(row.order_date, group.grain), grainKey(row.order_date, group.grain), row);
    }
  }

  const computeMetrics = (accs) => {
    const values = {};
    for (const [id, acc] of accs) values[id] = finalizeRaw(acc, base.find((b) => b.id === id));
    for (const def of ratios) {
      const numId = def.definition.numeratorMetric ?? def.definition.numerator;
      const denId = def.definition.denominatorMetric ?? def.definition.denominator;
      const n = values[numId] ?? 0;
      const d = values[denId] ?? 0;
      values[def.id] = d === 0 ? null : n / d;
    }
    return values;
  };

  const totals = computeMetrics(allAccs);

  const list = [...buckets.values()].map((bucket) => ({ key: bucket.key, label: bucket.label, values: computeMetrics(bucket.accs), order: bucket.order, cohortSize: bucket.cohort }));
  return { rows: list, totals };
}

function roundMetric(value, metricDef) {
  if (value === null || value === undefined) return null;
  if (metricDef.kind === 'count' || metricDef.kind === 'count_distinct') return Math.round(value);
  if (metricDef.unit === '%') return Math.round(value * 10000) / 10000;
  if (metricDef.kind === 'ratio' && metricDef.unit === '元') return Math.round(value) / 100;
  return Math.round(value) / 100;
}

function displayMetric(value, metricDef) {
  if (value === null) return '—';
  if (metricDef.unit === '%') return `${(value * 100).toFixed(1)}%`;
  if (metricDef.kind === 'count' || metricDef.kind === 'count_distinct') return String(Math.round(value));
  const n = roundMetric(value, metricDef);
  return n.toLocaleString('zh-CN', { maximumFractionDigits: 2 });
}

export function executeIntent({ snapshot, role, intent, partitions, policy, now, queryId }) {
  const doc = snapshot.doc;
  const start = intent.time.start;
  const end = intent.time.end;
  const rows = [];
  const usedPartitions = [];
  for (const part of partitions) {
    usedPartitions.push({ month: part.month, rowCount: part.rowCount, contentHash: part.contentHash });
    for (const row of part.rows) {
      if (row.order_date < start || row.order_date > end) continue;
      rows.push(row);
    }
  }
  const preds = compilePredicates(intent, policy.appliedScopes ?? []);
  const filtered = rows.filter((row) => rowMatches(row, preds));
  const { rows: grouped, totals } = gatherBuckets(filtered, intent, doc);

  const metricDefs = intent.metrics.map((m) => doc.metrics.find((x) => x.id === m.id));
  const sort = intent.sort;
  if (sort && grouped.length > 1) {
    grouped.sort((a, b) => {
      let av; let bv;
      if (sort.by === 'metric') { av = a.values[sort.metric]; bv = b.values[sort.metric]; }
      else { av = a.key; bv = b.key; }
      if (av === null) return 1;
      if (bv === null) return -1;
      const cmp = typeof av === 'string' ? (av < bv ? -1 : av > bv ? 1 : 0) : av - bv;
      return sort.direction === 'asc' ? cmp : -cmp;
    });
  } else if (sort?.by === 'group' && intent.group?.kind === 'time') {
    grouped.sort((a, b) => (grainSortKey(a.key, intent.group.grain) < grainSortKey(b.key, intent.group.grain) ? -1 : 1));
  }

  // Small-cohort suppression: a group of fewer than N underlying orders is not
  // shown, and totals over small cohorts are withheld as well.
  const minCohort = policy.role?.minCohort ?? 0;
  let suppressed = 0;
  let outputRows;
  if (intent.group) {
    outputRows = grouped.map((g) => ({ ...g }));
    const small = outputRows.filter((g) => g.cohortSize < minCohort);
    if (minCohort > 0) {
      for (const g of small) { g.suppressed = true; g.values = Object.fromEntries(metricDefs.map((d) => [d.id, null])); suppressed += 1; }
    }
    if (intent.limit) outputRows = outputRows.slice(0, intent.limit);
    // Do not let totals disclose what an individual suppressed row hides.
    if (minCohort > 0 && small.length && intent.metrics.some((m) => m.id === 'unique_customers')) {
      totals.__cohortSuppressed = true;
    }
    for (const key of Object.keys(totals)) if (key.startsWith('__')) delete totals[key];
  } else {
    outputRows = [{ key: '总计', label: '总计', values: totals }];
  }

  const formatted = outputRows.map((g) => ({
    group: g.label,
    groupKey: g.key,
    metrics: Object.fromEntries(metricDefs.map((d) => [d.id, {
      id: d.id,
      label: d.label,
      value: roundMetric(g.values[d.id], d),
      display: displayMetric(g.values[d.id], d),
      unit: d.unit,
    }])),
    ...(g.suppressed ? { suppressed: true } : {}),
  }));

  const totalRowCount = filtered.length;
  const coverage = {
    queriedStart: start,
    queriedEnd: end,
    days: daysBetween(start, end) + 1,
    partitions: usedPartitions,
    sourceRowsScanned: rows.length,
    sourceRowsMatched: totalRowCount,
  };

  return {
    columns: [
      ...(intent.group ? [{ id: 'group', label: intent.group.kind === 'time' ? `时间(${intent.group.label})` : intent.group.label, type: 'dimension' }] : []),
      ...metricDefs.map((d) => ({ id: d.id, label: d.label, unit: d.unit, type: 'metric' })),
    ],
    rows: formatted,
    totals: Object.fromEntries(metricDefs.map((d) => [d.id, { value: roundMetric(totals[d.id], d), display: displayMetric(totals[d.id], d), unit: d.unit }])),
    truncated: Boolean(intent.limit && grouped.length > intent.limit),
    groupsBeforeLimit: grouped.length,
    suppressedGroups: suppressed,
    minCohort,
    coverage,
    rowCount: formatted.length,
    queryId,
    executedAt: (now instanceof Date ? now : new Date(now)).toISOString(),
  };
}

export function buildEvidence({ snapshot, roleId, intent, parse, authorization, result, dataCoverage, asOf, queryId, executedAt }) {
  const doc = snapshot.doc;
  const metricDefs = intent.metrics.map((m) => doc.metrics.find((x) => x.id === m.id));
  const filterDefs = intent.filters.map((f) => {
    const def = doc.fields.find((x) => x.id === f.field);
    return {
      field: f.field,
      fieldLabel: f.fieldLabel,
      column: f.column,
      type: f.type,
      op: f.op,
      values: f.values,
      displayValues: f.type === 'number' ? f.rawValues ?? f.values : f.values,
      registryPointer: def ? `/fields/${def.id}` : null,
      description: def?.description ?? '',
    };
  });
  const groupDef = intent.group ? (intent.group.kind === 'field'
    ? { kind: 'field', field: intent.group.field, label: intent.group.label, pointer: intent.group.pointer, column: doc.fields.find((f) => f.id === intent.group.field)?.column }
    : { kind: 'time', grain: intent.group.grain, label: intent.group.label, pointer: intent.group.pointer, sourceField: 'order_date' }) : null;

  const scope = (authorization.appliedScopes ?? []).map((s) => ({ ...s }));
  const role = doc.roles[roleId];

  return {
    schema: 'rulegate.evidence/v1',
    queryId,
    generatedAt: executedAt,
    registry: {
      label: snapshot.meta.label,
      registryVersion: snapshot.meta.registryVersion,
      publishedAt: snapshot.meta.publishedAt,
      publishedBy: snapshot.meta.publishedBy,
      hashAlgorithm: 'sha256/canonical-json',
    },
    role: { id: roleId, label: role.label, rowScope: role.rowScope ?? {}, maxRangeDays: role.maxRangeDays, minCohort: role.minCohort },
    authorization: {
      result: 'allowed',
      appliedScopes: scope,
      checks: [
        'metrics ⊆ role.allowedMetrics',
        'filter fields ⊆ role.allowedFields',
        'filter ops ⊆ role.allowedOps',
        'rowScope containment',
        'rangeDays ≤ role.maxRangeDays',
        'limit ≤ role.maxLimit',
      ],
    },
    parse: {
      normalizedText: parse.normalizedText,
      mappings: parse.mappings,
      asOf: parse.asOf,
      warnings: parse.warnings,
    },
    intent: {
      metrics: metricDefs.map((d) => ({ id: d.id, label: d.label, kind: d.kind, unit: d.unit, pointer: `/metrics/${d.id}`, description: d.description })),
      filters: filterDefs,
      group: groupDef,
      time: { start: intent.time.start, end: intent.time.end, source: intent.time.source, raw: intent.time.raw },
      sort: intent.sort,
      limit: intent.limit,
    },
    data: {
      dataset: 'orders',
      calendar: 'UTC',
      coverage: dataCoverage,
      partitions: result.coverage.partitions,
      sourceRowsScanned: result.coverage.sourceRowsScanned,
      sourceRowsMatched: result.coverage.sourceRowsMatched,
      partitionsHash: sha256(result.coverage.partitions),
    },
    result: {
      rowCount: result.rowCount,
      groupsBeforeLimit: result.groupsBeforeLimit,
      truncated: result.truncated,
      suppressedGroups: result.suppressedGroups,
      minCohort: result.minCohort,
      outputHash: sha256(canonicalJson(result.rows)),
    },
  };
}

export function hashIntent(intent) {
  return sha256(canonicalJson(intent));
}

export { grainKey };
