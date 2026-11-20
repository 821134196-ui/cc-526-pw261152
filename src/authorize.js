import { daysBetween } from './util.js';

/*
 * Authorization happens after parsing and before execution.
 *
 * A parsed intent is only a proposal. Every referenced metric, field, operator,
 * range and limit is re-checked against the *pinned* role definition. Row-level
 * scope is applied in SQL-like predicate form and recorded as evidence.
 */

export class PolicyViolation {
  constructor(code, message, extra = {}) {
    this.code = code;
    this.message = message;
    this.hint = extra.hint ?? null;
    this.detail = extra.detail ?? null;
    this.stage = 'authorize';
  }
  toJSON() {
    return { code: this.code, title: TITLES[this.code] ?? '权限校验失败', message: this.message, hint: this.hint, detail: this.detail, stage: this.stage, span: null, suggestions: [] };
  }
}

const TITLES = {
  ROLE_UNKNOWN: '角色未登记',
  METRIC_NOT_GRANTED: '指标未授权',
  FIELD_NOT_GRANTED: '字段未授权',
  OP_NOT_ALLOWED: '操作符未授权',
  SCOPE_VIOLATION: '超出数据行权限',
  RANGE_TOO_LONG: '时间窗超限',
  TIME_TOO_BROAD: '时间范围过宽',
  GROUP_DISABLED: '角色不可分组',
  SORT_DISABLED: '角色不可排序',
  SORT_INVALID: '排序条件非法',
  SORT_METRIC_NOT_SELECTED: '排序指标未选择',
  LIMIT_EXCEEDED: '条数超出上限',
  EXPORT_FORBIDDEN: '角色无导出权限',
  AUDIT_FORBIDDEN: '角色无审计读取权限',
  PUBLISH_FORBIDDEN: '角色无规则发布权限',
  REPLAY_FORBIDDEN: '角色无可复现权限',
};

export function effectiveScope(doc, roleId) {
  const role = doc.roles[roleId];
  if (!role) return null;
  const scope = {};
  for (const [fieldId, values] of Object.entries(role.rowScope ?? {})) {
    const field = doc.fields.find((f) => f.id === fieldId);
    if (!field) continue;
    const labels = values.map((v) => field.enum?.find((e) => e.value === v)?.value ?? v);
    scope[fieldId] = { column: field.column, label: field.label, values: [...values], labels };
  }
  return scope;
}

export function authorizeIntent({ snapshot, roleId, intent, policyWarnings = [] }) {
  const doc = snapshot.doc;
  const role = doc.roles[roleId];
  if (!role) return { ok: false, violations: [new PolicyViolation('ROLE_UNKNOWN', `角色 ${roleId} 未在规则 ${snapshot.meta.label} 中登记`, { hint: '请先切换为已登记角色。' })] };
  const violations = [];
  const appliedScopes = [];

  const metricSet = new Set(role.allowedMetrics);
  for (const m of intent.metrics) {
    const def = doc.metrics.find((x) => x.id === m.id);
    if (!def) { violations.push(new PolicyViolation('METRIC_NOT_GRANTED', `指标 ${m.id} 未在规则中登记`)); continue; }
    if (def.hidden) violations.push(new PolicyViolation('METRIC_NOT_GRANTED', `指标“${def.label}”为内部派生项，不可查询`));
    if (!metricSet.has(m.id)) violations.push(new PolicyViolation('METRIC_NOT_GRANTED', `角色“${role.label}”未被授予指标“${def.label}”`, { hint: `可用指标：${[...metricSet].map((id) => doc.metrics.find((x) => x.id === id)?.label ?? id).join('、')}` }));
  }

  const fieldSet = new Set(role.allowedFields);
  const opSet = new Set(role.allowedOps);
  for (const f of intent.filters) {
    const def = doc.fields.find((x) => x.id === f.field);
    if (!def) { violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `字段 ${f.field} 未在规则中登记`)); continue; }
    if (def.pii) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `PII 字段“${def.label}”禁止用于筛选`));
    if (!fieldSet.has(f.field)) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `角色“${role.label}”未被授予字段“${def.label}”`, { hint: `可用筛选字段：${[...fieldSet].map((id) => doc.fields.find((x) => x.id === id)?.label ?? id).join('、')}` }));
    if (!opSet.has(f.op)) violations.push(new PolicyViolation('OP_NOT_ALLOWED', `角色“${role.label}”未被授予操作符 ${f.op}`, { hint: `可用操作：${[...opSet].join(', ')}` }));
  }

  // Row scope: a filter on a scoped field must be a subset of the scope values.
  for (const [fieldId, scope] of Object.entries(role.rowScope ?? {})) {
    const def = doc.fields.find((f) => f.id === fieldId);
    const requested = intent.filters.filter((f) => f.field === fieldId);
    const scopeLabel = `${def?.label ?? fieldId}=${scope.join('、')}`;
    if (!requested.length) {
      appliedScopes.push({ source: 'role', field: fieldId, fieldLabel: def?.label ?? fieldId, column: def?.column ?? fieldId, op: 'in', values: scope, description: `角色“${role.label}”行级权限自动限定 ${scopeLabel}` });
      continue;
    }
    for (const f of requested) {
      if (f.op === 'eq' || f.op === 'in') {
        const outside = f.values.filter((v) => !scope.includes(v));
        if (outside.length) {
          violations.push(new PolicyViolation('SCOPE_VIOLATION', `筛选条件“${def.label}=${outside.join('、')}”超出角色“${role.label}”的数据范围（${scope.join('、')}）`, { hint: '请只查询授权范围内的数据，或使用具备跨区域权限的角色。' }));
        } else {
          appliedScopes.push({ source: 'query', field: fieldId, fieldLabel: def?.label ?? fieldId, column: def?.column ?? fieldId, op: 'in', values: f.values, description: `查询条件限定 ${def.label}=${f.values.join('、')}，已被角色范围覆盖` });
        }
      } else if (f.op === 'not_in' || f.op === 'neq') {
        const remaining = scope.filter((v) => !f.values.includes(v));
        if (!remaining.length) {
          violations.push(new PolicyViolation('SCOPE_VIOLATION', `排除条件清空了角色“${role.label}”的全部授权范围`, { hint: '该条件在授权范围内无数据可查。' }));
        } else {
          appliedScopes.push({ source: 'role', field: fieldId, fieldLabel: def?.label ?? fieldId, column: def?.column ?? fieldId, op: 'in', values: remaining, description: `角色范围 ${scope.join('、')} 扣除排除值后保留 ${remaining.join('、')}` });
        }
      } else {
        violations.push(new PolicyViolation('SCOPE_VIOLATION', `角色“${role.label}”的行级权限字段“${def.label}”不支持操作符 ${f.op}`, { hint: '行级权限字段仅支持等于/属于/排除。' }));
      }
    }
  }

  if (intent.group) {
    if (!role.canGroupBy) violations.push(new PolicyViolation('GROUP_DISABLED', `角色“${role.label}”不允许分组查询`));
    if (intent.group.kind === 'field') {
      const def = doc.fields.find((f) => f.id === intent.group.field);
      if (!def) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `分组字段 ${intent.group.field} 未登记`));
      else {
        if (def.pii) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `PII 字段“${def.label}”禁止分组`));
        if (def.groupable === false) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `字段“${def.label}”未登记为可分组`));
        if (!fieldSet.has(def.id)) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `角色“${role.label}”未被授予分组字段“${def.label}”`, { hint: `可用分组字段：${[...fieldSet].map((id) => doc.fields.find((x) => x.id === id)?.label ?? id).join('、')}` }));
      }
    } else if (intent.group.kind === 'time') {
      const def = doc.timeGrains.find((g) => g.grain === intent.group.grain || g.id === intent.group.id);
      if (!def) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `时间粒度 ${intent.group.grain} 未登记`));
      else if (!fieldSet.has(def.sourceField)) violations.push(new PolicyViolation('FIELD_NOT_GRANTED', `角色“${role.label}”未被授予时间分组（依赖 ${def.sourceField}）`));
    }
  }

  if (intent.sort) {
    if (!role.canSort) violations.push(new PolicyViolation('SORT_DISABLED', `角色“${role.label}”不允许排序`));
    if (intent.sort.by === 'metric') {
      if (!intent.metrics.some((m) => m.id === intent.sort.metric)) violations.push(new PolicyViolation('SORT_METRIC_NOT_SELECTED', '排序指标必须在本次查询所选指标之内'));
    } else if (intent.sort.by === 'group') {
      if (!intent.group) violations.push(new PolicyViolation('SORT_INVALID', '未分组时不能按分组键排序'));
    }
  }

  const days = daysBetween(intent.time.start, intent.time.end) + 1;
  if (days > role.maxRangeDays) {
    violations.push(new PolicyViolation('RANGE_TOO_LONG', `时间窗 ${days} 天超过角色“${role.label}”上限 ${role.maxRangeDays} 天`, { hint: `请缩小区间至 ${role.maxRangeDays} 天以内。` }));
  }

  const limit = intent.limit ?? role.defaultLimit;
  if (limit > role.maxLimit) {
    violations.push(new PolicyViolation('LIMIT_EXCEEDED', `条数 ${limit} 超过角色“${role.label}”上限 ${role.maxLimit}`, { hint: `请把条数限制在 ${role.maxLimit} 以内。` }));
  }

  if (violations.length) return { ok: false, violations, appliedScopes };

  return {
    ok: true,
    violations: [],
    role: { id: roleId, label: role.label, maxRangeDays: role.maxRangeDays, maxLimit: role.maxLimit, minCohort: role.minCohort, canExport: role.canExport },
    appliedScopes,
    limit,
    days,
    warnings: policyWarnings,
  };
}
