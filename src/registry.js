import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson, sha256, deepFreeze, clone, normalizeForMatch } from './util.js';

/*
 * Rule registry
 * ------------
 * A rule version is an immutable, content-addressed snapshot describing every
 * field, metric, role and operation the query language is allowed to touch.
 * Nothing outside this registry can be addressed by a query.
 *
 * Query execution always uses a pinned snapshot. Replays therefore keep the
 * same vocabulary and authorization semantics even after newer rules ship.
 */

export const FILTER_OPS = ['eq', 'neq', 'in', 'not_in', 'gt', 'gte', 'lt', 'lte', 'between', 'contains'];
export const FIELD_TYPES = ['id', 'string', 'enum', 'date', 'number', 'boolean'];
export const METRIC_KINDS = ['sum', 'count', 'count_distinct', 'ratio'];
export const TIME_GRAINS = ['day', 'week', 'month', 'quarter', 'year'];

const FIELD_ID = /^[a-z][a-z0-9_]{1,39}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function field(id, label, column, type, opts = {}) {
  return {
    id,
    label,
    table: 'orders',
    column,
    type,
    semantic: opts.semantic ?? 'dimension',
    description: opts.description ?? '',
    aliases: opts.aliases ?? [],
    filterable: opts.filterable ?? type !== 'id',
    groupable: opts.groupable ?? (type === 'enum' || type === 'date'),
    pii: opts.pii ?? false,
    operators: opts.operators ?? defaultOps(type),
    ...(opts.enum ? { enum: opts.enum } : {}),
    ...(opts.scale !== undefined ? { scale: opts.scale } : {}),
    ...(opts.unit ? { unit: opts.unit } : {}),
  };
}

function defaultOps(type) {
  if (type === 'enum' || type === 'boolean') return ['eq', 'neq', 'in', 'not_in'];
  if (type === 'number' || type === 'date') return ['eq', 'neq', 'in', 'not_in', 'gt', 'gte', 'lt', 'lte', 'between'];
  if (type === 'string') return ['eq', 'neq', 'in', 'not_in', 'contains'];
  return ['eq', 'neq'];
}

const enumDef = (values) => values.map(([value, ...aliases]) => ({ value, aliases }));

const CORE_FIELDS = [
  field('order_id', '订单号', 'order_id', 'id', {
    description: '订单唯一标识（不可分组、不可筛选）',
    groupable: false,
    filterable: false,
    aliases: ['订单号', '单号'],
  }),
  field('order_date', '下单日期', 'order_date', 'date', {
    description: '订单日期（UTC 日历）',
    aliases: ['下单日期', '日期', '时间', '订单日期', 'date'],
    unit: 'date',
  }),
  field('region', '区域', 'region', 'enum', {
    description: '订单所属销售大区',
    aliases: ['区域', '大区', '地区', '销售区域', 'region'],
    enum: enumDef([
      ['华东', 'East China', '华东区'],
      ['华南', 'South China', '华南区'],
      ['华北', 'North China', '华北区'],
      ['西南', 'Southwest', '西南区'],
      ['西北', 'Northwest', '西北区'],
    ]),
  }),
  field('channel', '渠道', 'channel', 'enum', {
    description: '订单来源渠道',
    aliases: ['渠道', '销售渠道', '通路', 'channel'],
    enum: enumDef([
      ['直营', 'Direct'],
      ['分销', 'Reseller'],
      ['电商', 'Ecommerce', '线上'],
      ['线下门店', 'Offline'],
    ]),
  }),
  field('product_category', '品类', 'product_category', 'enum', {
    description: '商品所属品类',
    aliases: ['品类', '商品类别', '类目', 'category'],
    enum: enumDef([
      ['数码', 'Digital'],
      ['家电', 'Appliance'],
      ['服饰', 'Apparel'],
      ['美妆', 'Beauty'],
      ['食品', 'Grocery'],
      ['其他', 'Other'],
    ]),
  }),
  field('amount', '订单金额', 'amount', 'number', {
    description: '订单含税金额（分）',
    aliases: ['订单金额', '金额', 'amount'],
    groupable: false,
    scale: 2,
    unit: '元',
    filterable: true,
  }),
  field('quantity', '数量', 'quantity', 'number', {
    description: '订单商品件数',
    aliases: ['数量', 'quantity'],
    groupable: false,
    unit: '件',
    filterable: true,
  }),
];

const EXTENDED_FIELDS = [
  field('customer_segment', '客户类型', 'customer_segment', 'enum', {
    description: '下单客户分层',
    aliases: ['客户类型', '客群', '人群', '客户分层', 'segment'],
    enum: enumDef([
      ['新客', 'New'],
      ['老客', 'Returning'],
      ['会员', 'Member'],
      ['企业', 'Enterprise'],
      ['未分层', 'Unsegmented'],
    ]),
  }),
  field('store', '门店', 'store', 'enum', {
    description: '下单门店（线上订单记为空）',
    aliases: ['店铺', 'store'],
    enum: enumDef([
      ['旗舰店', 'Flagship'],
      ['社区店', 'Community'],
      ['云店', 'Cloud'],
    ]),
  }),
  field('cost', '成本', 'cost', 'number', {
    description: '订单成本（分），仅用于派生指标',
    aliases: ['成本'],
    groupable: false,
    filterable: false,
    scale: 2,
    unit: '元',
  }),
  field('discount', '优惠金额', 'discount', 'number', {
    description: '订单优惠金额（分）',
    aliases: ['优惠金额'],
    groupable: false,
    scale: 2,
    unit: '元',
    filterable: true,
  }),
  field('refund_amount', '退款金额', 'refund_amount', 'number', {
    description: '订单退款金额（分）',
    aliases: ['退款金额'],
    groupable: false,
    scale: 2,
    unit: '元',
    filterable: true,
  }),
  field('customer_id', '客户编号', 'customer_id', 'string', {
    description: '客户唯一标识（PII，仅允许聚合客户数）',
    aliases: ['客户编号'],
    pii: true,
    filterable: false,
    groupable: false,
  }),
  field('email', '邮箱', 'email', 'string', {
    description: '客户邮箱（PII，禁止查询）',
    aliases: ['邮箱'],
    pii: true,
    filterable: false,
    groupable: false,
  }),
  field('phone', '手机号', 'phone', 'string', {
    description: '客户手机号（PII，禁止查询）',
    aliases: ['手机号', '电话'],
    pii: true,
    filterable: false,
    groupable: false,
  }),
];

const GRAINS = [
  { id: 'day', label: '天', grain: 'day', sourceField: 'order_date', description: '按下单日期汇总', aliases: ['天', '日', '每天', '每日', '按天', '按日', '各天'] },
  { id: 'month', label: '月', grain: 'month', sourceField: 'order_date', description: '按下单月份汇总', aliases: ['月', '月份', '按月'] },
  { id: 'quarter', label: '季度', grain: 'quarter', sourceField: 'order_date', description: '按下单季度汇总', aliases: ['季度', '按季度'] },
  { id: 'year', label: '年', grain: 'year', sourceField: 'order_date', description: '按下单年份汇总', aliases: ['年', '年份', '按年'] },
];

function metric(id, label, aliases, kind, definition, extra = {}) {
  return { id, label, aliases, kind, definition, unit: extra.unit ?? '元', description: extra.description ?? '', ...extra };
}

const CORE_METRICS = [
  metric('revenue', '销售额', ['销售额', '营收', '收入', '营业额'], 'sum', { field: 'amount' }, {
    unit: '元', description: '订单金额合计（扣除优惠前）', higherIsBetter: true,
  }),
  metric('orders', '订单数', ['订单数', '订单量', '单量', '订单'], 'count', { field: 'order_id' }, {
    unit: '单', description: '订单条数', higherIsBetter: true,
  }),
  metric('units', '销量', ['销量', '销售件数', '件数'], 'sum', { field: 'quantity' }, {
    unit: '件', description: '商品件数合计', higherIsBetter: true,
  }),
  metric('aov', '客单价', ['客单价', '平均订单金额', '均价'], 'ratio', { numerator: 'revenue', denominator: 'orders' }, {
    unit: '元', description: '销售额 / 订单数', higherIsBetter: true,
  }),
];

const EXTENDED_METRICS_V2 = [
  metric('gross_profit_amount', '毛利额', ['毛利额'], 'sum', { field: 'amount', minusField: 'cost' }, {
    unit: '元', description: '订单金额减去成本', higherIsBetter: true,
  }),
  metric('gross_margin', '毛利率', ['毛利率', '业绩'], 'ratio', {
    numeratorMetric: 'gross_profit_amount', denominatorMetric: 'revenue',
  }, { unit: '%', description: '毛利额 / 销售额', higherIsBetter: true }),
  metric('unique_customers', '客户数', ['客户数', '买家数', '去重客户数'], 'count_distinct', { field: 'customer_id' }, {
    unit: '人', description: '去重客户数（PII 的安全聚合口径）', higherIsBetter: true,
  }),
  metric('refund_rate', '退款率', ['退款率'], 'ratio', { numerator: 'refunded_amount', denominator: 'revenue' }, {
    unit: '%', description: '退款金额 / 销售额', higherIsBetter: false,
  }),
  metric('refunded_amount', '退款金额合计', ['退款金额合计'], 'sum', { field: 'refund_amount' }, {
    unit: '元', description: '内部派生项，不直接展示', hidden: true,
  }),
  metric('discount_amount', '优惠金额', ['优惠金额合计', '折扣金额'], 'sum', { field: 'discount' }, {
    unit: '元', description: '优惠金额合计', higherIsBetter: false,
  }),
];

function role(id, label, cfg) {
  return {
    id,
    label,
    description: cfg.description ?? '',
    allowedMetrics: cfg.allowedMetrics,
    allowedFields: cfg.allowedFields,
    allowedOps: cfg.allowedOps ?? FILTER_OPS.filter((op) => op !== 'contains'),
    rowScope: cfg.rowScope ?? {},
    maxRangeDays: cfg.maxRangeDays ?? 90,
    defaultRangeDays: cfg.defaultRangeDays ?? 30,
    defaultLimit: cfg.defaultLimit ?? 50,
    maxLimit: cfg.maxLimit ?? 200,
    canExport: cfg.canExport ?? false,
    minCohort: cfg.minCohort ?? 0,
    canGroupBy: cfg.canGroupBy ?? true,
    canSort: cfg.canSort ?? true,
    auditRead: cfg.auditRead ?? false,
    canPublish: cfg.canPublish ?? false,
    canReplay: cfg.canReplay ?? true,
  };
}

const ANALYST_FIELDS = ['order_date', 'region', 'channel', 'product_category', 'amount', 'quantity', 'order_id'];

const PII_IDS = new Set(['customer_id', 'email', 'phone']);

function baseRoles(fields, metrics) {
  return {
    analyst: role('analyst', '数据分析师', {
      description: '全区域分析，可导出聚合结果，不可查看 PII。',
      allowedMetrics: metrics,
      allowedFields: fields,
      maxRangeDays: 400,
      defaultRangeDays: 90,
      defaultLimit: 100,
      maxLimit: 500,
      canExport: true,
      auditRead: false,
    }),
    sales_west: role('sales_west', '华东销售', {
      description: '仅华东数据；结果不可导出；单次时间窗 90 天。',
      allowedMetrics: ['revenue', 'orders', 'aov', 'units'],
      allowedFields: ['order_date', 'region', 'channel'],
      rowScope: { region: ['华东'] },
      maxRangeDays: 90,
      defaultRangeDays: 30,
      defaultLimit: 20,
      maxLimit: 100,
      canExport: false,
      minCohort: 5,
    }),
    sales_east: role('sales_east', '华南销售', {
      description: '仅华南数据；结果不可导出；单次时间窗 90 天。',
      allowedMetrics: ['revenue', 'orders', 'aov', 'units'],
      allowedFields: ['order_date', 'region', 'channel'],
      rowScope: { region: ['华南'] },
      maxRangeDays: 90,
      defaultRangeDays: 30,
      defaultLimit: 20,
      maxLimit: 50,
      canExport: false,
      minCohort: 5,
    }),
    auditor: role('auditor', '审计员', {
      description: '只读全量聚合与审计流水，可导出审计报告。',
      allowedMetrics: metrics,
      allowedFields: fields.filter((f) => !PII_IDS.has(f)),
      maxRangeDays: 400,
      defaultRangeDays: 90,
      defaultLimit: 200,
      maxLimit: 1000,
      canExport: true,
      auditRead: true,
    }),
    rules_admin: role('rules_admin', '规则管理员', {
      description: '维护登记表并发布规则版本。',
      allowedMetrics: metrics,
      allowedFields: fields.filter((f) => !PII_IDS.has(f)),
      maxRangeDays: 400,
      defaultRangeDays: 90,
      defaultLimit: 200,
      maxLimit: 1000,
      canExport: true,
      auditRead: true,
      canPublish: true,
    }),
  };
}

function baseDoc(label, publishedAt, notes, fields, metrics) {
  return {
    schemaVersion: 1,
    label,
    publishedAt,
    notes,
    calendar: { timezone: 'UTC' },
    tables: {
      orders: {
        description: '订单事实表（合成数据）',
        columns: ['order_id', 'order_date', 'region', 'channel', 'product_category', 'customer_segment', 'store', 'amount', 'cost', 'discount', 'refund_amount', 'quantity', 'customer_id', 'email', 'phone'],
      },
    },
    fields,
    timeGrains: GRAINS.filter((g) => fields.some((f) => f.id === g.sourceField)),
    metrics,
    roles: baseRoles(fields.map((f) => f.id), metrics.filter((m) => !m.hidden).map((m) => m.id)),
  };
}

function buildSeedVersions() {
  const v1Fields = CORE_FIELDS;
  const v1 = baseDoc('v1', '2026-08-01T02:00:00.000Z', '初始登记：核心销售字段与指标。', v1Fields, CORE_METRICS);

  const v2Fields = [...CORE_FIELDS, ...EXTENDED_FIELDS];
  const v2Metrics = [
    { ...CORE_METRICS[0], aliases: [...CORE_METRICS[0].aliases, '业绩'] },
    CORE_METRICS[1],
    CORE_METRICS[2],
    CORE_METRICS[3],
    ...EXTENDED_METRICS_V2,
  ];
  const v2 = baseDoc('v2', '2026-09-15T09:00:00.000Z', '新增毛利、退款率、客户数与客户分层；引入“业绩”双口径。', v2Fields, v2Metrics);
  v2.roles = baseRoles(v2Fields.map((f) => f.id), v2Metrics.filter((m) => !m.hidden).map((m) => m.id));
  v2.roles.sales_west.allowedMetrics = ['revenue', 'orders', 'aov', 'units', 'gross_margin'];
  v2.roles.sales_east.allowedMetrics = ['revenue', 'orders', 'aov', 'units', 'gross_margin'];
  v2.roles.analyst.allowedFields = [...ANALYST_FIELDS, 'customer_segment', 'store', 'discount', 'refund_amount'];
  v2.roles.sales_west.allowedFields = ['order_date', 'region', 'channel'];
  v2.roles.sales_east.allowedFields = ['order_date', 'region', 'channel'];
  v2.acknowledgedAmbiguities = ['业绩'];

  const v3Fields = clone(v2Fields);
  const v3Metrics = clone(v2Metrics);
  v3Metrics[0] = { ...v3Metrics[0], aliases: v3Metrics[0].aliases.filter((a) => a !== '业绩').concat('流水') };
    const v3 = baseDoc('v3', '2026-11-01T02:00:00.000Z', '消解“业绩”歧义（仅指毛利）；新增“流水”别名；华东/华南时间窗收紧至 180 天。', v3Fields, v3Metrics);
  v3.roles = clone(v2.roles);
  v3.roles.sales_west = { ...v3.roles.sales_west, maxRangeDays: 180 };
  v3.roles.sales_east = { ...v3.roles.sales_east, maxRangeDays: 180 };
  v3.acknowledgedAmbiguities = [];

  return [v1, v2, v3];
}

/* ------------------------------------------------------------------ */
/* Validation                                                          */
/* ------------------------------------------------------------------ */

function normalizeAlias(alias) {
  return normalizeForMatch(alias);
}

export function computeAmbiguities(doc) {
  const byTerm = new Map();
  const add = (term, target) => {
    const key = normalizeAlias(term);
    if (!key) return;
    if (!byTerm.has(key)) byTerm.set(key, { term, targets: [] });
    byTerm.get(key).targets.push(target);
  };
  for (const m of doc.metrics ?? []) {
    for (const alias of m.aliases ?? []) add(alias, { kind: 'metric', id: m.id, label: m.label, pointer: `/metrics/${m.id}/aliases` });
  }
  for (const f of doc.fields ?? []) {
    for (const alias of f.aliases ?? []) add(alias, { kind: 'field', id: f.id, label: f.label, pointer: `/fields/${f.id}/aliases` });
    for (const value of f.enum ?? []) {
      for (const alias of [value.value, ...(value.aliases ?? [])]) {
        add(alias, { kind: 'enum', id: f.id, label: `${f.label}=${value.value}`, value: value.value, pointer: `/fields/${f.id}/enum/${value.value}` });
      }
    }
  }
  return [...byTerm.values()]
    .filter((entry) => {
      const keys = new Set(entry.targets.map((t) => `${t.kind}:${t.id}:${t.value ?? ''}`));
      return keys.size > 1;
    })
    .map((entry) => ({ term: entry.term, targets: entry.targets }));
}

export function validateRuleDoc(doc) {
  const errors = [];
  const warn = [];
  const err = (code, at, message) => errors.push({ code, path: at, message });

  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    err('DOC_INVALID', '/', '规则文档必须是 JSON 对象');
    return { ok: false, errors, warnings: warn, ambiguities: [] };
  }
  if (doc.schemaVersion !== 1) err('SCHEMA_VERSION', '/schemaVersion', '仅支持 schemaVersion=1');
  if (typeof doc.label !== 'string' || !/^v\d+$/.test(doc.label)) err('LABEL_INVALID', '/label', '版本标签必须形如 v1、v2');
  if (typeof doc.publishedAt !== 'string' || !ISO.test(doc.publishedAt)) err('PUBLISHED_AT_INVALID', '/publishedAt', 'publishedAt 必须是 UTC ISO 时间');
  if (typeof doc.notes !== 'string') err('NOTES_INVALID', '/notes', 'notes 必须是字符串');
  if (!doc.calendar || doc.calendar.timezone !== 'UTC') err('CALENDAR_INVALID', '/calendar', '仅支持 UTC 日历');

  const fields = Array.isArray(doc.fields) ? doc.fields : null;
  const metrics = Array.isArray(doc.metrics) ? doc.metrics : null;
  if (!fields) err('FIELDS_INVALID', '/fields', 'fields 必须是数组');
  if (!metrics) err('METRICS_INVALID', '/metrics', 'metrics 必须是数组');
  if (!fields || !metrics) return { ok: false, errors, warnings: warn, ambiguities: [] };

  const fieldById = new Map();
  for (const [i, f] of fields.entries()) {
    const at = `/fields/${i}`;
    if (!f || typeof f !== 'object') { err('FIELD_INVALID', at, '字段定义必须是对象'); continue; }
    if (!FIELD_ID.test(f.id ?? '')) err('FIELD_ID_INVALID', `${at}/id`, '字段 id 必须匹配 ^[a-z][a-z0-9_]{1,39}$');
    if (fieldById.has(f.id)) err('FIELD_DUPLICATE', `${at}/id`, `字段 id 重复：${f.id}`);
    fieldById.set(f.id, f);
    if (typeof f.label !== 'string' || !f.label.trim()) err('FIELD_LABEL_INVALID', `${at}/label`, '字段 label 不能为空');
    if (!FIELD_TYPES.includes(f.type)) err('FIELD_TYPE_INVALID', `${at}/type`, `不支持的字段类型：${f.type}`);
    if (typeof f.column !== 'string' || !/^[a-z][a-z0-9_]{1,39}$/.test(f.column)) err('FIELD_COLUMN_INVALID', `${at}/column`, 'column 非法');
    if (typeof f.pii !== 'boolean') err('FIELD_PII_INVALID', `${at}/pii`, 'pii 必须是布尔值');
    if (!Array.isArray(f.aliases) || f.aliases.length === 0) err('FIELD_ALIASES_INVALID', `${at}/aliases`, '至少需要一个别名');
    else {
      const seen = new Set();
      for (const [j, alias] of f.aliases.entries()) {
        if (typeof alias !== 'string' || !alias.trim()) err('FIELD_ALIAS_INVALID', `${at}/aliases/${j}`, '别名必须是非空字符串');
        else if (seen.has(normalizeAlias(alias))) err('FIELD_ALIAS_DUPLICATE', `${at}/aliases/${j}`, `同一字段内别名重复：${alias}`);
        else seen.add(normalizeAlias(alias));
      }
    }
    if (!Array.isArray(f.operators) || f.operators.some((op) => !FILTER_OPS.includes(op))) err('FIELD_OPS_INVALID', `${at}/operators`, 'operators 含未登记操作');
    if (f.type === 'enum') {
      if (!Array.isArray(f.enum) || f.enum.length === 0) err('FIELD_ENUM_INVALID', `${at}/enum`, '枚举字段必须登记取值');
      else {
        const values = new Set();
        for (const [j, v] of f.enum.entries()) {
          if (!v || typeof v.value !== 'string' || !v.value.trim()) err('ENUM_VALUE_INVALID', `${at}/enum/${j}`, '枚举取值必须是非空字符串');
          else if (values.has(v.value)) err('ENUM_VALUE_DUPLICATE', `${at}/enum/${j}`, `枚举取值重复：${v.value}`);
          else values.add(v.value);
          if (v && v.aliases !== undefined && !Array.isArray(v.aliases)) err('ENUM_ALIASES_INVALID', `${at}/enum/${j}/aliases`, '枚举别名必须是数组');
        }
      }
      if (f.pii) warn.push({ code: 'PII_ENUM', path: at, message: 'PII 字段一般不应分组或筛选' });
      if (f.groupable) { /* ok */ }
    }
    if (f.pii && f.groupable) err('PII_GROUPABLE', `${at}/groupable`, 'PII 字段不得登记为可分组');
    if (f.pii && f.filterable) err('PII_FILTERABLE', `${at}/filterable`, 'PII 字段不得登记为可筛选');
    if (typeof f.scale !== 'undefined' && (!Number.isInteger(f.scale) || f.scale < 0 || f.scale > 4)) err('FIELD_SCALE_INVALID', `${at}/scale`, 'scale 必须是 0-4 的整数');
  }

  const metricById = new Map();
  for (const [i, m] of metrics.entries()) {
    const at = `/metrics/${i}`;
    if (!m || typeof m !== 'object') { err('METRIC_INVALID', at, '指标定义必须是对象'); continue; }
    if (!FIELD_ID.test(m.id ?? '')) err('METRIC_ID_INVALID', `${at}/id`, '指标 id 非法');
    if (metricById.has(m.id)) err('METRIC_DUPLICATE', `${at}/id`, `指标 id 重复：${m.id}`);
    metricById.set(m.id, m);
    if (typeof m.label !== 'string' || !m.label.trim()) err('METRIC_LABEL_INVALID', `${at}/label`, '指标 label 不能为空');
    if (!METRIC_KINDS.includes(m.kind)) err('METRIC_KIND_INVALID', `${at}/kind`, `不支持的聚合类型：${m.kind}`);
    if (!Array.isArray(m.aliases) || m.aliases.length === 0) err('METRIC_ALIASES_INVALID', `${at}/aliases`, '至少需要一个别名');
    else {
      const seen = new Set();
      for (const [j, alias] of m.aliases.entries()) {
        if (typeof alias !== 'string' || !alias.trim()) err('METRIC_ALIAS_INVALID', `${at}/aliases/${j}`, '别名必须是非空字符串');
        else if (seen.has(normalizeAlias(alias))) err('METRIC_ALIAS_DUPLICATE', `${at}/aliases/${j}`, `同一指标内别名重复：${alias}`);
        else seen.add(normalizeAlias(alias));
      }
    }
    if (!m.definition || typeof m.definition !== 'object') err('METRIC_DEF_INVALID', `${at}/definition`, 'definition 必须是对象');
    else if (m.kind === 'sum' || m.kind === 'count' || m.kind === 'count_distinct') {
      const f = fieldById.get(m.definition.field);
      if (!f) err('METRIC_FIELD_UNKNOWN', `${at}/definition/field`, `指标引用了未登记字段：${m.definition.field}`);
      else {
        if (m.kind === 'sum' && f.type !== 'number') err('METRIC_FIELD_TYPE', `${at}/definition/field`, 'sum 指标必须引用数值字段');
        if (m.kind === 'count_distinct' && f.type !== 'string' && f.type !== 'id') err('METRIC_FIELD_TYPE', `${at}/definition/field`, 'count_distinct 指标必须引用字符串/标识字段');
      }
    } else if (m.kind === 'ratio') {
      const num = m.definition.numeratorMetric ?? m.definition.numerator;
      const den = m.definition.denominatorMetric ?? m.definition.denominator;
      for (const ref of [num, den]) {
        const target = metricById.get(ref) ?? metrics.find((x) => x.id === ref);
        if (!target) err('METRIC_RATIO_REF', `${at}/definition`, `比率指标引用了未登记指标：${ref}`);
      }
      if (num === den) err('METRIC_RATIO_SELF', `${at}/definition`, '比率指标的分子与分母不能相同');
    }
    if (m.hidden === true && !m.description) warn.push({ code: 'HIDDEN_METRIC_UNDOCUMENTED', path: at, message: '隐藏派生指标建议填写说明' });
    if (typeof m.hidden !== 'undefined' && typeof m.hidden !== 'boolean') err('METRIC_HIDDEN_INVALID', `${at}/hidden`, 'hidden 必须是布尔值');
  }
  for (const [i, m] of metrics.entries()) {
    if (m?.kind === 'ratio') {
      const num = m.definition?.numeratorMetric ?? m.definition?.numerator;
      const den = m.definition?.denominatorMetric ?? m.definition?.denominator;
      const numM = metricById.get(num);
      const denM = metricById.get(den);
      if (numM && numM.kind === 'ratio') err('METRIC_RATIO_NESTED', `/metrics/${i}/definition`, '比率指标不支持嵌套比率分子');
      if (denM && denM.kind === 'ratio') err('METRIC_RATIO_NESTED', `/metrics/${i}/definition`, '比率指标不支持嵌套比率分母');
    }
  }

  if (!Array.isArray(doc.timeGrains)) err('GRAINS_INVALID', '/timeGrains', 'timeGrains 必须是数组');
  else for (const [i, g] of doc.timeGrains.entries()) {
    const at = `/timeGrains/${i}`;
    const source = fieldById.get(g.sourceField);
    if (!source) err('GRAIN_SOURCE_UNKNOWN', `${at}/sourceField`, `时间粒度引用了未登记字段：${g.sourceField}`);
    else if (source.type !== 'date') err('GRAIN_SOURCE_TYPE', `${at}/sourceField`, '时间粒度必须引用日期字段');
    if (!TIME_GRAINS.includes(g.grain)) err('GRAIN_INVALID', `${at}/grain`, `不支持的时间粒度：${g.grain}`);
    if (!FIELD_ID.test(g.id ?? '')) err('GRAIN_ID_INVALID', `${at}/id`, '时间粒度 id 非法');
  }

  if (!doc.roles || typeof doc.roles !== 'object' || Array.isArray(doc.roles)) err('ROLES_INVALID', '/roles', 'roles 必须是对象');
  else for (const [id, r] of Object.entries(doc.roles)) {
    const at = `/roles/${id}`;
    if (!FIELD_ID.test(id)) err('ROLE_ID_INVALID', `${at}`, '角色 id 非法');
    if (typeof r.label !== 'string' || !r.label.trim()) err('ROLE_LABEL_INVALID', `${at}/label`, '角色 label 不能为空');
    if (!Array.isArray(r.allowedMetrics) || r.allowedMetrics.some((m) => !metricById.has(m))) err('ROLE_METRIC_UNKNOWN', `${at}/allowedMetrics`, '角色授权了未登记指标');
    if (!Array.isArray(r.allowedFields) || r.allowedFields.some((f) => !fieldById.has(f))) err('ROLE_FIELD_UNKNOWN', `${at}/allowedFields`, '角色授权了未登记字段');
    if (Array.isArray(r.allowedFields)) {
      for (const fid of r.allowedFields) {
        if (fieldById.get(fid)?.pii) err('PII_ROLE_GRANT', `${at}/allowedFields`, `不得向角色直接授权 PII 字段：${fid}`);
      }
    }
    if (!Array.isArray(r.allowedOps) || r.allowedOps.some((op) => !FILTER_OPS.includes(op))) err('ROLE_OPS_UNKNOWN', `${at}/allowedOps`, '角色授权了未登记操作');
    if (!Number.isInteger(r.maxRangeDays) || r.maxRangeDays < 1 || r.maxRangeDays > 3650) err('ROLE_RANGE_INVALID', `${at}/maxRangeDays`, 'maxRangeDays 必须是 1-3650 的整数');
    if (!Number.isInteger(r.defaultRangeDays) || r.defaultRangeDays < 1 || r.defaultRangeDays > r.maxRangeDays) err('ROLE_DEFAULT_RANGE_INVALID', `${at}/defaultRangeDays`, 'defaultRangeDays 必须在 1..maxRangeDays 之间');
    if (!Number.isInteger(r.defaultLimit) || r.defaultLimit < 1 || r.defaultLimit > r.maxLimit) err('ROLE_DEFAULT_LIMIT_INVALID', `${at}/defaultLimit`, 'defaultLimit 必须在 1..maxLimit 之间');
    if (!Number.isInteger(r.maxLimit) || r.maxLimit < 1 || r.maxLimit > 10000) err('ROLE_MAX_LIMIT_INVALID', `${at}/maxLimit`, 'maxLimit 必须是 1-10000 的整数');
    if (!Number.isInteger(r.minCohort) || r.minCohort < 0 || r.minCohort > 1000) err('ROLE_MIN_COHORT_INVALID', `${at}/minCohort`, 'minCohort 必须是 0-1000 的整数');
    for (const key of ['canExport', 'canGroupBy', 'canSort', 'auditRead', 'canPublish', 'canReplay']) {
      if (typeof r[key] !== 'boolean') err('ROLE_FLAG_INVALID', `${at}/${key}`, `${key} 必须是布尔值`);
    }
    if (!r.rowScope || typeof r.rowScope !== 'object' || Array.isArray(r.rowScope)) { err('ROLE_SCOPE_INVALID', `${at}/rowScope`, 'rowScope 必须是对象'); continue; }
    for (const [fid, values] of Object.entries(r.rowScope)) {
      const f = fieldById.get(fid);
      if (!f) { err('ROLE_SCOPE_FIELD_UNKNOWN', `${at}/rowScope/${fid}`, '行级权限引用了未登记字段'); continue; }
      if (f.type !== 'enum') { err('ROLE_SCOPE_FIELD_TYPE', `${at}/rowScope/${fid}`, '行级权限仅支持枚举字段'); continue; }
      if (!Array.isArray(values) || values.length === 0) { err('ROLE_SCOPE_VALUES', `${at}/rowScope/${fid}`, '行级权限取值不能为空'); continue; }
      const allowed = new Set((f.enum ?? []).map((v) => v.value));
      for (const v of values) if (!allowed.has(v)) err('ROLE_SCOPE_VALUE_UNKNOWN', `${at}/rowScope/${fid}`, `行级权限取值未登记：${v}`);
    }
  }

  // Cross-target alias collisions are allowed but must be acknowledged at publish.
  const ambiguities = computeAmbiguities(doc);
  const acked = new Set((doc.acknowledgedAmbiguities ?? []).map(normalizeAlias));
  for (const a of ambiguities) {
    if (!acked.has(normalizeAlias(a.term))) {
      warn.push({ code: 'AMBIGUITY_UNACKNOWLEDGED', path: '/', message: `别名“${a.term}”指向多个目标，发布时需显式确认`, term: a.term });
    }
  }

  return { ok: errors.length === 0, errors, warnings: warn, ambiguities };
}

/* ------------------------------------------------------------------ */
/* Registry                                                            */
/* ------------------------------------------------------------------ */

function sealDoc(doc, meta) {
  const payload = canonicalJson(doc);
  const registryVersion = sha256(payload);
  return deepFreeze({
    meta: { ...meta, registryVersion, label: doc.label, publishedAt: doc.publishedAt },
    doc: clone(doc),
    docHash: registryVersion,
  });
}

export class RuleRegistry {
  constructor({ persistDir, seedDoc = null, now = () => new Date() } = {}) {
    this.persistDir = persistDir ? path.join(persistDir, 'rules') : null;
    this.now = now;
    this.versions = [];
    this.byHash = new Map();
    this.byLabel = new Map();
    if (this.persistDir) fs.mkdirSync(this.persistDir, { recursive: true });
    const seeds = seedDoc ? [seedDoc] : buildSeedVersions();
    for (const doc of seeds) {
      this.#register(doc, {
        publishedBy: 'system-seed',
        parentVersion: null,
        notes: doc.notes,
        acknowledgedAmbiguities: doc.acknowledgedAmbiguities ?? [],
        builtin: true,
      }, false);
    }
    this.#loadPersisted();
  }

  #loadPersisted() {
    if (!this.persistDir) return;
    const files = fs.readdirSync(this.persistDir).filter((f) => f.endsWith('.json')).sort();
    for (const file of files) {
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(this.persistDir, file), 'utf8'));
        if (raw?.doc && raw?.meta) this.#register(raw.doc, raw.meta, false);
      } catch (error) {
        // A corrupt snapshot must not break startup, but it must be visible.
        console.error(`[registry] failed to load ${file}: ${error.message}`);
      }
    }
  }

  #register(doc, meta, persist = true) {
    const sealed = sealDoc(doc, meta);
    const hash = sealed.meta.registryVersion;
    if (this.byHash.has(hash)) return this.byHash.get(hash);
    this.versions.push(sealed);
    this.byHash.set(hash, sealed);
    this.byLabel.set(sealed.meta.label, sealed);
    if (persist && this.persistDir) {
      const file = path.join(this.persistDir, `${sealed.meta.label}-${hash.slice(0, 12)}.json`);
      fs.writeFileSync(file, JSON.stringify({ doc: sealed.doc, meta: sealed.meta }, null, 2));
    }
    return sealed;
  }

  list() {
    return this.versions
      .slice()
      .sort((a, b) => (a.meta.publishedAt < b.meta.publishedAt ? -1 : a.meta.publishedAt > b.meta.publishedAt ? 1 : 0))
      .map((v) => ({
        label: v.meta.label,
        registryVersion: v.meta.registryVersion,
        publishedAt: v.meta.publishedAt,
        publishedBy: v.meta.publishedBy,
        parentVersion: v.meta.parentVersion,
        notes: v.meta.notes,
        builtin: Boolean(v.meta.builtin),
        ambiguities: computeAmbiguities(v.doc).map((a) => a.term),
        acknowledgedAmbiguities: v.meta.acknowledgedAmbiguities ?? [],
      }));
  }

  snapshot(ref) {
    if (!ref) return null;
    if (ref.startsWith('v') && this.byLabel.has(ref)) return this.byLabel.get(ref);
    return this.byHash.get(ref) ?? null;
  }

  current(asOf = this.now()) {
    const iso = (asOf instanceof Date ? asOf : new Date(asOf)).toISOString();
    const eligible = this.versions.filter((v) => v.meta.publishedAt <= iso);
    const pool = eligible.length ? eligible : this.versions;
    return pool.slice().sort((a, b) => (a.meta.publishedAt < b.meta.publishedAt ? -1 : 1)).at(-1);
  }

  latestOverall() {
    return this.versions.slice().sort((a, b) => (a.meta.publishedAt < b.meta.publishedAt ? -1 : 1)).at(-1);
  }

  publish({ doc, expectedVersion, actor, notes, acknowledgeAmbiguities = [], now = this.now() }) {
    if (!expectedVersion) {
      const error = new Error('发布规则必须携带 expectedVersion（If-Match）');
      error.code = 'PRECONDITION_REQUIRED';
      throw error;
    }
    const current = this.current(now);
    if (current.meta.registryVersion !== expectedVersion) {
      const error = new Error('规则已被其他发布者更新，请重新加载后再发布');
      error.code = 'RULE_VERSION_CONFLICT';
      error.details = { expectedVersion, actualVersion: current.meta.registryVersion, actualLabel: current.meta.label };
      throw error;
    }
    const candidate = clone(doc);
    const verdict = validateRuleDoc(candidate);
    if (!verdict.ok) {
      const error = new Error('规则校验失败');
      error.code = 'RULE_VALIDATION_FAILED';
      error.details = { errors: verdict.errors, warnings: verdict.warnings, ambiguities: verdict.ambiguities };
      throw error;
    }
    const ack = new Set(acknowledgeAmbiguities.map(normalizeAlias));
    const unacked = verdict.ambiguities.filter((a) => !ack.has(normalizeAlias(a.term)));
    if (unacked.length) {
      const error = new Error('存在未确认的歧义别名');
      error.code = 'AMBIGUITY_ACK_REQUIRED';
      error.details = { ambiguities: unacked };
      throw error;
    }
    const labelNumber = this.versions.reduce((max, v) => Math.max(max, Number(/^v(\d+)$/.exec(v.meta.label)?.[1] ?? 0)), 0) + 1;
    const publishedAt = (now instanceof Date ? now : new Date(now)).toISOString();
    candidate.label = `v${labelNumber}`;
    candidate.publishedAt = publishedAt;
    candidate.notes = typeof notes === 'string' && notes.trim() ? notes.trim() : candidate.notes;
    candidate.acknowledgedAmbiguities = verdict.ambiguities.map((a) => a.term);
    if (!Array.isArray(candidate.timeGrains)) candidate.timeGrains = [];
    const meta = {
      publishedBy: actor,
      parentVersion: current.meta.registryVersion,
      notes: candidate.notes,
      acknowledgedAmbiguities: candidate.acknowledgedAmbiguities,
      builtin: false,
    };
    const sealed = this.#register(candidate, meta, true);
    return sealed;
  }
}

export function registryVersionOf(version) {
  return version?.meta?.registryVersion ?? null;
}
