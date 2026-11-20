import {
  addDays, daysBetween, normalizeForMatch, parseDateString, startOfMonth, startOfQuarter,
  startOfYear, toDateString, uniq,
} from './util.js';

/*
 * Restricted natural-language parser.
 *
 * Design rule: the parser never guesses. Every word that maps to data must be
 * a registered alias in the pinned rule snapshot. Unknown words, ambiguous
 * aliases, unregistered values and unsupported time phrases all become
 * explicit rejections with a code, a span and a hint. Nothing is silently
 * dropped, and no free-form text ever reaches a datasource.
 */

export const REJECT_CODES = {
  INPUT_EMPTY: '输入为空',
  INPUT_TOO_LONG: '输入超长',
  CONTROL_CHARS: '包含不可见控制字符',
  DANGEROUS_INTENT: '检测到非查询意图',
  AMBIGUOUS_TERM: '别名歧义',
  UNRECOGNIZED_TERM: '无法识别的词',
  METRIC_REQUIRED: '缺少指标',
  TOO_MANY_METRICS: '指标过多',
  METRIC_NOT_GRANTED: '指标未授权',
  METRIC_INTERNAL: '指标为内部派生项',
  FIELD_NOT_GRANTED: '字段未授权',
  FIELD_NOT_FILTERABLE: '字段不可筛选',
  FIELD_NOT_GROUPABLE: '字段不可分组',
  FIELD_PII_FORBIDDEN: 'PII 字段禁止查询',
  FIELD_WITHOUT_CONDITION: '字段缺少条件',
  OP_NOT_ALLOWED: '操作符未授权',
  OP_INCOMPATIBLE: '操作符与字段类型不兼容',
  VALUE_MISSING: '缺少取值',
  VALUE_NOT_REGISTERED: '取值未登记',
  VALUE_FIELD_MISMATCH: '取值与字段不匹配',
  VALUE_TYPE_INVALID: '取值类型不匹配',
  BETWEEN_INVALID: '区间条件非法',
  SCOPE_VIOLATION: '超出数据行权限',
  TIME_INVALID: '时间条件无法解析',
  TIME_RANGE_REVERSED: '时间区间起止颠倒',
  TIME_FUTURE: '时间区间超出当前锚点',
  RANGE_TOO_LONG: '时间窗超限',
  TIME_TOO_BROAD: '时间范围过宽',
  TIME_CONFLICT: '时间条件冲突',
  GROUP_INVALID: '分组条件非法',
  GROUP_NOT_GRANTED: '分组字段未授权',
  SORT_INVALID: '排序条件非法',
  SORT_METRIC_NOT_SELECTED: '排序指标未选择',
  SORT_NOT_GRANTED: '排序未授权',
  LIMIT_INVALID: '条数限制非法',
  LIMIT_EXCEEDED: '条数超出上限',
  UNSUPPORTED_CLAUSE: '不支持的查询子句',
  RESIDUAL_TEXT: '存在未解析的文本',
  INTERNAL: '解析器内部错误',
};

export class ParseFailure {
  constructor(code, message, extra = {}) {
    this.code = code;
    this.message = message;
    this.span = extra.span ?? null;
    this.hint = extra.hint ?? null;
    this.detail = extra.detail ?? null;
    this.stage = extra.stage ?? 'parse';
    this.suggestions = extra.suggestions ?? [];
  }
  toJSON() {
    return {
      code: this.code,
      title: REJECT_CODES[this.code] ?? this.code,
      message: this.message,
      span: this.span,
      hint: this.hint,
      detail: this.detail,
      stage: this.stage,
      suggestions: this.suggestions,
    };
  }
}

/* ------------------------------------------------------------------ */
/* Lexicon                                                             */
/* ------------------------------------------------------------------ */

const OP_WORDS = [
  ['大于等于', 'gte'], ['不低于', 'gte'], ['至少', 'gte'], ['>=', 'gte'], ['≥', 'gte'],
  ['小于等于', 'lte'], ['不高于', 'lte'], ['至多', 'lte'], ['不超过', 'lte'], ['<=', 'lte'], ['≤', 'lte'],
  ['不等于', 'neq'], ['不为', 'neq'], ['不是', 'neq'], ['!=', 'neq'], ['≠', 'neq'], ['<>', 'neq'],
  ['大于', 'gt'], ['超过', 'gt'], ['高于', 'gt'], ['>', 'gt'],
  ['小于', 'lt'], ['低于', 'lt'], ['少于', 'lt'], ['<', 'lt'],
  ['介于', 'between'], ['之间', 'between'], ['包含', 'contains'], ['含有', 'contains'],
  ['等于', 'eq'], ['属于', 'in'], ['=', 'eq'], ['≠', 'neq'],
];

const KEYWORDS = [
  // time anchors / units
  ['最近', 'recent'], ['近', 'recent'], ['过去', 'recent'],
  ['今年', 'this_year'], ['去年', 'last_year'], ['本年', 'this_year'], ['上年', 'last_year'],
  ['本季度', 'this_quarter'], ['上季度', 'last_quarter'], ['本季', 'this_quarter'], ['上季', 'last_quarter'],
  ['本月', 'this_month'], ['上月', 'last_month'], ['本周', 'this_week'], ['上周', 'last_week'],
  ['今天', 'today'], ['昨天', 'yesterday'],
  ['天', 'day_unit'], ['日', 'day_unit'], ['周', 'week_unit'], ['星期', 'week_unit'],
  ['个月', 'month_unit'], ['月', 'month_unit_unit'], ['季度', 'quarter_unit'], ['年', 'year_unit'],
  ['全部时间', 'all_time'], ['所有时间', 'all_time'], ['全部数据', 'all_time'], ['所有数据', 'all_time'],
  // grouping / sorting / limiting
  ['从高到低', 'desc'], ['从低到高', 'asc'], ['降序排列', 'desc'], ['升序排列', 'asc'],
  ['降序', 'desc'], ['升序', 'asc'], ['倒序', 'desc'], ['排序', 'sort_keyword'], ['排列', 'sort_keyword'],
  ['分组', 'group_keyword'], ['汇总', 'group_keyword'], ['拆分', 'group_keyword'],
  ['按', 'by'], ['各', 'each'], ['每', 'each'], ['分', 'by'], ['归', 'by'],
  ['取前', 'top'], ['前', 'top'], ['top', 'top'], ['最多', 'most'], ['最少', 'least'],
  ['个', 'counter'], ['条', 'counter'], ['名', 'counter'], ['位', 'counter'], ['笔', 'counter'],
  ['到', 'to'], ['至', 'to'], ['~', 'to'], ['-', 'dash'],
  // filters
  ['排除', 'exclude'], ['除了', 'exclude'], ['剔除', 'exclude'], ['不要', 'exclude'], ['不含', 'exclude'],
  ['且', 'and'], ['并且', 'and'], ['并', 'and'], ['以及', 'and'], ['和', 'and'], ['与', 'and'], ['及', 'and'], ['、', 'and'], ['或', 'or'],
  ['在', 'at'], ['为', 'eq_word'], ['是', 'eq_word'], ['有', 'eq_word'],
  // NL filler / well-known query verbs (allowed, carry no data meaning)
  ['查询', 'filler'], ['查一下', 'filler'], ['查下', 'filler'], ['查看', 'filler'], ['看一下', 'filler'], ['看下', 'filler'],
  ['帮我', 'filler'], ['请问', 'filler'], ['请', 'filler'], ['统计', 'filler'], ['分析', 'filler'], ['显示', 'filler'],
  ['给出', 'filler'], ['列出', 'filler'], ['查', 'filler'], ['看', 'filler'], ['要', 'filler'],
  ['想', 'filler'], ['知道', 'filler'], ['了解', 'filler'], ['数据', 'filler'], ['结果', 'filler'], ['一下', 'filler'],
  ['的', 'filler'], ['了', 'filler'], ['呢', 'filler'], ['吗', 'filler'], ['吧', 'filler'], ['我', 'filler'], ['我们', 'filler'],
  ['所有', 'all'], ['全部', 'all'], ['整体', 'all'], ['总计', 'all'],
  ['方面', 'filler'], ['情况', 'filler'], ['表现', 'filler'], ['之外', 'filler'], ['以外', 'filler'],
  ['元', 'currency'], ['万元', 'currency'], ['块钱', 'currency'], ['块', 'currency'],
];

const DANGEROUS_PATTERNS = [
  [/删除|删掉|清除|清空|drop\s+table|delete\s+from|truncate/i, '删除/破坏类操作不在查询语言内'],
  [/修改|更新|写入|插入|upsert|insert\s+into|update\s+\w+\s+set/i, '写操作不在查询语言内'],
  [/忽略(上述|之前|以上)|ignore\s+(all\s+)?(previous|above)|system\s*prompt|越狱|jailbreak/i, '提示词注入模式不被接受'],
  [/绕过|跳过(权限|校验)|越权|提权|sudo|admin\s*mode/i, '不存在绕过权限的查询路径'],
  [/导出|下载|dump|全库|所有客户|全部客户/i, '导出须通过受控的导出接口，不能在查询语句中触发'],
];

function normalizeWithMap(text) {
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    let ch = text[i];
    const code = ch.charCodeAt(0);
    if (code >= 0xff01 && code <= 0xff5e) ch = String.fromCharCode(code - 0xfee0);
    else if (code === 0x3000) ch = ' ';
    else if (ch === '，') ch = ',';
    else if (ch === '；') ch = ';';
    else if (ch === '：') ch = ':';
    else if (ch === '（') ch = '(';
    else if (ch === '）') ch = ')';
    else if (ch === '。') ch = '.';
    else if (ch === '“' || ch === '”') ch = '"';
    else if (ch === '‘' || ch === '’') ch = "'";
    else if (ch === '—' || ch === '–') ch = '-';
    else if (ch === '≥') ch = '>=';
    else if (ch === '≤') ch = '<=';
    else if (ch === '≠') ch = '!=';
    else if (ch === '～') ch = '~';
    out += ch.toLowerCase();
  }
  return out;
}

const CN_NUM = { 一: 1, 二: 2, 两: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9, 十: 10 };

function parseCnNumber(text) {
  if (/^\d+$/.test(text)) return Number(text);
  if (text in CN_NUM) return CN_NUM[text];
  if (/^十[一二三四五六七八九]$/.test(text)) return 10 + CN_NUM[text[1]];
  if (/^[一二三四五六七八九]十$/.test(text)) return CN_NUM[text[0]] * 10;
  if (/^[一二三四五六七八九]十[一二三四五六七八九]$/.test(text)) return CN_NUM[text[0]] * 10 + CN_NUM[text[2]];
  return null;
}

function targetKey(t) {
  return `${t.kind}:${t.id}:${t.value ?? ''}`;
}

export function prepareLexicon(snapshot) {
  const doc = snapshot.doc;
  const entries = new Map(); // normalized alias -> array of targets
  const add = (alias, target) => {
    const key = normalizeForMatch(alias);
    if (!key) return;
    const list = entries.get(key) ?? [];
    if (!list.some((t) => targetKey(t) === targetKey(target))) list.push(target);
    entries.set(key, list);
  };
  for (const m of doc.metrics) {
    const target = { kind: 'metric', id: m.id, label: m.label, hidden: Boolean(m.hidden), pointer: `/metrics/${m.id}` };
    for (const alias of [m.label, ...(m.aliases ?? [])]) add(alias, target);
  }
  for (const f of doc.fields) {
    const target = { kind: 'field', id: f.id, label: f.label, type: f.type, pointer: `/fields/${f.id}` };
    for (const alias of [f.label, ...(f.aliases ?? [])]) add(alias, target);
    for (const value of f.enum ?? []) {
      const enumTarget = { kind: 'enum', id: f.id, fieldLabel: f.label, value: value.value, label: `${f.label}=${value.value}`, pointer: `/fields/${f.id}/enum/${value.value}` };
      for (const alias of [value.value, ...(value.aliases ?? [])]) add(alias, enumTarget);
    }
  }
  for (const g of doc.timeGrains ?? []) {
    const target = { kind: 'grain', grain: g.grain, id: g.id, label: g.label, pointer: `/timeGrains/${g.id}` };
    for (const alias of [g.label, ...(g.aliases ?? [])]) add(alias, target);
  }
  const all = [];
  for (const [alias, targets] of entries) {
    all.push({ alias, targets, type: targets.length > 1 ? 'ambiguous' : targets[0].kind });
  }
  all.sort((a, b) => b.alias.length - a.alias.length || (a.alias < b.alias ? -1 : 1));

  const keywordEntries = [];
  const seenKeywords = new Set();
  for (const [phrase, key] of KEYWORDS) {
    const alias = normalizeForMatch(phrase);
    if (seenKeywords.has(alias)) continue;
    seenKeywords.add(alias);
    keywordEntries.push({ alias, key });
  }
  keywordEntries.sort((a, b) => b.alias.length - a.alias.length);
  const opEntries = [];
  for (const [phrase, op] of OP_WORDS) opEntries.push({ alias: normalizeForMatch(phrase), op });
  opEntries.sort((a, b) => b.alias.length - a.alias.length);

  return { entries: all, keywordEntries, opEntries, byAlias: entries };
}

/* ------------------------------------------------------------------ */
/* Lexer                                                               */
/* ------------------------------------------------------------------ */

const DATE_PATTERNS = [
  { re: /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:日|号)?/, kind: 'day', parts: (m) => ({ year: +m[1], month: +m[2], day: +m[3] }) },
  { re: /^(\d{4})年(\d{1,2})月(\d{1,2})(?:日|号)?/, kind: 'day', parts: (m) => ({ year: +m[1], month: +m[2], day: +m[3] }) },
  { re: /^(\d{4})[-/.](\d{1,2})月?/, kind: 'month', parts: (m) => ({ year: +m[1], month: +m[2] }) },
  { re: /^(\d{4})年(\d{1,2})月(?!个)/, kind: 'month', parts: (m) => ({ year: +m[1], month: +m[2] }) },
  { re: /^(\d{1,2})月(?!个)/, kind: 'month', parts: (m) => ({ month: +m[1] }) },
  { re: /^(\d{4})[-/.]?q([1-4])/i, kind: 'quarter', parts: (m) => ({ year: +m[1], quarter: +m[2] }) },
  { re: /^(\d{4})年?(?:第)?([1-4一二三四])季度/, kind: 'quarter', parts: (m) => ({ year: +m[1], quarter: m[2].match(/\d/) ? +m[2] : CN_NUM[m[2]] }) },
  { re: /^(?:第)?([1-4一二三四])季度/, kind: 'quarter', parts: (m) => ({ quarter: m[1].match(/\d/) ? +m[1] : CN_NUM[m[1]] }) },
  { re: /^(\d{4})年(?!\d)/, kind: 'year', parts: (m) => ({ year: +m[1] }) },
];

function makeDateToken(kind, parts, start, end, raw, today) {
  if (parts.month < 1 || parts.month > 12) return { error: `月份非法：${raw}` };
  const year = parts.year ?? today.getUTCFullYear();
  let startDate;
  let endDate;
  if (kind === 'day') {
    const ds = toDateString(new Date(Date.UTC(year, parts.month - 1, parts.day)));
    if (Number(ds.slice(5, 7)) !== parts.month || Number(ds.slice(8, 10)) !== parts.day) return { error: `日期非法：${raw}` };
    startDate = ds;
    endDate = ds;
  } else if (kind === 'month') {
    const ds = `${year}-${String(parts.month).padStart(2, '0')}-01`;
    startDate = ds;
    endDate = addDays(startOfMonth(addDays(ds, 32)), -1);
  } else if (kind === 'quarter') {
    const qStartMonth = (parts.quarter - 1) * 3 + 1;
    const ds = `${year}-${String(qStartMonth).padStart(2, '0')}-01`;
    startDate = ds;
    endDate = addDays(startOfQuarter(addDays(ds, 95)), -1);
  } else {
    startDate = `${year}-01-01`;
    endDate = `${year}-12-31`;
  }
  return { type: 'date', kind, start: startDate, end: endDate, raw, span: { start, end }, year, ...parts };
}

export function lex(text, snapshot, lexicon, today) {
  const tokens = [];
  let i = 0;
  const push = (token) => tokens.push(token);
  while (i < text.length) {
    const rest = text.slice(i);
    const ws = /^\s+/.exec(rest);
    if (ws) { i += ws[0].length; continue; }

    let matchedDate = false;
    for (const pattern of DATE_PATTERNS) {
      const m = pattern.re.exec(rest);
      if (!m) continue;
      const t = makeDateToken(pattern.kind, pattern.parts(m), i, i + m[0].length, m[0], today);
      if (t.error) return { error: t.error, span: { start: i, end: i + m[0].length } };
      push(t);
      i += m[0].length;
      matchedDate = true;
      break;
    }
    if (matchedDate) continue;

    const num = /^\d+(?:\.\d+)?(?:万|千)?/.exec(rest);
    if (num) {
      let raw = num[0];
      let multiplier = 1;
      if (raw.endsWith('万')) { multiplier = 10000; raw = raw.slice(0, -1); }
      else if (raw.endsWith('千')) { multiplier = 1000; raw = raw.slice(0, -1); }
      push({ type: 'number', value: Number(raw) * multiplier, raw: num[0], span: { start: i, end: i + num[0].length } });
      i += num[0].length;
      continue;
    }

    const cnNum = /^[一二两三四五六七八九十]{1,3}(?=个|条|天|日|周|星期|月|年|季度|位|名|笔)/.exec(rest);
    if (cnNum && parseCnNumber(cnNum[0]) !== null) {
      push({ type: 'number', value: parseCnNumber(cnNum[0]), raw: cnNum[0], span: { start: i, end: i + cnNum[0].length } });
      i += cnNum[0].length;
      continue;
    }

    let best = null;
    for (const entry of lexicon.opEntries) {
      if (entry.alias && rest.startsWith(entry.alias)) { best = { type: 'op', op: entry.op, raw: entry.alias, length: entry.alias.length }; break; }
    }
    if (!best) {
      for (const entry of lexicon.entries) {
        if (rest.startsWith(entry.alias)) {
          best = { type: entry.type, targets: entry.targets, raw: entry.alias, length: entry.alias.length };
          break;
        }
      }
    }
    if (!best) {
      for (const entry of lexicon.keywordEntries) {
        if (rest.startsWith(entry.alias)) { best = { type: 'keyword', key: entry.key, raw: entry.alias, length: entry.alias.length }; break; }
      }
    }
    if (best) {
      push({ ...best, span: { start: i, end: i + best.length } });
      i += best.length;
      continue;
    }

    const punct = /^[,;:.()\[\]{}"'、。!?/\\|]/.exec(rest);
    if (punct) {
      push({ type: 'punct', value: punct[0], span: { start: i, end: i + 1 } });
      i += 1;
      continue;
    }

    // Residual run: stop at the next position that any known term can start.
    let j = i + 1;
    while (j < text.length) {
      const sub = text.slice(j);
      const multi = (e) => e.alias.length > 1;
      const hit =
        lexicon.entries.some((e) => multi(e) && sub.startsWith(e.alias)) ||
        lexicon.keywordEntries.some((e) => multi(e) && sub.startsWith(e.alias)) ||
        lexicon.opEntries.some((e) => multi(e) && sub.startsWith(e.alias)) ||
        DATE_PATTERNS.some((p) => p.re.test(sub)) ||
        /^\d/.test(sub) ||
        /^\s/.test(sub) ||
        /^[,;:.()\[\]{}"'、。!?/\\|]/.test(sub);
      if (hit) break;
      j += 1;
    }
    push({ type: 'text', value: text.slice(i, j), raw: text.slice(i, j), span: { start: i, end: j } });
    i = j;
  }
  return { tokens };
}

/* ------------------------------------------------------------------ */
/* Parser                                                              */
/* ------------------------------------------------------------------ */

const CONNECTOR_KEYS = new Set(['and', 'or', 'filler']);
const FILLER_UNITS = { day_unit: 1, week_unit: 7, month_unit: 30, month_unit_unit: 30, quarter_unit: 91, year_unit: 365 };

function spanOf(tokens) {
  if (!tokens.length) return null;
  return { start: tokens[0].span.start, end: tokens.at(-1).span.end };
}

function sliceRaw(tokens) {
  return tokens.map((t) => t.raw ?? t.value ?? '').join('');
}

class Cursor {
  constructor(tokens) { this.tokens = tokens; this.i = 0; }
  peek(offset = 0) { return this.tokens[this.i + offset] ?? null; }
  next() { return this.tokens[this.i++] ?? null; }
  eof() { return this.i >= this.tokens.length; }
  mark() { return this.i; }
  reset(i) { this.i = i; }
}

function isKeyword(token, key) { return token?.type === 'keyword' && token.key === key; }
function isField(token) { return token?.type === 'field'; }
function isMetric(token) { return token?.type === 'metric'; }
function isGrain(token) { return token?.type === 'grain'; }
function isNumber(token) { return token?.type === 'number'; }
function isDate(token) { return token?.type === 'date'; }
function isPunct(token) { return token?.type === 'punct'; }
function isConnector(token) {
  return token?.type === 'punct' || (token?.type === 'keyword' && CONNECTOR_KEYS.has(token.key));
}

export class RestrictedQueryParser {
  constructor(snapshot, { asOf, today } = {}) {
    this.snapshot = snapshot;
    this.asOf = asOf instanceof Date ? asOf : new Date(asOf ?? Date.now());
    this.today = today instanceof Date ? today : new Date(Date.UTC(this.asOf.getUTCFullYear(), this.asOf.getUTCMonth(), this.asOf.getUTCDate()));
    this.todayString = toDateString(this.today);
    this.lexicon = prepareLexicon(snapshot);
  }

  parse(text) {
    const rejections = [];
    const mappings = [];
    const warnings = [];
    const rawText = typeof text === 'string' ? text : '';
    if (!rawText.trim()) return this.#fail([new ParseFailure('INPUT_EMPTY', '请输入查询条件', { hint: '例如：最近 30 天各渠道的销售额' })], { rawText, mappings, warnings });
    if (rawText.length > 600) return this.#fail([new ParseFailure('INPUT_TOO_LONG', '查询语句超过 600 字符上限', { hint: '请拆分为多条更精确的查询' })], { rawText, mappings, warnings });
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(rawText)) {
      return this.#fail([new ParseFailure('CONTROL_CHARS', '查询语句包含不可见控制字符', { hint: '请粘贴纯文本后重试' })], { rawText, mappings, warnings });
    }
    for (const [pattern, message] of DANGEROUS_PATTERNS) {
      const m = pattern.exec(rawText);
      if (m) {
        return this.#fail([new ParseFailure('DANGEROUS_INTENT', message, {
          span: { start: m.index, end: m.index + m[0].length },
          hint: '本系统只接受只读聚合查询；如有写入或导出需求，请走审批流程。',
        })], { rawText, mappings, warnings });
      }
    }

    const normalized = normalizeWithMap(rawText);
    const lexed = lex(normalized, this.snapshot, this.lexicon, this.today);
    if (lexed.error) {
      return this.#fail([new ParseFailure('TIME_INVALID', lexed.error, { span: lexed.span, hint: '日期需使用 2026-10-01 或 2026年10月 这样的写法' })], { rawText, mappings, warnings, normalized });
    }
    const tokens = lexed.tokens;

    // Ambiguous aliases are surfaced before any grammar decisions.
    for (const token of tokens) {
      if (token.type === 'ambiguous') {
        mappings.push({ term: rawText.slice(token.span.start, token.span.end), targets: token.targets.map((t) => ({ kind: t.kind, id: t.id, label: t.label, pointer: t.pointer })), span: token.span });
        rejections.push(new ParseFailure('AMBIGUOUS_TERM', `“${rawText.slice(token.span.start, token.span.end)}”在规则 ${this.snapshot.meta.label} 中指向多个登记项，无法自动消歧`, {
          span: token.span,
          hint: '请改用登记表中的规范名称。',
          suggestions: token.targets.map((t) => t.label),
          detail: { candidates: token.targets },
        }));
      }
    }
    if (rejections.length) return this.#fail(rejections, { rawText, mappings, warnings, normalized, tokens });

    const parseErrors = [];
    try {
      return this.#parseTokens(tokens, rawText, normalized, mappings, warnings);
    } catch (error) {
      if (error instanceof ParseFailure) parseErrors.push(error);
      else parseErrors.push(new ParseFailure('INTERNAL', '解析器遇到内部错误', { detail: String(error?.message ?? error) }));
      return this.#fail(parseErrors, { rawText, mappings, warnings, normalized, tokens });
    }
  }

  #fail(rejections, ctx) {
    return {
      ok: false,
      normalizedText: ctx.normalized ?? null,
      mappings: ctx.mappings ?? [],
      warnings: ctx.warnings ?? [],
      rejections: rejections.map((r) => r.toJSON()),
      tokens: (ctx.tokens ?? []).map((t) => ({ type: t.type, raw: t.raw, span: t.span })),
      registry: this.#registryMeta(),
      asOf: this.asOf.toISOString(),
    };
  }

  #registryMeta() {
    return {
      label: this.snapshot.meta.label,
      registryVersion: this.snapshot.meta.registryVersion,
      publishedAt: this.snapshot.meta.publishedAt,
      publishedBy: this.snapshot.meta.publishedBy,
    };
  }

  #parseTokens(tokens, rawText, normalized, mappings, warnings) {
    const cursor = new Cursor(tokens);
    const rejections = [];
    const text = (span) => rawText.slice(span.start, span.end);
    const addMapping = (token, target, role) => {
      mappings.push({
        term: text(token.span),
        span: token.span,
        role,
        target: { kind: target.kind, id: target.id, label: target.label, pointer: target.pointer, ...(target.value ? { value: target.value } : {}) },
      });
    };

    // ---------- pass 1: time ----------
    let time = null;
    const timeTokens = [];
    for (let idx = 0; idx < tokens.length; idx += 1) {
      const t = tokens[idx];
      if (isKeyword(t, 'all_time')) {
        rejections.push(new ParseFailure('TIME_TOO_BROAD', '不接受“全部时间/所有数据”这类无边界查询', { span: t.span, hint: '请给出明确的时间窗，例如“最近 30 天”或“2026年第三季度”。' }));
        timeTokens.push(idx);
        continue;
      }
      if (isDate(t)) {
        let endDate = t.end;
        let endToken = t;
        // explicit range A 到 B
        if (isKeyword(tokens[idx + 1], 'to') && isDate(tokens[idx + 2])) {
          endToken = tokens[idx + 2];
          endDate = tokens[idx + 2].end;
          timeTokens.push(idx, idx + 1, idx + 2);
          idx += 2;
        } else if (isKeyword(tokens[idx + 1], 'to')) {
          rejections.push(new ParseFailure('TIME_INVALID', '时间区间缺少结束日期', { span: spanOf([t, tokens[idx + 1]]), hint: '请写成“2026-01-01 到 2026-03-31”。' }));
          timeTokens.push(idx, idx + 1);
          idx += 1;
          continue;
        } else {
          timeTokens.push(idx);
        }
        if (time) {
          rejections.push(new ParseFailure('TIME_CONFLICT', '一条查询只能有一个时间窗口', { span: t.span, hint: '请合并为一个连续区间。' }));
          continue;
        }
        time = { start: t.start, end: endDate, source: 'explicit', raw: text({ start: t.span.start, end: endToken.span.end }), tokens: [t, endToken] };
        continue;
      }
      if (isKeyword(t, 'recent') || (isKeyword(t, 'before') && isNumber(tokens[idx + 1]) && FILLER_UNITS[tokens[idx + 2]?.key])) {
        const anchorToken = t;
        let cursorIdx = idx + 1;
        let amount = null;
        let unitKey = null;
        if (isNumber(tokens[cursorIdx])) {
          amount = tokens[cursorIdx].value;
          cursorIdx += 1;
        }
        if (isKeyword(tokens[cursorIdx], 'counter')) cursorIdx += 1;
        const unitToken = tokens[cursorIdx];
        if (unitToken?.type === 'keyword' && FILLER_UNITS[unitToken.key]) {
          unitKey = unitToken.key;
          cursorIdx += 1;
        } else if (unitToken?.type === 'grain' && ['day', 'month', 'quarter', 'year'].includes(unitToken.targets[0].grain)) {
          unitKey = { day: 'day_unit', month: 'month_unit', quarter: 'quarter_unit', year: 'year_unit' }[unitToken.targets[0].grain];
          cursorIdx += 1;
        }
        if (amount === null || !Number.isFinite(amount) || amount <= 0 || !Number.isInteger(amount)) {
          rejections.push(new ParseFailure('TIME_INVALID', '相对时间缺少合法的数量', { span: spanOf(tokens.slice(idx, cursorIdx)), hint: '例如“最近 30 天”“近 3 个月”。' }));
          idx = cursorIdx - 1;
          continue;
        }
        if (!unitKey) {
          rejections.push(new ParseFailure('TIME_INVALID', '相对时间缺少时间单位', { span: spanOf(tokens.slice(idx, cursorIdx)), hint: '支持 天/周/个月/年。' }));
          idx = cursorIdx - 1;
          continue;
        }
        const days = amount * FILLER_UNITS[unitKey] - (FILLER_UNITS[unitKey] > 1 ? 1 : 0);
        if (time) rejections.push(new ParseFailure('TIME_CONFLICT', '一条查询只能有一个时间窗口', { span: spanOf(tokens.slice(idx, cursorIdx)), hint: '请合并为一个连续区间。' }));
        else time = { start: addDays(this.todayString, -days), end: this.todayString, source: 'relative', raw: text({ start: anchorToken.span.start, end: tokens[cursorIdx - 1].span.end }), tokens: tokens.slice(idx, cursorIdx) };
        for (let k = idx; k < cursorIdx; k += 1) timeTokens.push(k);
        idx = cursorIdx - 1;
        continue;
      }
      if (t.type === 'keyword' && ['this_month', 'last_month', 'this_quarter', 'last_quarter', 'this_year', 'last_year', 'this_week', 'last_week', 'today', 'yesterday'].includes(t.key)) {
        const resolved = this.#resolveAnchor(t.key);
        if (time) rejections.push(new ParseFailure('TIME_CONFLICT', '一条查询只能有一个时间窗口', { span: t.span, hint: '请合并为一个连续区间。' }));
        else time = { ...resolved, source: 'anchor', raw: text(t.span), tokens: [t] };
        timeTokens.push(idx);
      }
    }

    // ---------- pass 2: limit & sort direction ----------
    let limit = null;
    let limitSpan = null;
    let direction = null;
    let directionToken = null;
    const consumed = new Set(timeTokens);
    const markConsumedLater = (from, to) => { for (let k = from; k < to; k += 1) consumed.add(k); };
    for (let idx = 0; idx < tokens.length; idx += 1) {
      const t = tokens[idx];
      if (isKeyword(t, 'desc') || isKeyword(t, 'asc')) {
        direction = (t.key === 'desc') ? 'desc' : 'asc';
        directionToken = t;
        consumed.add(idx);
        continue;
      }
      if (isKeyword(t, 'top') || isKeyword(t, 'most') || isKeyword(t, 'least')) {
        let j = idx + 1;
        let amount = null;
        if (isNumber(tokens[j])) { amount = tokens[j].value; j += 1; }
        if (isKeyword(tokens[j], 'counter')) j += 1;
        if (amount === null) {
          rejections.push(new ParseFailure('LIMIT_INVALID', '条数限制缺少数字', { span: spanOf(tokens.slice(idx, j)), hint: '例如“前 5”“top 10”。' }));
          continue;
        }
        if (!Number.isInteger(amount) || amount <= 0) {
          rejections.push(new ParseFailure('LIMIT_INVALID', `条数必须是正整数，收到：${amount}`, { span: spanOf(tokens.slice(idx, j)) }));
          continue;
        }
        if (limit !== null) rejections.push(new ParseFailure('LIMIT_INVALID', '重复指定条数限制', { span: spanOf(tokens.slice(idx, j)) }));
        limit = amount;
        limitSpan = spanOf(tokens.slice(idx, j));
        if (t.key === 'most') { direction = 'desc'; directionToken = t; }
        if (t.key === 'least') { direction = 'asc'; directionToken = t; }
        for (let k = idx; k < j; k += 1) consumed.add(k);
        idx = j - 1;
      }
    }

    // ---------- pass 3: grouping ----------
    let group = null;
    const groupTokens = [];
    for (let idx = 0; idx < tokens.length; idx += 1) {
      if (consumed.has(idx)) continue;
      const t = tokens[idx];
      if (isKeyword(t, 'group_keyword')) consumed.add(idx);
      const startsGroup = isKeyword(t, 'by') || isKeyword(t, 'each') || isGrain(t);
      if (!startsGroup) continue;
      if (group) {
        // Consume the whole duplicate phrase (e.g. "按渠道分组") so it does not
        // resurface later as an unrelated "field without condition" rejection.
        let dupEnd = idx + 1;
        while (dupEnd < tokens.length && dupEnd <= idx + 3) {
          const v = tokens[dupEnd];
          if (isField(v) || isGrain(v) || isKeyword(v, 'group_keyword')) { dupEnd += 1; continue; }
          break;
        }
        rejections.push(new ParseFailure('GROUP_INVALID', '一次查询仅支持一个分组维度', { span: spanOf(tokens.slice(idx, dupEnd)), hint: '请拆分为两条查询。' }));
        markConsumedLater(idx, dupEnd);
        idx = dupEnd - 1;
        continue;
      }
      let j = idx;
      let targetToken = null;
      if (isGrain(t)) {
        targetToken = t;
        j = idx + 1;
      } else {
        j = idx + 1;
        if (isKeyword(tokens[j], 'by') || isKeyword(tokens[j], 'each') || isKeyword(tokens[j], 'group_keyword')) j += 1;
        targetToken = tokens[j];
        j += 1;
      }
      if (!targetToken || (!isField(targetToken) && !isGrain(targetToken))) {
        rejections.push(new ParseFailure('GROUP_INVALID', '分组目标必须是已登记且可分组的字段或时间粒度', {
          span: spanOf(tokens.slice(idx, Math.max(j, idx + 1))),
          hint: '例如“按渠道分组”“按月分组”。',
        }));
        for (let k = idx; k < j; k += 1) { groupTokens.push(k); consumed.add(k); }
        idx = j - 1;
        continue;
      }
      if (targetToken.type === 'ambiguous') continue;
      if (group) {
        rejections.push(new ParseFailure('GROUP_INVALID', '一次查询仅支持一个分组维度', { span: spanOf(tokens.slice(idx, j)), hint: '请拆分为两条查询。' }));
        for (let k = idx; k < j; k += 1) consumed.add(k);
        idx = j - 1;
        continue;
      } else if (isField(targetToken)) {
        const target = targetToken.targets[0];
        const def = this.snapshot.doc.fields.find((f) => f.id === target.id);
        if (def?.pii) {
          rejections.push(new ParseFailure('FIELD_PII_FORBIDDEN', `PII 字段“${def.label}”禁止用于分组`, { span: targetToken.span, hint: 'PII 字段只允许通过登记的安全聚合指标使用。' }));
          addMapping(targetToken, target, 'group');
          for (let k = idx; k < j; k += 1) { groupTokens.push(k); consumed.add(k); }
          idx = j - 1;
          continue;
        }
        if (def?.groupable === false) {
          rejections.push(new ParseFailure('FIELD_NOT_GROUPABLE', `字段“${def.label}”未登记为可分组`, { span: targetToken.span, hint: '请选择可分组的维度字段。' }));
          for (let k = idx; k < j; k += 1) { groupTokens.push(k); consumed.add(k); }
          idx = j - 1;
          continue;
        }
        group = { kind: 'field', field: target.id, label: target.label, pointer: target.pointer, token: targetToken };
        addMapping(targetToken, target, 'group');
        consumed.add(j - 1);
      } else {
        const target = targetToken.targets[0];
        group = { kind: 'time', grain: target.grain, id: target.id, label: target.label, pointer: target.pointer, token: targetToken };
        addMapping(targetToken, target, 'group');
        consumed.add(j - 1);
      }
      for (let k = idx; k < j; k += 1) { groupTokens.push(k); consumed.add(k); }
      idx = j - 1;
    }

    // "按销售额排序": 按 + metric is a sort key, not a group.
    let sortByMetricToken = null;
    for (let idx = 0; idx < tokens.length; idx += 1) {
      if (consumed.has(idx)) continue;
      if (isKeyword(tokens[idx], 'by') && isMetric(tokens[idx + 1])) {
        sortByMetricToken = tokens[idx + 1];
        consumed.add(idx); consumed.add(idx + 1);
        if (!directionToken && (isKeyword(tokens[idx + 2], 'sort_keyword') || isKeyword(tokens[idx + 2], 'desc') || isKeyword(tokens[idx + 2], 'asc'))) consumed.add(idx + 2);
        idx += 2;
      }
    }

    // ---------- pass 4: filters ----------
    const filters = [];
    const usedFieldTokens = new Set();
    const markConsumed = (from, to) => { for (let k = from; k < to; k += 1) consumed.add(k); };

    const applyParsed = (parsed, tokenFrom, tokenTo) => {
      if (parsed.error) rejections.push(parsed.error);
      else if (parsed.timeFilter) {
        const merged = this.#mergeTimeFilter(parsed, time, rejections, text);
        if (merged) time = merged;
      } else if (parsed.filter) filters.push(parsed.filter);
      markConsumed(tokenFrom, tokenTo);
    };

    for (let idx = 0; idx < tokens.length; idx += 1) {
      if (consumed.has(idx) || usedFieldTokens.has(idx)) continue;
      const t = tokens[idx];

      if (isKeyword(t, 'exclude') || isKeyword(t, 'not')) {
        let j = idx + 1;
        if (isKeyword(tokens[j], 'by')) j += 1;
        const valueTokens = [];
        const fieldToken = isField(tokens[j]) ? tokens[j] : null;
        if (fieldToken) j += 1;
        else if (isKeyword(tokens[j], 'eq_word')) j += 1;
        if (isKeyword(tokens[j], 'at')) j += 1;
        while (j < tokens.length) {
          const v = tokens[j];
          if (v.type === 'enum' || isNumber(v) || isDate(v)) { valueTokens.push(v); j += 1; continue; }
          if (isKeyword(v, 'and') && valueTokens.length > 0) { j += 1; continue; }
          if (isKeyword(v, 'currency')) { j += 1; continue; }
          break;
        }
        const anyField = fieldToken
          ? this.snapshot.doc.fields.find((f) => f.id === fieldToken.targets[0].id)
          : (valueTokens[0]?.type === 'enum' ? this.snapshot.doc.fields.find((f) => f.id === valueTokens[0].targets[0].id) : null);
        if (!anyField || valueTokens.length === 0) {
          rejections.push(new ParseFailure('FIELD_WITHOUT_CONDITION', '排除条件缺少字段或取值', { span: spanOf(tokens.slice(idx, j)), hint: '例如“排除华南”“区域不是华南”。' }));
          markConsumed(idx, j);
          idx = j - 1;
          continue;
        }
        if (fieldToken) addMapping(fieldToken, fieldToken.targets[0], 'filter');
        const parsed = this.#buildFilter(anyField, 'not_in', valueTokens, tokens.slice(idx, j), { fieldToken, opToken: t });
        if (parsed.timeFilter) rejections.push(new ParseFailure('TIME_INVALID', '不支持对时间字段做排除', { span: spanOf(tokens.slice(idx, j)) }));
        else applyParsed(parsed, idx, j);
        idx = j - 1;
        continue;
      }

      if (t.type === 'enum') {
        const target = t.targets[0];
        const field = this.snapshot.doc.fields.find((f) => f.id === target.id);
        let j = idx + 1;
        const valueTokens = [t];
        while (j < tokens.length) {
          const v = tokens[j];
          if (isKeyword(v, 'and') && tokens[j + 1]?.type === 'enum' && tokens[j + 1].targets[0].id === field.id) { j += 1; continue; }
          if (isKeyword(v, 'or') && tokens[j + 1]?.type === 'enum' && tokens[j + 1].targets[0].id === field.id) { j += 1; continue; }
          if (v.type === 'enum' && v.targets[0].id === field.id) { valueTokens.push(v); j += 1; continue; }
          break;
        }
        addMapping(t, target, 'filter');
        applyParsed(this.#buildFilter(field, valueTokens.length > 1 ? 'in' : 'eq', valueTokens, tokens.slice(idx, j), {}), idx, j);
        idx = j - 1;
        continue;
      }

      if (!isField(t)) continue;
      usedFieldTokens.add(idx);
      const field = this.snapshot.doc.fields.find((f) => f.id === t.targets[0].id);
      if (field?.pii) {
        addMapping(t, t.targets[0], 'field');
        rejections.push(new ParseFailure('FIELD_PII_FORBIDDEN', `PII 字段“${field.label}”禁止直接查询或筛选`, {
          span: t.span,
          hint: '如需统计客户规模，请使用登记的聚合指标“客户数”。',
        }));
        markConsumed(idx, idx + 1);
        continue;
      }
      let j = idx + 1;
      let op = null;
      let opToken = null;
      if (isKeyword(tokens[j], 'at')) j += 1;
      if (tokens[j]?.type === 'op') { op = tokens[j].op; opToken = tokens[j]; j += 1; }
      else if (isKeyword(tokens[j], 'eq_word')) { op = 'eq'; opToken = tokens[j]; j += 1; }

      const startValue = j;
      const isRangeConnector = (v) => isKeyword(v, 'to') || isKeyword(v, 'and') || isKeyword(v, 'dash') || isKeyword(v, 'between');
      const canBeValue = (v) => isNumber(v) || isDate(v) || v?.type === 'enum';

      // "金额在 1000 到 5000" / "金额介于 1000 和 5000"
      if (op === 'between' || (isKeyword(tokens[startValue - 1], 'at') && canBeValue(tokens[startValue]) && isRangeConnector(tokens[startValue + 1]) && canBeValue(tokens[startValue + 2]))) {
        const values = [];
        if (canBeValue(tokens[j]) && isRangeConnector(tokens[j + 1]) && canBeValue(tokens[j + 2])) {
          values.push(tokens[j], tokens[j + 2]);
          j += 3;
        }
        while (isKeyword(tokens[j], 'currency') || (tokens[j]?.type === 'op' && tokens[j].op === 'between')) j += 1;
        addMapping(t, t.targets[0], 'filter');
        if (values.length !== 2) {
          rejections.push(new ParseFailure('BETWEEN_INVALID', '区间条件需要两个边界值', { span: spanOf(tokens.slice(idx, j)), hint: '例如“金额在 1000 到 5000 之间”。' }));
          markConsumed(idx, j);
          idx = j - 1;
          continue;
        }
        applyParsed(this.#buildFilter(field, 'between', values, tokens.slice(idx, j), { fieldToken: t, opToken, betweenPhrase: true }), idx, j);
        idx = j - 1;
        continue;
      }

      const valueTokens = [];
      while (j < tokens.length) {
        const v = tokens[j];
        if (canBeValue(v)) {
          if (v.type === 'enum' && v.targets[0].id !== field.id && valueTokens.length === 0) break;
          valueTokens.push(v); j += 1; continue;
        }
        if (isKeyword(v, 'currency')) { j += 1; continue; }
        if ((isKeyword(v, 'and') || isKeyword(v, 'or')) && valueTokens.length > 0 && canBeValue(tokens[j + 1]) && !isConnector(tokens[j - 1])) { j += 1; continue; }
        break;
      }
      if (valueTokens.length === 0) {
        rejections.push(new ParseFailure('FIELD_WITHOUT_CONDITION', `字段“${field.label}”后缺少条件或取值`, {
          span: t.span,
          hint: `若想按${field.label}拆分，请写“按${field.label}分组”；若想筛选，请写“${field.label} 为 …”。`,
        }));
        markConsumed(idx, j);
        continue;
      }
      if (!op) op = valueTokens.length > 1 ? 'in' : 'eq';
      addMapping(t, t.targets[0], 'filter');
      if (opToken && opToken.type === 'op') {
        mappings.push({ term: text(opToken.span), span: opToken.span, role: 'operator', target: { kind: 'operator', id: op, label: op, pointer: '/' } });
      }
      applyParsed(this.#buildFilter(field, op, valueTokens, tokens.slice(idx, j), { fieldToken: t, opToken }), idx, j);
      idx = j - 1;
    }

    // ---------- pass 5: metrics ----------
    const metricTokens = [];
    for (let idx = 0; idx < tokens.length; idx += 1) {
      if (consumed.has(idx)) continue;
      if (isMetric(tokens[idx])) {
        metricTokens.push(tokens[idx]);
        addMapping(tokens[idx], tokens[idx].targets[0], 'metric');
      }
    }
    if (!metricTokens.length) {
      rejections.push(new ParseFailure('METRIC_REQUIRED', '未识别到任何已登记指标', {
        hint: '请在登记指标中选择，例如“销售额”“订单数”“客单价”。',
        suggestions: this.snapshot.doc.metrics.filter((m) => !m.hidden).map((m) => m.label),
      }));
    }
    if (metricTokens.length > 3) {
      rejections.push(new ParseFailure('TOO_MANY_METRICS', '一次最多查询 3 个指标', { hint: '请减少指标或拆分查询。' }));
    }

    // ---------- pass 6: residual ----------
    for (let idx = 0; idx < tokens.length; idx += 1) {
      if (consumed.has(idx)) continue;
      const t = tokens[idx];
      if (t.type === 'punct') continue;
      if (t.type === 'keyword' && (CONNECTOR_KEYS.has(t.key) || t.key === 'sort_keyword' || t.key === 'group_keyword' || t.key === 'currency' || t.key === 'eq_word' || t.key === 'counter' || t.key === 'all')) continue;
      if (t.type === 'keyword' && FILLER_UNITS[t.key]) continue;
      if (t.type === 'ambiguous') continue;
      if (t.type === 'op') {
        rejections.push(new ParseFailure('UNSUPPORTED_CLAUSE', `操作符“${text(t.span)}”没有可应用的已登记字段`, {
          span: t.span,
          hint: '操作符必须紧跟在可筛选字段之后，例如“金额大于 10000”；不支持对指标结果再做条件（无 HAVING）。',
        }));
        continue;
      }
      if (isNumber(t) || isDate(t)) {
        rejections.push(new ParseFailure('UNSUPPORTED_CLAUSE', `取值“${text(t.span)}”没有关联到任何已登记字段`, {
          span: t.span,
          hint: '请把取值写在字段之后，例如“金额在 1000 到 5000 之间”。',
        }));
        continue;
      }
      if (isMetric(t) || isField(t) || isGrain(t) || t.type === 'enum') continue;
      if (t.type === 'text') {
        rejections.push(new ParseFailure('UNRECOGNIZED_TERM', `“${text(t.span)}”不在规则 ${this.snapshot.meta.label} 的登记词表中`, {
          span: t.span,
          hint: '查询只能使用已登记的字段、指标、取值与操作符。',
          suggestions: this.#suggest(text(t.span)),
        }));
        continue;
      }
      if (t.type === 'keyword') {
        rejections.push(new ParseFailure('UNSUPPORTED_CLAUSE', `关键字“${text(t.span)}”在此处无法使用`, { span: t.span, hint: '请参考示例语法。' }));
      }
    }

    // ---------- assemble ----------
    const metrics = uniq(metricTokens.map((t) => t.targets[0].id)).map((id) => {
      const def = this.snapshot.doc.metrics.find((m) => m.id === id);
      return { id, label: def.label, unit: def.unit, kind: def.kind, hidden: Boolean(def.hidden) };
    });

    // metric hidden check
    for (const mt of metricTokens) {
      const target = mt.targets[0];
      const def = this.snapshot.doc.metrics.find((m) => m.id === target.id);
      if (def?.hidden) rejections.push(new ParseFailure('METRIC_INTERNAL', `“${def.label}”是内部派生项，不能直接查询`, { span: mt.span, hint: '请使用登记表中的展示指标。' }));
    }

    for (const f of filters) {
      const def = this.snapshot.doc.fields.find((x) => x.id === f.field);
      if (def?.pii) rejections.push(new ParseFailure('FIELD_PII_FORBIDDEN', `PII 字段“${def.label}”禁止用于筛选`, { span: f.span, hint: '仅允许使用登记的安全聚合指标。' }));
    }

    if (!time) {
      const roleDefault = 30; // role defaults are applied later in authorization
      time = {
        start: addDays(this.todayString, -(roleDefault - 1)),
        end: this.todayString,
        source: 'default',
        raw: null,
        tokens: [],
        defaultDays: roleDefault,
      };
    }

    if (rejections.length) return this.#fail(rejections, { rawText, mappings, warnings, normalized });

    // Normalize time bounds, clipping to the anchor.
    if (time.start > time.end) rejections.push(new ParseFailure('TIME_RANGE_REVERSED', `时间起点 ${time.start} 晚于终点 ${time.end}`, { hint: '请调整时间区间。' }));
    if (time.start > this.todayString) rejections.push(new ParseFailure('TIME_FUTURE', `时间区间 ${time.start} 超过当前锚点 ${this.todayString}`, { hint: '不能查询尚未发生的日期。' }));
    else if (time.end > this.todayString) {
      warnings.push({ code: 'TIME_CLIPPED', message: `结束日期 ${time.end} 超过当前锚点，已裁剪至 ${this.todayString}。` });
      time = { ...time, end: this.todayString, clipped: true };
    }

    if (direction && !group && !sortByMetricToken) {
      // sorting a single-row aggregate: harmless but meaningless
      warnings.push({ code: 'SORT_IGNORED', message: '未分组时排序不影响单行结果，已忽略。' });
      direction = null;
    }

    const intent = {
      metrics,
      filters: filters.map((f) => ({ ...f })),
      group,
      time,
      sort: direction || sortByMetricToken ? {
        direction: direction ?? 'desc',
        by: sortByMetricToken ? 'metric' : (group ? 'group' : 'metric'),
        metric: sortByMetricToken ? sortByMetricToken.targets[0].id : metrics[0]?.id ?? null,
        tokenSpan: sortByMetricToken?.span ?? directionToken?.span ?? null,
        explicit: true,
      } : {
        direction: group ? 'asc' : 'desc',
        by: group ? 'group' : 'metric',
        metric: metrics[0]?.id ?? null,
        explicit: false,
        tokenSpan: null,
      },
      limit: limit ?? null,
      limitSpan,
    };

    if (rejections.length) return this.#fail(rejections, { rawText, mappings, warnings, normalized });

    return {
      ok: true,
      normalizedText: normalized,
      rawText,
      intent,
      mappings,
      warnings,
      rejections: [],
      registry: this.#registryMeta(),
      asOf: this.asOf.toISOString(),
      today: this.todayString,
    };
  }

  #mergeTimeFilter(parsed, currentTime, rejections, text) {
    if (currentTime) {
      rejections.push(new ParseFailure('TIME_CONFLICT', '时间窗口与日期字段筛选重复', { span: parsed.span, hint: '请只保留一种时间表达。' }));
      return currentTime;
    }
    return {
      start: parsed.timeFilter.start,
      end: parsed.timeFilter.end,
      source: 'field_filter',
      raw: text(parsed.span),
      tokens: [],
    };
  }

  #resolveAnchor(key) {
    const today = this.today;
    const y = today.getUTCFullYear();
    const m = today.getUTCMonth();
    switch (key) {
      case 'today': return { start: this.todayString, end: this.todayString };
      case 'yesterday': return { start: addDays(this.todayString, -1), end: addDays(this.todayString, -1) };
      case 'this_week': {
        const dow = today.getUTCDay() || 7;
        const s = addDays(this.todayString, -(dow - 1));
        return { start: s, end: this.todayString };
      }
      case 'last_week': {
        const dow = today.getUTCDay() || 7;
        const end = addDays(this.todayString, -dow);
        return { start: addDays(end, -6), end };
      }
      case 'this_month': return { start: toDateString(new Date(Date.UTC(y, m, 1))), end: this.todayString };
      case 'last_month': {
        const s = toDateString(new Date(Date.UTC(y, m - 1, 1)));
        return { start: s, end: addDays(startOfMonth(`${toDateString(today).slice(0, 7)}-01`), -1) };
      }
      case 'this_quarter': return { start: startOfQuarter(this.todayString), end: this.todayString };
      case 'last_quarter': {
        const end = addDays(startOfQuarter(this.todayString), -1);
        return { start: startOfQuarter(end), end };
      }
      case 'this_year': return { start: startOfYear(this.todayString), end: this.todayString };
      case 'last_year': return { start: `${y - 1}-01-01`, end: `${y - 1}-12-31` };
      default: return { start: this.todayString, end: this.todayString };
    }
  }

  #buildFilter(field, op, valueTokens, spanTokens, ctx) {
    const span = spanOf(spanTokens);
    if (!field) return { error: new ParseFailure('FIELD_NOT_GRANTED', '字段未登记', { span }) };
    if (field.pii) return { error: new ParseFailure('FIELD_PII_FORBIDDEN', `PII 字段“${field.label}”禁止查询`, { span, hint: 'PII 字段既不可筛选也不可分组。' }) };
    if (field.filterable === false) return { error: new ParseFailure('FIELD_NOT_FILTERABLE', `字段“${field.label}”未登记为可筛选`, { span, hint: `该字段仅可用于 ${field.groupable ? '分组' : '展示'}。` }) };
    const allowedOps = Array.isArray(field.operators) ? field.operators : [];
    if (!allowedOps.includes(op)) return { error: new ParseFailure('OP_INCOMPATIBLE', `字段“${field.label}”不支持操作符 ${op}`, { span, hint: `可用操作：${allowedOps.join(', ')}` }) };

    if (field.type === 'date') {
      if (!['between', 'eq', 'in', 'gte', 'lte', 'gt', 'lt'].includes(op)) return { error: new ParseFailure('OP_INCOMPATIBLE', '日期字段仅支持区间/比较操作', { span }) };
      const dates = valueTokens.filter(isDate);
      if (!dates.length) return { error: new ParseFailure('VALUE_TYPE_INVALID', `日期字段“${field.label}”需要日期取值`, { span, hint: '例如“日期在 2026-10-01 到 2026-10-31”。' }) };
      if (op === 'between' || op === 'in' || dates.length === 2) {
        return { timeFilter: { start: dates[0].start, end: dates.at(-1).end }, span };
      }
      if (op === 'eq') return { timeFilter: { start: dates[0].start, end: dates[0].end }, span };
      return { error: new ParseFailure('TIME_INVALID', '日期字段的单个比较条件不足以构成时间窗', { span, hint: '请使用区间，例如“日期在 A 到 B”。' }) };
    }

    if (field.type === 'enum') {
      if (!['eq', 'neq', 'in', 'not_in'].includes(op)) return { error: new ParseFailure('OP_INCOMPATIBLE', `枚举字段“${field.label}”仅支持等于/属于/不等于/排除`, { span }) };
      const values = [];
      for (const v of valueTokens) {
        if (v.type === 'enum') {
          if (v.targets[0].id !== field.id) return { error: new ParseFailure('VALUE_FIELD_MISMATCH', `取值“${v.raw}”属于字段“${v.targets[0].fieldLabel}”，不属于“${field.label}”`, { span: v.span, hint: `请检查字段与取值的搭配。` }) };
          values.push(v.targets[0].value);
        } else if (v.type === 'text') {
          const def = field.enum.find((x) => [x.value, ...(x.aliases ?? [])].some((a) => normalizeForMatch(a) === normalizeForMatch(v.raw)));
          if (!def) return { error: new ParseFailure('VALUE_NOT_REGISTERED', `“${v.raw}”不是字段“${field.label}”的登记取值`, { span: v.span, hint: `登记取值：${field.enum.map((x) => x.value).join('、')}`, suggestions: field.enum.map((x) => x.value) }) };
          values.push(def.value);
        } else {
          return { error: new ParseFailure('VALUE_TYPE_INVALID', `字段“${field.label}”需要枚举取值`, { span: v.span, hint: `登记取值：${field.enum.map((x) => x.value).join('、')}` }) };
        }
      }
      if (!values.length) return { error: new ParseFailure('VALUE_MISSING', `字段“${field.label}”缺少取值`, { span }) };
      const finalOp = op === 'neq' && values.length > 1 ? 'not_in' : op === 'eq' && values.length > 1 ? 'in' : op;
      return { filter: { field: field.id, fieldLabel: field.label, column: field.column, type: field.type, op: finalOp, values, span } };
    }

    if (field.type === 'number') {
      if (!['eq', 'neq', 'in', 'not_in', 'gt', 'gte', 'lt', 'lte', 'between'].includes(op)) return { error: new ParseFailure('OP_INCOMPATIBLE', `数值字段“${field.label}”不支持该操作符`, { span }) };
      const nums = valueTokens.filter(isNumber);
      if (nums.length === 0) {
        const bad = valueTokens.find((v) => v.type === 'enum' || v.type === 'text');
        if (bad) return { error: new ParseFailure('VALUE_TYPE_INVALID', `字段“${field.label}”需要数值`, { span: bad.span, hint: '例如“金额大于 10000”。' }) };
        return { error: new ParseFailure('VALUE_MISSING', `字段“${field.label}”缺少数值`, { span }) };
      }
      if (op === 'between' && nums.length !== 2) return { error: new ParseFailure('BETWEEN_INVALID', '区间条件需要两个边界值', { span }) };
      if ((op === 'gt' || op === 'gte' || op === 'lt' || op === 'lte' || op === 'eq' || op === 'neq') && nums.length > 1) return { error: new ParseFailure('VALUE_TYPE_INVALID', '比较操作只接受一个数值', { span }) };
      const scale = field.scale ?? 0;
      const factor = 10 ** scale;
      const values = nums.map((n) => n.value * factor);
      if (op === 'between' && values[0] > values[1]) return { error: new ParseFailure('BETWEEN_INVALID', '区间下界大于上界', { span }) };
      return { filter: { field: field.id, fieldLabel: field.label, column: field.column, type: field.type, op, values, rawValues: nums.map((n) => n.raw), scale, span } };
    }

    if (field.type === 'string' || field.type === 'id') {
      if (op !== 'contains' && op !== 'eq' && op !== 'neq') return { error: new ParseFailure('OP_INCOMPATIBLE', `字符串字段“${field.label}”仅支持等于/包含`, { span }) };
      return { error: new ParseFailure('FIELD_NOT_GRANTED', `字符串字段“${field.label}”未开放自由文本筛选`, { span, hint: '自由文本值无法保证在登记范围内，已拒绝。' }) };
    }

    return { error: new ParseFailure('OP_INCOMPATIBLE', `字段“${field.label}”不支持筛选`, { span }) };
  }

  #suggest(term) {
    const candidates = new Set();
    const key = normalizeForMatch(term);
    for (const entry of this.lexicon.entries) {
      if (entry.alias.includes(key) || key.includes(entry.alias)) {
        for (const t of entry.targets) if (t.kind === 'metric') candidates.add(t.label);
      }
      if (candidates.size >= 5) break;
    }
    for (const m of this.snapshot.doc.metrics) {
      if (m.aliases.some((a) => normalizeForMatch(a).includes(key) || key.includes(normalizeForMatch(a)))) candidates.add(m.label);
      if (candidates.size >= 5) break;
    }
    return [...candidates].slice(0, 5);
  }
}
