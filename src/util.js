import { createHash } from 'node:crypto';

export function canonicalJson(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortDeep(value[key]);
    return out;
  }
  return value;
}

export function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : canonicalJson(value)).digest('hex');
}

export function shortHash(hash, length = 12) {
  return typeof hash === 'string' ? hash.slice(0, length) : '';
}

export function deepFreeze(value) {
  if (value && (typeof value === 'object' || typeof value === 'function') && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

export function clone(value) {
  return structuredClone(value);
}

export function toDateString(date) {
  const d = date instanceof Date ? date : new Date(date);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
}

export function parseDateString(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return null;
  const date = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  if (toDateString(date) !== value) return null;
  return date;
}

export function addDays(dateString, days) {
  const date = parseDateString(dateString);
  if (!date) throw new Error(`Invalid date: ${dateString}`);
  date.setUTCDate(date.getUTCDate() + days);
  return toDateString(date);
}

export function daysBetween(start, end) {
  const a = parseDateString(start);
  const b = parseDateString(end);
  return Math.round((b - a) / 86400000);
}

export function startOfMonth(dateString) {
  return `${dateString.slice(0, 7)}-01`;
}

export function startOfQuarter(dateString) {
  const d = parseDateString(dateString);
  const month = d.getUTCMonth();
  const qStart = Math.floor(month / 3) * 3;
  return toDateString(new Date(Date.UTC(d.getUTCFullYear(), qStart, 1)));
}

export function startOfYear(dateString) {
  return `${dateString.slice(0, 4)}-01-01`;
}

export function nowIso(now) {
  return (now instanceof Date ? now : new Date(now)).toISOString();
}

export function clampText(value, max = 240) {
  const text = typeof value === 'string' ? value : String(value ?? '');
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function toInt(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

export function escapeCsvCell(value) {
  let text = value === null || value === undefined ? '' : String(value);
  // Neutralize spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  if (/["\n\r,]/.test(text)) text = `"${text.replaceAll('"', '""')}"`;
  return text;
}

export function csvRows(rows) {
  return rows.map((row) => row.map(escapeCsvCell).join(',')).join('\r\n');
}

export function uniq(values) {
  return [...new Set(values)];
}

export function normalizeForMatch(text) {
  return String(text ?? '')
    .normalize('NFKC')
    .replace(/[，、；]/g, ',')
    .replace(/[：]/g, ':')
    .replace(/[（]/g, '(')
    .replace(/[）]/g, ')')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}
