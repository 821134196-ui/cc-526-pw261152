import { addDays, daysBetween, parseDateString, toDateString, sha256, canonicalJson } from './util.js';

/*
 * Synthetic, deterministic order warehouse.
 *
 * Every row lives in a monthly "partition" file under data/. A query only pins
 * the partitions it actually touches, so asking the same question against the
 * same rule version yields byte-identical results and evidence.
 */

const REGIONS = ['华东', '华南', '华北', '西南', '西北'];
const CHANNELS = ['直营', '分销', '电商', '门店'];
const CATEGORIES = ['数码', '家电', '服饰', '美妆', '食品', '其他'];
const SEGMENTS = ['新客', '老客', '会员', '企业', '未分层'];

const PRODUCTS = {
  数码: [{ name: '真无线耳机', price: 89900 }, { name: '智能手表', price: 159900 }, { name: '便携投影仪', price: 289900 }],
  家电: [{ name: '空气净化器', price: 129900 }, { name: '扫地机器人', price: 219900 }, { name: '电热水壶', price: 19900 }],
  服饰: [{ name: '轻羽夹克', price: 59900 }, { name: '跑步鞋', price: 45900 }, { name: '羊毛围巾', price: 15900 }],
  美妆: [{ name: '精华液套装', price: 68900 }, { name: '防晒喷雾', price: 9900 }, { name: '口红礼盒', price: 29900 }],
  食品: [{ name: '坚果礼包', price: 12900 }, { name: '冻干咖啡', price: 9900 }, { name: '有机杂粮', price: 7900 }],
  其他: [{ name: '定制礼品卡', price: 50000 }, { name: '环保购物袋', price: 2900 }],
};

const REGION_FACTOR = { 华东: 1.0, 华南: 0.82, 华北: 0.71, 西南: 0.53, 西北: 0.31 };
const CHANNEL_FACTOR = { 直营: 1.0, 分销: 0.74, 电商: 1.28, 门店: 0.66 };

// 2026 weekday holiday bump so period comparisons are not flat noise.
const DAILY_BOOST = { '01-01': 1.6, '02-14': 1.4, '05-01': 1.8, '06-18': 1.9, '10-01': 1.7, '11-11': 2.6, '12-12': 2.2, '12-24': 1.5 };

function mulberry32(seed) {
  let a = seed >>> 0;
  return function random() {
    a += 0x6d2b79f5;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pickWeighted(rand, items, weights) {
  const total = weights.reduce((a, b) => a + b, 0);
  let roll = rand() * total;
  for (let i = 0; i < items.length; i += 1) {
    roll -= weights[i];
    if (roll <= 0) return items[i];
  }
  return items.at(-1);
}

export function monthKey(dateString) {
  return dateString.slice(0, 7);
}

export function monthRange(startDate, endDate) {
  const months = [];
  let d = parseDateString(`${startDate.slice(0, 7)}-01`);
  const end = parseDateString(endDate);
  while (d <= end) {
    months.push(toDateString(d).slice(0, 7));
    d = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1));
  }
  return months;
}

export function generatePartition(month, { seed = 'rulegate-v1' } = {}) {
  const rand = mulberry32(Number.parseInt(sha256(`${seed}:${month}`).slice(0, 8), 16));
  const [y, m] = month.split('-').map(Number);
  const daysInMonth = new Date(Date.UTC(y, m, 0)).getUTCDate();
  const rows = [];
  for (let day = 1; day <= daysInMonth; day += 1) {
    const date = `${month}-${String(day).padStart(2, '0')}`;
    const dow = new Date(`${date}T00:00:00Z`).getUTCDay();
    const boost = DAILY_BOOST[date.slice(5)] ?? 1;
    const weekend = dow === 0 || dow === 6 ? 1.22 : 1;
    const base = 26 * boost * weekend;
    const count = Math.max(3, Math.round(base * (0.7 + rand() * 0.6)));
    const regionWeights = REGIONS.map((r) => REGION_FACTOR[r] * (0.85 + rand() * 0.3));
    for (let i = 0; i < count; i += 1) {
      const region = pickWeighted(rand, REGIONS, regionWeights);
      const channel = pickWeighted(rand, CHANNELS, CHANNELS.map((c) => CHANNEL_FACTOR[c] * (0.8 + rand() * 0.4)));
      const category = pickWeighted(rand, CATEGORIES, [1.6, 1.1, 1.4, 0.9, 1.2, 0.35]);
      const product = PRODUCTS[category][Math.floor(rand() * PRODUCTS[category].length)];
      const quantity = 1 + Math.floor(rand() * (rand() < 0.12 ? 6 : 3));
      const gross = product.price * quantity;
      const discountRate = rand() < 0.42 ? Math.round(rand() * 18) / 100 : 0;
      const discount = Math.round(gross * discountRate);
      const amount = gross - discount;
      const cost = Math.round(gross * (0.52 + rand() * 0.16));
      const refunded = rand() < 0.061 ? Math.round(amount * (0.35 + rand() * 0.65)) : 0;
      const segment = pickWeighted(rand, SEGMENTS, [2.4, 2.1, 1.7, 0.7, 1.0]);
      const store = channel === '门店' || channel === '直营'
        ? pickWeighted(rand, ['旗舰店', '社区店', '云店'], [1.2, 1.6, 1.0])
        : null;
      const seq = rows.length + 1;
      rows.push({
        order_id: `SO${month.replace('-', '')}${String(seq).padStart(5, '0')}`,
        order_date: date,
        region,
        channel,
        product_category: category,
        product_name: product.name,
        customer_segment: segment,
        store,
        quantity,
        gross_amount: gross,
        discount,
        amount,
        cost,
        refund_amount: refunded,
        customer_id: `C${sha256(`${region}:${customerOrdinal(rand, region)}`).slice(0, 10)}`,
        email: `buyer${String(seq).padStart(4, '0')}@example.test`,
        phone: `1380000${String(1000 + (seq % 9000))}`,
      });
    }
  }
  rows.sort((a, b) => (a.order_id < b.order_id ? -1 : 1));
  const payload = { month, seed, rows };
  return { ...payload, rowCount: rows.length, contentHash: sha256(canonicalJson(rows)) };
}

function customerOrdinal(rand, region) {
  return `${region}-${Math.floor(rand() * 400)}`;
}

export class DataWarehouse {
  constructor({ dataDir }) {
    this.dataDir = dataDir;
  }

  async partition(month, { seed = 'rulegate-v1', write = false, fs } = {}) {
    const file = `${this.dataDir}/orders-${month}.json`;
    const { promises: fsp } = fs ?? await import('node:fs');
    try {
      const raw = await fsp.readFile(file, 'utf8');
      return JSON.parse(raw);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const generated = generatePartition(month, { seed });
      if (write) {
        await fsp.mkdir(this.dataDir, { recursive: true });
        await fsp.writeFile(file, JSON.stringify(generated));
      }
      return generated;
    }
  }

  async materialize({ start, end, seed, write = true }) {
    if (daysBetween(start, end) < 0) return [];
    const months = monthRange(start, end);
    const out = [];
    for (const month of months) out.push(await this.partition(month, { seed, write }));
    return out;
  }
}
