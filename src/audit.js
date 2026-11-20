import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson, sha256 } from './util.js';

/*
 * Append-only audit ledger.
 *
 * Every query attempt (allowed or denied), replay, publish and export writes one
 * record. Records are chained: each entry stores prevHash and its own hash over
 * the canonical record, so tampering with any record invalidates all later ones.
 * This is tamper-evident, not tamper-proof: the ledger file is outside the API's
 * write path and can be mirrored externally.
 */

const GENESIS = '0'.repeat(64);

export class AuditLedger {
  constructor({ auditDir = null, now = () => new Date() } = {}) {
    this.auditDir = auditDir;
    this.now = now;
    this.records = [];
    if (auditDir) fs.mkdirSync(auditDir, { recursive: true });
    this.load();
  }

  load() {
    if (!this.auditDir) return;
    const file = path.join(this.auditDir, 'audit.jsonl');
    if (!fs.existsSync(file)) return;
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        const rec = JSON.parse(line);
        if (rec && typeof rec.seq === 'number') this.records.push(rec);
      } catch {
        // A corrupt line is preserved in the file; verification will report it.
        this.records.push({ corrupt: true, raw: line });
      }
    }
  }

  append(type, payload, { actor, registryVersion = null } = {}) {
    const seq = this.records.length + 1;
    const prev = this.records.at(-1);
    const prevHash = prev?.hash ?? GENESIS;
    const body = {
      schema: 'rulegate.audit/v1',
      seq,
      type,
      at: this.now().toISOString(),
      actor: actor ?? 'anonymous',
      registryVersion,
      payload,
      prevHash,
    };
    const hash = sha256(canonicalJson(body));
    const record = { ...body, hash };
    this.records.push(record);
    if (this.auditDir) {
      fs.appendFileSync(path.join(this.auditDir, 'audit.jsonl'), `${JSON.stringify(record)}\n`);
    }
    return record;
  }

  head() {
    return this.records.at(-1)?.hash ?? GENESIS;
  }

  list({ limit = 100, type = null, actor = null, queryId = null } = {}) {
    let items = this.records;
    if (type) items = items.filter((r) => r.type === type);
    if (actor) items = items.filter((r) => r.actor === actor);
    if (queryId) items = items.filter((r) => r.payload?.queryId === queryId);
    return items.slice(-limit).reverse();
  }

  find(queryId) {
    return this.records.find((r) => r.payload?.queryId === queryId) ?? null;
  }

  verify() {
    let prevHash = GENESIS;
    const problems = [];
    for (const rec of this.records) {
      if (rec.corrupt) { problems.push({ seq: null, code: 'CORRUPT_LINE', detail: '存在无法解析的记录行' }); continue; }
      if (rec.prevHash !== prevHash) problems.push({ seq: rec.seq, code: 'CHAIN_BROKEN', detail: `记录的 prevHash 与上一条 hash 不一致` });
      const { hash, ...body } = rec;
      const expected = sha256(canonicalJson(body));
      if (expected !== hash) problems.push({ seq: rec.seq, code: 'HASH_MISMATCH', detail: '记录内容与其 hash 不匹配' });
      prevHash = rec.hash;
    }
    return { ok: problems.length === 0, records: this.records.length, head: this.head(), problems };
  }

  /** Export a verifiable audit bundle for a window of records. */
  exportBundle({ fromSeq = 1, toSeq = null } = {}) {
    const all = this.records.filter((r) => !r.corrupt);
    const to = toSeq ?? all.at(-1)?.seq ?? 0;
    // The export record is appended before the bundle is rendered; snapshot now.
    const window = all.filter((r) => r.seq >= fromSeq && r.seq <= to);
    const first = window[0];
    const last = window.at(-1);
    return {
      schema: 'rulegate.audit-bundle/v1',
      exportedAt: this.now().toISOString(),
      range: { fromSeq: first?.seq ?? null, toSeq: last?.seq ?? null, count: window.length },
      startingPrevHash: first?.prevHash ?? null,
      endingHash: last?.hash ?? null,
      ledgerHead: last?.hash ?? this.head(),
      records: window,
    };
  }
}
