import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createService } from '../src/service.js';
import { RuleRegistry, computeAmbiguities } from '../src/registry.js';

export const AS_OF = '2026-11-20T10:00:00.000Z';

export function tmpDir(prefix = 'rulegate-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function makeService(overrides = {}) {
  const dir = tmpDir();
  const clock = () => new Date(overrides.now ?? AS_OF);
  const built = createService({
    dataDir: path.join(dir, 'data'),
    persistDir: path.join(dir, 'state'),
    auditDir: path.join(dir, 'audit'),
    now: clock,
  });
  return { ...built, dir, clock };
}

/** Turn a registry snapshot into an editable draft document. */
export function cloneDraft(snapshot) {
  const doc = snapshot.doc ?? snapshot;
  return {
    schemaVersion: 1,
    label: 'v0',
    publishedAt: '2026-11-20T00:00:00.000Z',
    notes: 'test draft',
    calendar: { timezone: 'UTC' },
    acknowledgedAmbiguities: computeAmbiguities(doc).map((a) => a.term),
    timeGrains: structuredClone(doc.timeGrains),
    fields: structuredClone(doc.fields),
    metrics: structuredClone(doc.metrics),
    roles: structuredClone(doc.roles),
  };
}

export function seedDraft(label = 'v3') {
  return cloneDraft(new RuleRegistry().snapshot(label));
}
