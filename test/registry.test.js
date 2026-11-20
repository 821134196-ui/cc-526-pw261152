import test from 'node:test';
import assert from 'node:assert/strict';
import { RuleRegistry, validateRuleDoc, computeAmbiguities, FILTER_OPS } from '../src/registry.js';
import { cloneDraft } from './helpers.js';

test('seed registry exposes three immutable versions with valid documents', () => {
  const registry = new RuleRegistry();
  const versions = registry.list();
  assert.deepEqual(versions.map((v) => v.label), ['v1', 'v2', 'v3']);
  for (const version of registry.versions) {
    const verdict = validateRuleDoc(version.doc);
    assert.deepEqual(verdict.errors, [], `${version.meta.label} should validate`);
    assert.ok(Object.isFrozen(version));
    assert.ok(Object.isFrozen(version.doc));
  }
  assert.equal(registry.current(new Date('2026-09-20T00:00:00Z')).meta.label, 'v2');
  assert.equal(registry.current(new Date('2026-11-20T00:00:00Z')).meta.label, 'v3');
});

test('registry version is content-addressed: identical docs hash identically', () => {
  const a = new RuleRegistry();
  const b = new RuleRegistry();
  assert.equal(a.current().meta.registryVersion, b.current().meta.registryVersion);
});

test('v2 has an acknowledged ambiguity on 业绩 while v3 resolves it', () => {
  const registry = new RuleRegistry();
  const v2 = registry.snapshot('v2');
  const v3 = registry.snapshot('v3');
  assert.deepEqual(computeAmbiguities(v2.doc).map((a) => a.term), ['业绩']);
  assert.deepEqual(computeAmbiguities(v3.doc), []);
});

test('validation rejects PII grants, unknown references and bad operators', () => {
  const registry = new RuleRegistry();
  const doc = cloneDraft(registry.snapshot('v3'));
  doc.roles.analyst.allowedFields.push('email');
  doc.metrics[0].definition.field = 'does_not_exist';
  doc.fields[0].operators = ['regex'];
  const verdict = validateRuleDoc(doc);
  const codes = verdict.errors.map((e) => e.code);
  assert.ok(codes.includes('PII_ROLE_GRANT'));
  assert.ok(codes.includes('METRIC_FIELD_UNKNOWN'));
  assert.ok(codes.includes('FIELD_OPS_INVALID'));
});

test('validation forbids PII fields from being filterable or groupable', () => {
  const registry = new RuleRegistry();
  const doc = cloneDraft(registry.snapshot('v3'));
  const phone = doc.fields.find((f) => f.id === 'phone');
  phone.filterable = true;
  phone.groupable = true;
  const codes = validateRuleDoc(doc).errors.map((e) => e.code);
  assert.ok(codes.includes('PII_FILTERABLE'));
  assert.ok(codes.includes('PII_GROUPABLE'));
});

test('every registered operator is from the closed operator list', () => {
  const registry = new RuleRegistry();
  for (const version of registry.versions) {
    for (const f of version.doc.fields) {
      for (const op of f.operators) assert.ok(FILTER_OPS.includes(op), `${f.id} uses ${op}`);
    }
    for (const r of Object.values(version.doc.roles)) {
      for (const op of r.allowedOps) assert.ok(FILTER_OPS.includes(op), `role uses ${op}`);
    }
  }
});
