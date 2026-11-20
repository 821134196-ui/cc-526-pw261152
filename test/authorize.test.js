import test from 'node:test';
import assert from 'node:assert/strict';
import { RuleRegistry } from '../src/registry.js';
import { RestrictedQueryParser } from '../src/parser.js';
import { authorizeIntent } from '../src/authorize.js';
import { AS_OF } from './helpers.js';

const registry = new RuleRegistry();
const snapshot = registry.snapshot('v3');
const parser = new RestrictedQueryParser(snapshot, { asOf: AS_OF });

function auth(text, roleId) {
  const parse = parser.parse(text);
  assert.equal(parse.ok, true, `${text} should parse: ${JSON.stringify(parse.rejections)}`);
  const result = authorizeIntent({ snapshot, roleId, intent: parse.intent });
  return { parse, result };
}

test('analyst may query across all regions', () => {
  const { result } = auth('最近30天各渠道的销售额', 'analyst');
  assert.equal(result.ok, true);
  assert.deepEqual(result.appliedScopes, []);
});

test('sales_west is confined to 华东 rows even without a filter', () => {
  const { result } = auth('最近30天各渠道的销售额', 'sales_west');
  assert.equal(result.ok, true);
  assert.equal(result.appliedScopes.length, 1);
  assert.equal(result.appliedScopes[0].field, 'region');
  assert.deepEqual(result.appliedScopes[0].values, ['华东']);
  assert.equal(result.appliedScopes[0].source, 'role');
});

test('sales_west cannot widen scope by naming another region', () => {
  const { result } = auth('最近30天华南的销售额', 'sales_west');
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === 'SCOPE_VIOLATION'));
});

test('sales_west can narrow within scope', () => {
  const { result } = auth('最近30天华东的销售额', 'sales_west');
  assert.equal(result.ok, true);
  assert.equal(result.appliedScopes.length, 1);
  assert.deepEqual(result.appliedScopes[0].values, ['华东']);
});

test('excluding the only in-scope region leaves nothing and is denied', () => {
  const { result } = auth('排除华东的销售额', 'sales_west');
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === 'SCOPE_VIOLATION'));
});

test('exclusion within a multi-region role narrows to the remainder', () => {
  const { result } = auth('排除华东的销售额', 'analyst');
  assert.equal(result.ok, true);
});

test('role range limits are enforced after parsing', () => {
  const { result } = auth('最近180天各渠道的销售额', 'sales_west');
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === 'RANGE_TOO_LONG'));
});

test('role limit is enforced', () => {
  const { result } = auth('最近30天各渠道的销售额，前500', 'sales_west');
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === 'LIMIT_EXCEEDED'));
});

test('metrics outside the role grant are denied', () => {
  const { result } = auth('最近30天客户数', 'sales_west');
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === 'METRIC_NOT_GRANTED'));
});

test('fields outside the role grant are denied', () => {
  const { result } = auth('最近30天各品类的销售额', 'sales_west');
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === 'FIELD_NOT_GRANTED'));
});

test('unknown role is denied', () => {
  const parse = parser.parse('最近30天的销售额');
  const result = authorizeIntent({ snapshot, roleId: 'ghost', intent: parse.intent });
  assert.equal(result.ok, false);
  assert.equal(result.violations[0].code, 'ROLE_UNKNOWN');
});

test('authorization is evaluated against the pinned snapshot, not the latest', () => {
  const v1 = registry.snapshot('v1');
  const p1 = new RestrictedQueryParser(v1, { asOf: AS_OF });
  const parse = p1.parse('最近30天各渠道的销售额');
  assert.equal(parse.ok, true);
  // v1 has no 毛利率 metric, so the field cannot even be referenced.
  const historical = authorizeIntent({ snapshot: v1, roleId: 'analyst', intent: parse.intent });
  assert.equal(historical.ok, true);
  assert.equal(historical.role.maxRangeDays, 400);
});
