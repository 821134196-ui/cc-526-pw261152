import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const SCRYPT_N = 16384;
const SCRYPT_r = 8;
export const DEMO_ACCOUNTS = [
  { username: 'alice', password: 'analyst-demo-2026', displayName: 'Alice（数据分析师）', roleId: 'analyst' },
  { username: 'wang', password: 'west-demo-2026', displayName: 'Wang（华东销售）', roleId: 'sales_west' },
  { username: 'li', password: 'east-demo-2026', displayName: 'Li（华南销售）', roleId: 'sales_east' },
  { username: 'audit', password: 'audit-demo-2026', displayName: 'Audit（审计员）', roleId: 'auditor' },
  { username: 'admin', password: 'rules-demo-2026', displayName: 'Admin（规则管理员）', roleId: 'rules_admin' },
];

function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const derived = scryptSync(password, salt, 32, { N: SCRYPT_N, r: SCRYPT_r, p: 1, maxmem: 64 * 1024 * 1024 });
  return { salt, hash: derived.toString('hex') };
}

export function verifyPassword(password, salt, expectedHex) {
  const derived = scryptSync(password, salt, 32, { N: SCRYPT_N, r: SCRYPT_r, p: 1, maxmem: 64 * 1024 * 1024 });
  const expected = Buffer.from(expectedHex, 'hex');
  if (expected.length !== derived.length) return false;
  return timingSafeEqual(derived, expected);
}

export class AuthStore {
  constructor({ accounts = DEMO_ACCOUNTS } = {}) {
    this.accounts = new Map();
    for (const account of accounts) {
      const { salt, hash } = hashPassword(account.password);
      this.accounts.set(account.username, { ...account, salt, hash });
    }
    this.sessions = new Map();
    this.failedAttempts = new Map();
  }

  login(username, password, { ip = 'unknown' } = {}) {
    const key = `${ip}:${username}`;
    const attempts = this.failedAttempts.get(key) ?? { count: 0, first: Date.now() };
    if (attempts.count >= 8 && Date.now() - attempts.first < 5 * 60 * 1000) {
      const error = new Error('登录尝试过于频繁，请 5 分钟后再试');
      error.code = 'LOGIN_THROTTLED';
      throw error;
    }
    const account = this.accounts.get(username);
    const ok = account ? verifyPassword(password, account.salt, account.hash) : (verifyPassword(password, 'decoy', '00'.repeat(32)), false);
    if (!ok) {
      attempts.count += 1;
      if (Date.now() - attempts.first > 5 * 60 * 1000) { attempts.count = 1; attempts.first = Date.now(); }
      this.failedAttempts.set(key, attempts);
      const error = new Error('用户名或密码错误');
      error.code = 'LOGIN_FAILED';
      throw error;
    }
    this.failedAttempts.delete(key);
    const token = randomBytes(32).toString('base64url');
    const session = {
      token,
      username: account.username,
      displayName: account.displayName,
      roleId: account.roleId,
      createdAt: Date.now(),
      expiresAt: Date.now() + 8 * 60 * 60 * 1000,
    };
    this.sessions.set(token, session);
    return session;
  }

  resolve(token) {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;
    if (session.expiresAt < Date.now()) { this.sessions.delete(token); return null; }
    return session;
  }

  logout(token) { this.sessions.delete(token); }
}
