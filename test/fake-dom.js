/*
 * Minimal DOM harness so the browser module can be exercised in Node without a
 * headless browser. It is intentionally tiny: enough surface for app.js to
 * boot, register handlers, and render. It is not a general DOM implementation.
 */
import { pathToFileURL } from 'node:url';
import path from 'node:path';

class ClassList {
  constructor() { this.set = new Set(); }
  add(...names) { for (const n of names) this.set.add(n); }
  remove(...names) { for (const n of names) this.set.delete(n); }
  toggle(name, force) {
    const on = force === undefined ? !this.set.has(name) : Boolean(force);
    if (on) this.set.add(name); else this.set.delete(name);
    return on;
  }
  contains(name) { return this.set.has(name); }
  get value() { return [...this.set].join(' '); }
  set value(v) { this.set = new Set(String(v).split(/\s+/).filter(Boolean)); }
}

const FORMULA_LIKE = /^[=+\-@]/;

export class FakeElement {
  constructor(selector, doc) {
    this.selector = selector;
    this.ownerDocument = doc;
    this._innerHTML = '';
    this.textContent = '';
    this.className = '';
    this.classList = new ClassList();
    this.style = {};
    this.dataset = {};
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.title = '';
    this.listeners = new Map();
    this.children = [];
    this._download = '';
  }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(v) {
    if (FORMULA_LIKE.test(String(v).trim())) throw new Error('suspicious innerHTML assignment');
    this._innerHTML = String(v);
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  dispatch(type, event = {}) {
    const fake = {
      preventDefault() {}, stopPropagation() {},
      target: { closest: () => null, querySelector: () => new FakeElement('button[type=submit]', this.ownerDocument), dataset: {} },
      ...event,
    };
    const results = [];
    for (const fn of this.listeners.get(type) ?? []) results.push(fn(fake));
    return Promise.all(results);
  }
  querySelector(sel) { return this.ownerDocument.querySelector(sel); }
  querySelectorAll(sel) { return this.ownerDocument.querySelectorAll(sel); }
  closest() { return null; }
  requestSubmit() { return this.dispatch('submit'); }
  focus() {}
  click() {}
  appendChild(child) { this.children.push(child); }
}

export class FakeDocument {
  constructor() {
    this.elements = new Map();
    this.cookie = '';
  }
  elementFor(selector) {
    if (!this.elements.has(selector)) this.elements.set(selector, new FakeElement(selector, this));
    return this.elements.get(selector);
  }
  querySelector(selector) {
    // Dynamic selectors (e.g. #drill-verdict-3) resolve lazily.
    return this.elementFor(selector);
  }
  querySelectorAll(selector) {
    if (selector === '#tabs .tab') {
      return ['query', 'rules', 'audit', 'drills'].map((name) => {
        const el = this.elementFor(`#tabs .tab[data-tab="${name}"]`);
        el.dataset.tab = name;
        return el;
      });
    }
    if (selector === '.tab') return this.querySelectorAll('#tabs .tab');
    return [];
  }
  createElement(tag) {
    const el = new FakeElement(tag, this);
    if (tag === 'a') {
      Object.defineProperty(el, 'href', { get: () => el._href ?? '', set: (v) => { el._href = v; } });
    }
    return el;
  }
}

export async function loadApp({ fetchImpl }) {
  const doc = new FakeDocument();
  const store = new Map();
  const appPath = pathToFileURL(path.resolve(import.meta.dirname, '../public/app.js')).href;
  globalThis.document = doc;
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  globalThis.fetch = fetchImpl;
  globalThis.URL.createObjectURL = () => 'blob:fake';
  globalThis.URL.revokeObjectURL = () => {};
  // Fresh module instance per harness run.
  const mod = await import(`${appPath}?v=${Math.random()}`);
  await new Promise((r) => setTimeout(r, 0));
  return { doc, mod };
}
