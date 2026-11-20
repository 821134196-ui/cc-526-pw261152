const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const state = {
  session: null,
  registry: null,
  versions: [],
  lastRun: null,
  drillRows: [],
  auditRecords: [],
};

const EXAMPLES = [
  { text: '最近30天各渠道的销售额和订单数', note: '基础分组' },
  { text: '最近30天销售额，按品类，降序，前3', note: '分组+排序+截断' },
  { text: '2026年第三季度华东的销售额', note: '绝对区间+枚举' },
  { text: '最近90天订单金额大于5000的订单数', note: '数值比较' },
  { text: '近3个月按月的客单价', note: '时间粒度分组' },
  { text: '最近30天毛利率', note: '比率指标' },
  { text: '最近30天的业绩', note: 'v3 已消歧，v2 会拒绝' },
  { text: '排除华南的销售额', note: '排除条件' },
  { text: '最近30天订单金额在1000到5000之间的订单数', note: '区间' },
  { text: '最近30天各渠道的销售额排名', note: '预期拒绝：未登记“排名”' },
  { text: '最近30天客户的邮箱', note: '预期拒绝：PII' },
  { text: '最近30天各门店的客户数', note: '小样本抑制（若角色启用）' },
];

const DRILLS = [
  { text: '最近30天的业绩', registryRef: 'v2', expect: 'reject:AMBIGUOUS_TERM', role: 'analyst' },
  { text: '最近30天的业绩', registryRef: 'v3', expect: 'ok', role: 'analyst' },
  { text: '最近30天各渠道的销售额排名', registryRef: null, expect: 'reject:UNRECOGNIZED_TERM' },
  { text: '最近30天客户邮箱', registryRef: null, expect: 'reject:FIELD_PII_FORBIDDEN' },
  { text: '最近30天按客户编号分组统计客户数', registryRef: null, expect: 'reject:FIELD_PII_FORBIDDEN' },
  { text: '最近30天华南的销售额', registryRef: null, expect: 'reject:SCOPE_VIOLATION', role: 'sales_west' },
  { text: '最近400天各渠道的销售额', registryRef: null, expect: 'reject:RANGE_TOO_LONG', role: 'sales_west' },
  { text: '删除所有订单', registryRef: null, expect: 'reject:DANGEROUS_INTENT' },
  { text: '最近30天销售额，按品类，前500', registryRef: null, expect: 'reject:LIMIT_EXCEEDED', role: 'sales_west' },
  { text: '最近30天订单金额大于5000的销售额', registryRef: null, expect: 'ok' },
  { text: '把所有客户手机号导出', registryRef: null, expect: 'reject:DANGEROUS_INTENT' },
  { text: '近3个月按月的销售额和订单数', registryRef: null, expect: 'ok' },
];

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function short(hash, n = 12) { return hash ? esc(String(hash).slice(0, n)) : '—'; }
function daysInclusive(start, end) {
  return Math.round((Date.parse(`${end}T00:00:00Z`) - Date.parse(`${start}T00:00:00Z`)) / 86400000) + 1;
}

function toast(message, kind = 'ok') {
  const el = $('#toast');
  el.textContent = message;
  el.className = `toast${kind === 'bad' ? ' bad' : ''}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.add('hidden'), 3200);
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers ?? {}) };
  const res = await fetch(path, { credentials: 'same-origin', ...options, headers });
  const type = res.headers.get('content-type') ?? '';
  if (!res.ok) {
    let payload;
    if (type.includes('application/json')) payload = await res.json();
    else payload = { error: { code: 'HTTP_ERROR', message: await res.text() } };
    const error = new Error(payload.error?.message ?? `HTTP ${res.status}`);
    error.code = payload.error?.code ?? `HTTP_${res.status}`;
    error.status = res.status;
    error.details = payload.error?.details;
    error.payload = payload;
    throw error;
  }
  if (type.includes('application/json')) return res.json();
  return { raw: await res.text(), headers: res.headers };
}

/* ---------------- login ---------------- */
async function loadDemoAccounts() {
  try {
    const data = await api('/api/demo-accounts');
    const list = $('#demo-list');
    list.innerHTML = data.accounts.map((a) => `
      <button class="demo-item" type="button" data-user="${esc(a.username)}" data-pass="${esc(a.password)}">
        <span>${esc(a.displayName)}</span>
        <span class="cred">${esc(a.username)} / ${esc(a.password)}</span>
      </button>`).join('');
    list.querySelectorAll('.demo-item').forEach((btn) => {
      btn.addEventListener('click', () => {
        $('#login-user').value = btn.dataset.user;
        $('#login-pass').value = btn.dataset.pass;
        $('#login-form').requestSubmit();
      });
    });
  } catch {
    $('#demo-list').innerHTML = '<p class="muted">演示账号不可用，请手动输入。</p>';
  }
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#login-error').textContent = '';
  const btn = event.target.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = '登录中…';
  try {
    await api('/api/login', { method: 'POST', body: JSON.stringify({ username: $('#login-user').value, password: $('#login-pass').value }) });
    await enterApp();
  } catch (error) {
    $('#login-error').textContent = error.message;
  } finally {
    btn.disabled = false;
    btn.textContent = '进入查询台';
  }
});

$('#logout-btn').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST', body: '{}' }); } catch { /* ignore */ }
  state.session = null;
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
});

async function enterApp() {
  const session = await api('/api/session');
  state.session = session;
  state.registry = session.registry;
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#session-name').textContent = session.session.displayName;
  $('#session-role').textContent = `${session.role.label} · ${session.role.id}`;
  const auditTab = document.querySelector('#tabs .tab[data-tab="audit"]');
  if (auditTab) {
    auditTab.classList.toggle('hidden', !session.role.auditRead);
    auditTab.title = session.role.auditRead ? '' : '当前角色无审计读取权限';
  }
  $('#avatar').textContent = session.session.displayName.slice(0, 1);
  $('#registry-pill').innerHTML = `规则 <code>${esc(session.registry.label)}</code> · <code>${short(session.registry.registryVersion, 8)}</code>`;
  await refreshRegistry();
  renderExamples();
  renderVocab();
  renderDrills();
  if (session.role.auditRead) await refreshAudit();
  else $('#audit-chain').innerHTML = '<span class="chain-node">当前角色无审计读取权限</span>';
  setTab('query');
}

/* ---------------- tabs ---------------- */
function setTab(name) {
  $$('#tabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  for (const view of ['query', 'rules', 'audit', 'drills']) {
    $(`#view-${view}`).classList.toggle('hidden', view !== name);
  }
  if (name === 'audit') refreshAudit();
  if (name === 'rules') refreshRules();
}
$('#tabs').addEventListener('click', (event) => {
  const tab = event.target.closest('.tab');
  if (tab) setTab(tab.dataset.tab);
});

/* ---------------- query ---------------- */
function renderExamples() {
  const pool = [...EXAMPLES].sort(() => Math.random() - 0.5).slice(0, 6);
  $('#example-list').innerHTML = pool.map((ex) => `<button class="example" type="button" data-q="${esc(ex.text)}" title="${esc(ex.note)}">${esc(ex.text)}</button>`).join('');
  $$('#example-list .example').forEach((btn) => {
    btn.addEventListener('click', () => {
      $('#query-text').value = btn.dataset.q;
      $('#query-text').focus();
    });
  });
}
$('#shuffle-examples').addEventListener('click', renderExamples);

function renderVocab() {
  const reg = state.registry;
  const role = state.session?.role;
  const allowedMetricIds = new Set(role?.metrics ?? reg.metrics.map((m) => m.id));
  const allowedFieldIds = new Set(role?.fields ?? reg.fields.map((f) => f.id));
  const usableFields = reg.fields.filter((f) => allowedFieldIds.has(f.id) && !f.pii);
  const metrics = reg.metrics.filter((m) => !m.hidden && allowedMetricIds.has(m.id)).map((m) => m.label);
  const fields = usableFields.map((f) => f.label);
  const grains = reg.timeGrains.filter((g) => allowedFieldIds.has(g.sourceField)).map((g) => g.label);
  const values = [...new Set(usableFields.flatMap((f) => (f.enum ?? []).map((e) => e.value)))];
  const section = (name, items) => `<div class="vocab-group"><span>${name}</span><div class="vocab-chips">${items.map((i) => `<span class="chip">${esc(i)}</span>`).join('')}</div></div>`;
  $('#vocab').innerHTML = [
    section('指标', metrics), section('字段', fields), section('时间', grains.concat(['最近 N 天', '本月', '上季度'])), section('取值', values),
  ].join('');
}

async function refreshRegistry() {
  const data = await api('/api/registry');
  state.registry = data.registry;
  state.versions = data.versions;
  const options = data.versions.map((v) => `<option value="${esc(v.label)}">${esc(v.label)} · ${new Date(v.publishedAt).toLocaleDateString('zh-CN')}${v.label === data.registry.label ? '（当前）' : ''}</option>`).join('');
  if ($('#registry-select')) $('#registry-select').innerHTML = options;
  if ($('#rules-registry-select')) $('#rules-registry-select').innerHTML = options;
  $('#registry-pill').innerHTML = `规则 <code>${esc(data.registry.label)}</code> · <code>${short(data.registry.registryVersion, 8)}</code>`;
}

$('#query-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const text = $('#query-text').value.trim();
  if (!text) return toast('请输入查询条件', 'bad');
  const btn = $('#run-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 执行中';
  try {
    const payload = await api('/api/query', {
      method: 'POST',
      body: JSON.stringify({
        text,
        registryRef: $('#registry-select').value || null,
        cacheBypass: $('#bypass-cache').checked,
      }),
    });
    state.lastRun = payload;
    if (payload.queryId) {
      $('#replay-query-id').value = payload.queryId;
      try { localStorage.setItem('rl:lastQuery', payload.queryId); } catch { /* ignore */ }
    }
    renderRun(payload);
    if (payload.ok) toast(`执行成功 · ${payload.cache.hit ? '命中缓存' : '已执行'} · 审计 #${payload.audit.seq}`);
    else toast(`已拒绝 · 审计 #${payload.audit.seq}`, 'bad');
  } catch (error) {
    if (error.payload) {
      state.lastRun = error.payload;
      renderRun(error.payload);
      toast(`请求失败：${error.message}`, 'bad');
    } else {
      toast(error.message, 'bad');
    }
  } finally {
    btn.disabled = false;
    btn.textContent = '执行查询';
  }
});

function renderRun(payload) {
  const status = $('#result-status');
  if (!payload.ok) {
    status.className = 'status-dot bad';
    status.innerHTML = '<i></i><span>已拒绝</span>';
    $('#export-btn').disabled = true;
    $('#result-body').innerHTML = renderRejections(payload);
    $('#evidence-body').innerHTML = renderEvidence(payload);
    $('#evidence-hint').textContent = payload.stage === 'parse' ? '解析阶段拦截' : '授权阶段拦截';
    return;
  }
  const hasRows = payload.result.rows.length > 0;
  status.className = 'status-dot ok';
  status.innerHTML = `<i></i><span>${esc(payload.registry.label)} · ${payload.result.rows.length} 行</span>`;
  $('#export-btn').disabled = !payload.canExport;
  $('#export-btn').title = payload.canExport ? '导出带证据头的 CSV' : '当前角色无导出权限';
  $('#result-body').innerHTML = renderResultTable(payload);
  $('#evidence-body').innerHTML = renderEvidence(payload);
  $('#evidence-hint').textContent = `证据链 · ${payload.evidence.schema}`;
  void hasRows;
}

function renderRejections(payload) {
  const items = payload.rejections ?? [];
  const text = payload.parse?.normalizedText ?? '';
  const banner = `
    <div class="reject-banner">
      <span class="glyph" aria-hidden="true">⛔</span>
      <div>
        <strong>${payload.stage === 'authorize' ? '授权未通过' : '解析未通过'} · 未执行任何数据查询</strong>
        <p>${items.length} 条拒绝原因。只有登记在规则 <code>${esc(payload.registry?.label ?? '')}</code> 中的字段、指标与操作可用。</p>
      </div>
    </div>`;
  const list = items.map((item) => `
    <div class="reject-item">
      <div class="code">${esc(item.code)} · ${esc(item.title ?? '')}</div>
      <div class="msg">${esc(item.message)}</div>
      ${item.span ? `<div class="span-mark">原文片段：[${esc(text.slice(item.span.start, item.span.end))}]</div>` : ''}
      ${item.hint ? `<div class="hint">${esc(item.hint)}</div>` : ''}
      ${item.suggestions?.length ? `<div class="sugs">${item.suggestions.map((s) => `<span class="chip">${esc(typeof s === 'string' ? s : s.label ?? s.id)}</span>`).join('')}</div>` : ''}
    </div>`).join('');
  return banner + list;
}

function formatCell(metric) {
  if (!metric) return '—';
  if (metric.display === '—' || metric.value === null) return '<span class="muted">—</span>';
  return metric.display;
}

function renderResultTable(payload) {
  const { rows, totals, truncated, groupsBeforeLimit, suppressedGroups, minCohort } = payload.result;
  const columns = payload.intent.group ? payload.result.columns : [{ id: 'group', label: '汇总', type: 'dimension' }, ...payload.result.columns];
  const meta = `
    <div class="result-meta">
      <span class="tag accent">规则 ${esc(payload.registry.label)} · ${short(payload.registry.registryVersion, 10)}</span>
      <span class="tag ${payload.cache.hit ? 'warn' : 'good'}">${payload.cache.hit ? '缓存命中' : '实时执行'}</span>
      <span class="tag">时间 ${esc(payload.intent.time.start)} → ${esc(payload.intent.time.end)}（${daysInclusive(payload.intent.time.start, payload.intent.time.end)} 天）</span>
      <span class="tag">扫描 ${payload.evidence.data.sourceRowsScanned} 行 · 命中 ${payload.evidence.data.sourceRowsMatched}</span>
      ${truncated ? `<span class="tag warn">已截断：${groupsBeforeLimit} 组取前 ${rows.length}</span>` : ''}
      ${suppressedGroups ? `<span class="tag warn">抑制 ${suppressedGroups} 个小样本组（&lt; ${minCohort}）</span>` : ''}
      <span class="tag">审计 #${payload.audit.seq}</span>
    </div>`;
  const head = `<tr>${columns.map((c) => `<th>${esc(c.label)}${c.unit ? ` <span class="muted">(${esc(c.unit)})</span>` : ''}</th>`).join('')}</tr>`;
  const body = rows.map((row) => {
    const cells = columns.map((c) => {
      if (c.id === 'group') return `<td class="group">${esc(row.group)}</td>`;
      const metric = row.metrics[c.id];
      return `<td class="num">${row.suppressed ? '<span class="muted">已抑制</span>' : formatCell(metric)}</td>`;
    }).join('');
    return `<tr class="${row.suppressed ? 'suppressed' : ''}">${cells}</tr>`;
  }).join('');
  const totalRow = !payload.intent.group ? '' : `<tr><td class="group">合计</td>${columns.slice(1).map((c) => `<td class="num"><strong>${formatCell(totals[c.id])}</strong></td>`).join('')}</tr>`;
  const filters = payload.intent.filters.length
    ? payload.intent.filters.map((f) => `${esc(f.fieldLabel)} ${esc(f.op)} ${esc((f.rawValues ?? f.values).join(' / '))}`).join('，')
    : '（无过滤条件）';
  const scope = payload.authorization.appliedScopes.length
    ? payload.authorization.appliedScopes.map((s) => esc(s.description)).join('；')
    : '（无行级限制）';
  return `${meta}
    <div class="table-wrap"><table><thead>${head}</thead><tbody>${body}${totalRow}</tbody></table></div>
    <div class="result-meta" style="margin-top:10px">
      <span class="tag">过滤：${filters}</span>
      <span class="tag">行权限：${scope}</span>
    </div>`;
}

function renderEvidence(payload) {
  const registry = payload.registry ?? payload.parse?.registry ?? {};
  const sections = [];
  sections.push(`
    <div class="ev-section">
      <div class="ev-head"><strong>解析映射</strong><span>${(payload.parse?.mappings ?? []).length} 项</span></div>
      <div class="ev-body">
        ${(payload.parse?.mappings ?? []).map((m) => `
          <div class="mapping-row">
            <span class="term">${esc(m.term)}</span><span class="arrow">→</span>
            <span class="target">${esc(m.target?.label ?? m.targets?.map((t) => t.label).join(' | ') ?? '')}</span>
            ${m.role ? `<span class="chip">${esc(m.role)}</span>` : ''}
            <span class="ptr">${esc(m.target?.pointer ?? '')}</span>
          </div>`).join('') || '<p class="muted" style="font-size:12px">无映射</p>'}
      </div>
    </div>`);
  if (payload.ok) {
    const ev = payload.evidence;
    sections.push(`
      <div class="ev-section">
        <div class="ev-head"><strong>版本与角色</strong><span>${esc(ev.registry.label)}</span></div>
        <div class="ev-body">
          <dl class="kv">
            <dt>registryVersion</dt><dd>${esc(ev.registry.registryVersion)}</dd>
            <dt>publishedAt</dt><dd>${esc(ev.registry.publishedAt)}</dd>
            <dt>publishedBy</dt><dd>${esc(ev.registry.publishedBy)}</dd>
            <dt>角色</dt><dd>${esc(ev.role.label)} (${esc(ev.role.id)})</dd>
            <dt>queryId</dt><dd>${esc(ev.queryId)}</dd>
            <dt>asOf</dt><dd>${esc(ev.parse.asOf)}</dd>
          </dl>
        </div>
      </div>
      <div class="ev-section">
        <div class="ev-head"><strong>过滤与数据版本</strong><span>${ev.data.partitions.length} 个分区</span></div>
        <div class="ev-body">
          ${ev.intent.filters.length ? ev.intent.filters.map((f) => `<dl class="kv"><dt>${esc(f.fieldLabel)}</dt><dd>${esc(f.op)} ${esc(f.displayValues.join(', '))} <span class="ptr">${esc(f.registryPointer)}</span></dd></dl>`).join('') : '<p class="muted" style="font-size:12px">无显式过滤</p>'}
          ${ev.authorization.appliedScopes.map((s) => `<dl class="kv"><dt>行权限</dt><dd>${esc(s.fieldLabel)} ∈ [${esc(s.values.join(', '))}] <span class="ptr">${esc(s.source)}</span></dd></dl>`).join('')}
          ${ev.data.partitions.map((p) => `<dl class="kv"><dt>${esc(p.month)}</dt><dd>${esc(p.contentHash)}</dd></dl>`).join('')}
          <dl class="kv"><dt>输出哈希</dt><dd>${esc(ev.result.outputHash)}</dd></dl>
          <dl class="kv"><dt>证据哈希</dt><dd class="evidence-hash">${esc(payload.evidenceHash ?? '')}</dd></dl>
        </div>
      </div>
      <div class="ev-section">
        <div class="ev-head"><strong>授权检查</strong><span>${esc(ev.authorization.result)}</span></div>
        <div class="ev-body">
          ${ev.authorization.checks.map((c) => `<div class="mapping-row"><span class="target">✓ ${esc(c)}</span></div>`).join('')}
        </div>
      </div>`);
  }
  if (payload.parse?.warnings?.length) {
    sections.push(`
      <div class="ev-section">
        <div class="ev-head"><strong>解析告警</strong><span>${payload.parse.warnings.length}</span></div>
        <div class="ev-body">${payload.parse.warnings.map((w) => `<div class="mapping-row"><span class="target">${esc(w.code)}：${esc(w.message)}</span></div>`).join('')}</div>
      </div>`);
  }
  if (payload.audit) {
    sections.push(`
      <div class="ev-section">
        <div class="ev-head"><strong>审计回执</strong><span>#${payload.audit.seq}</span></div>
        <div class="ev-body"><dl class="kv"><dt>recordHash</dt><dd class="evidence-hash">${esc(payload.audit.hash)}</dd></dl></div>
      </div>`);
  }
  void registry;
  return sections.join('');
}

$('#export-btn').addEventListener('click', async () => {
  if (!state.lastRun?.ok) return;
  try {
    const res = await fetch(`/api/export/query/${encodeURIComponent(state.lastRun.queryId)}`, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{"format":"csv"}',
    });
    if (!res.ok) {
      const payload = await res.json().catch(() => ({}));
      return toast(payload.error?.message ?? '导出失败', 'bad');
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rulegate-${state.lastRun.queryId}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast(`导出完成 · 审计 #${res.headers.get('X-Audit-Seq') ?? '?'}`);
    refreshAudit();
  } catch (error) {
    toast(error.message, 'bad');
  }
});

/* ---------------- rules ---------------- */
async function refreshRules() {
  await refreshRegistry();
  $('#rules-hint').textContent = state.session.role.canPublish ? '可发布新版本' : '只读（当前角色无发布权限）';
  $('#version-list').innerHTML = state.versions.map((v) => `
    <div class="version-card ${v.label === state.registry.label ? 'active' : ''}" data-label="${esc(v.label)}">
      <div class="vhead"><span class="vlabel">${esc(v.label)}</span><span class="vtime">${new Date(v.publishedAt).toLocaleString('zh-CN')}</span></div>
      <div class="vnotes">${esc(v.notes)}</div>
      <div class="vmeta">
        <span class="chip">${short(v.registryVersion, 10)}</span>
        ${v.ambiguities.length ? `<span class="tag warn">歧义 ${v.ambiguities.length}</span>` : '<span class="tag good">无歧义</span>'}
        ${v.builtin ? '<span class="chip">builtin</span>' : '<span class="chip">published</span>'}
      </div>
    </div>`).join('');
  $$('#version-list .version-card').forEach((card) => {
    card.addEventListener('click', async () => {
      const data = await api(`/api/registry/${encodeURIComponent(card.dataset.label)}`);
      renderRegistryTable(data.registry);
      $$('#version-list .version-card').forEach((c) => c.classList.toggle('active', c === card));
    });
  });
  renderRegistryTable(state.registry);
  $('#expected-version').textContent = state.registry.registryVersion;
}

function renderRegistryTable(reg) {
  const metrics = reg.metrics.map((m) => `
    <div class="reg-row">
      <span class="lbl">${esc(m.label)}</span>
      <code>${esc(m.id)}</code>
      <span class="tag ${m.hidden ? 'warn' : ''}">${esc(m.kind)} · ${esc(m.unit)}</span>
      ${m.hidden ? '<span class="tag bad">内部派生</span>' : ''}
      <span class="aliases">${m.aliases.map((a) => `<span class="chip">${esc(a)}</span>`).join('')}</span>
    </div>`).join('');
  const fields = reg.fields.map((f) => `
    <div class="reg-row">
      <span class="lbl">${esc(f.label)}</span>
      <code>${esc(f.id)}</code>
      <span class="tag">${esc(f.type)}</span>
      ${f.pii ? '<span class="tag bad">PII</span>' : ''}
      ${f.filterable ? '<span class="chip">可筛选</span>' : ''}
      ${f.groupable ? '<span class="chip">可分组</span>' : ''}
      <span class="aliases">${f.aliases.map((a) => `<span class="chip">${esc(a)}</span>`).join('')}</span>
    </div>`).join('');
  const roles = reg.roles.map((r) => `
    <div class="reg-row">
      <span class="lbl">${esc(r.label)}</span>
      <code>${esc(r.id)}</code>
      <span class="tag">≤${r.maxRangeDays}天</span>
      <span class="tag">≤${r.maxLimit}条</span>
      ${Object.keys(r.rowScope).length ? `<span class="tag warn">行权限 ${esc(Object.entries(r.rowScope).map(([k, v]) => `${k}=${v.join('/')}`).join('; '))}</span>` : ''}
      ${r.canExport ? '<span class="chip">可导出</span>' : ''}
      ${r.auditRead ? '<span class="chip">读审计</span>' : ''}
      ${r.canPublish ? '<span class="chip">可发布</span>' : ''}
    </div>`).join('');
  const ambiguities = reg.ambiguities.length
    ? reg.ambiguities.map((a) => `
      <div class="reg-row">
        <span class="lbl">${esc(a.term)}</span>
        <span class="tag bad">歧义</span>
        <span class="aliases">${a.targets.map((t) => `<span class="chip">${esc(t.label)}</span>`).join('')}</span>
      </div>`).join('')
    : '<p class="muted" style="font-size:12px">该版本无语义冲突别名。</p>';
  $('#registry-table').innerHTML = `
    <div class="reg-section"><h3>指标 · ${reg.metrics.length}</h3>${metrics}</div>
    <div class="reg-section"><h3>字段 · ${reg.fields.length}</h3>${fields}</div>
    <div class="reg-section"><h3>角色 · ${reg.roles.length}</h3>${roles}</div>
    <div class="reg-section"><h3>歧义别名</h3>${ambiguities}</div>`;
}

$('#load-draft').addEventListener('click', async () => {
  const label = $('#rules-registry-select').value;
  const data = await api(`/api/registry/${encodeURIComponent(label)}`);
  const doc = {
    schemaVersion: 1,
    label: 'v0',
    publishedAt: '2026-11-20T00:00:00.000Z',
    notes: '由界面载入的草稿',
    calendar: { timezone: 'UTC' },
    timeGrains: data.registry.timeGrains,
    fields: data.registry.fields.map((f) => ({
      id: f.id, label: f.label, table: 'orders', column: f.id, type: f.type, semantic: f.semantic,
      description: f.description, aliases: f.aliases, filterable: f.filterable, groupable: f.groupable,
      pii: f.pii, operators: f.operators, ...(f.enum ? { enum: f.enum } : {}), ...(f.unit ? { unit: f.unit } : {}),
      ...(f.scale !== undefined && f.scale !== null ? { scale: f.scale } : {}),
    })),
    metrics: data.registry.metrics.map((m) => ({ id: m.id, label: m.label, aliases: m.aliases, kind: m.kind, definition: m.definition, unit: m.unit, description: m.description, ...(m.hidden ? { hidden: true } : {}) })),
    roles: Object.fromEntries(data.registry.roles.map((r) => [r.id, {
      label: r.label, description: r.description, allowedMetrics: r.metrics, allowedFields: r.fields,
      allowedOps: r.ops, rowScope: r.rowScope, maxRangeDays: r.maxRangeDays, maxLimit: r.maxLimit,
      minCohort: r.minCohort, canExport: r.canExport, auditRead: r.auditRead, canPublish: r.canPublish,
      defaultRangeDays: 30, defaultLimit: 50, canGroupBy: true, canSort: true, canReplay: true,
    }])),
  };
  $('#draft-json').value = JSON.stringify(doc, null, 2);
  $('#expected-version').textContent = state.registry.registryVersion;
});

async function submitDraft({ notes, expectedVersion } = {}) {
  await refreshRegistry();
  const draft = JSON.parse($('#draft-json').value);
  const body = {
    doc: draft,
    notes: notes ?? $('#publish-notes').value,
    acknowledgeAmbiguities: draft.acknowledgedAmbiguities ?? [],
  };
  const res = await fetch('/api/rules/publish', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'If-Match': `"${expectedVersion ?? state.registry.registryVersion}"` },
    body: JSON.stringify(body),
  });
  const payload = await res.json();
  return { status: res.status, payload };
}

$('#validate-draft').addEventListener('click', async () => {
  const feedback = $('#publish-feedback');
  try {
    const doc = JSON.parse($('#draft-json').value);
    const data = await api('/api/rules/validate', { method: 'POST', body: JSON.stringify({ doc }) });
    const v = data.validation;
    feedback.innerHTML = v.ok
      ? `<span class="ok">校验通过</span>${v.warnings.length ? `<ul class="issue-list">${v.warnings.map((w) => `<li>${esc(w.code)} · ${esc(w.message)}</li>`).join('')}</ul>` : ''}`
      : `<span class="err">校验失败（${v.errors.length}）</span><ul class="issue-list">${v.errors.map((e) => `<li>${esc(e.code)} <code>${esc(e.path)}</code> · ${esc(e.message)}</li>`).join('')}</ul>`;
  } catch (error) {
    feedback.innerHTML = `<span class="err">${esc(error.message)}</span>`;
  }
});

$('#publish-btn').addEventListener('click', async () => {
  const feedback = $('#publish-feedback');
  feedback.innerHTML = '<span class="muted">发布中…</span>';
  try {
    const { status, payload } = await submitDraft();
    if (status === 201) {
      feedback.innerHTML = `<span class="ok">已发布 ${esc(payload.version.label)}</span> · ${short(payload.version.registryVersion, 12)} · 审计 #${payload.audit.seq}`;
      await refreshRules();
      renderVocab();
      renderDrills();
      toast(`规则 ${payload.version.label} 已发布`);
    } else {
      feedback.innerHTML = `<span class="err">${esc(payload.error?.code)}：${esc(payload.error?.message)}</span>`;
    }
  } catch (error) {
    feedback.innerHTML = `<span class="err">${esc(error.message)}</span>`;
  }
});

/* ---------------- audit ---------------- */
async function refreshAudit() {
  try {
    const data = await api('/api/audit?limit=120');
    state.auditRecords = data.records;
    const v = data.verification;
    $('#audit-chain').innerHTML = `
      <span class="chain-node ${v.ok ? 'ok' : 'bad'}">${v.records} 条 · ${v.ok ? '链完整' : `${v.problems.length} 个问题`}</span>
      <span class="chain-node">head ${short(v.head, 16)}</span>`;
    $('#audit-list').innerHTML = data.records.map((r) => `
      <div class="audit-row">
        <span class="seq">#${r.seq}</span>
        <div>
          <span class="type ${typeClass(r.type)}">${esc(r.type)}</span>
          <span class="who"> · ${esc(r.actor)}${r.payload?.queryId ? ` · <code>${esc(r.payload.queryId)}</code>` : ''}</span>
        </div>
        <span class="hash" title="${esc(r.hash)}">${short(r.hash, 10)}</span>
      </div>`).join('');
  } catch (error) {
    $('#audit-list').innerHTML = `<p class="muted">${esc(error.message)}</p>`;
  }
}
function typeClass(type) {
  if (type.startsWith('query.allowed')) return 'allowed';
  if (type.startsWith('query.denied')) return 'denied';
  if (type.startsWith('rules')) return 'rules';
  if (type.includes('export')) return 'exported';
  return '';
}
$('#audit-refresh').addEventListener('click', refreshAudit);
$('#audit-verify').addEventListener('click', async () => {
  const data = await api('/api/audit/verify');
  const v = data.verification;
  toast(v.ok ? `审计链完整 · ${v.records} 条` : `审计链异常 · ${v.problems.length} 处`, v.ok ? 'ok' : 'bad');
});
$('#audit-export').addEventListener('click', async () => {
  const res = await fetch('/api/audit/export?format=json', { credentials: 'same-origin' });
  if (!res.ok) {
    const p = await res.json().catch(() => ({}));
    return toast(p.error?.message ?? '导出失败', 'bad');
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'rulegate-audit.json'; a.click();
  URL.revokeObjectURL(url);
  toast('审计包已导出');
  refreshAudit();
});

$('#replay-btn').addEventListener('click', async () => {
  const queryId = $('#replay-query-id').value.trim();
  const out = $('#replay-output');
  if (!queryId && state.lastRun) { $('#replay-query-id').value = state.lastRun.queryId; }
  try {
    const data = await api(`/api/replay/${encodeURIComponent(queryId || state.lastRun?.queryId || '')}`, { method: 'POST', body: '{}' });
    out.innerHTML = `
      <div class="outcome-card ${data.verification.deterministic ? 'ok' : 'bad'}">
        <strong>${data.verification.deterministic ? '复现一致' : '复现不一致'}</strong>
        <p>规则 ${esc(data.ruleLabel)} · ${short(data.registryVersion, 12)}</p>
      </div>
      <dl class="kv"><dt>原始输出</dt><dd>${short(data.verification.originalOutputHash, 24)}</dd></dl>
      <dl class="kv"><dt>复现输出</dt><dd>${short(data.verification.replayOutputHash ?? '—', 24)}</dd></dl>
      <p class="muted" style="font-size:12px">${esc(data.note)}</p>`;
    toast(data.verification.deterministic ? '复现结果一致' : '复现结果不一致', data.verification.deterministic ? 'ok' : 'bad');
  } catch (error) {
    out.innerHTML = `<p class="muted">${esc(error.message)}</p>`;
  }
});

/* ---------------- drills ---------------- */
function renderDrills() {
  const roleId = state.session?.role?.id;
  $('#drill-list').innerHTML = DRILLS.map((d, i) => {
    const blocked = d.role && d.role !== roleId;
    return `
    <div class="drill-row">
      <button class="btn btn-sm btn-ghost" data-drill="${i}" title="${esc(d.label ?? '')}" ${blocked ? 'disabled title="需以对应角色登录"' : ''}>运行</button>
      <span class="q">${esc(d.text)}</span>
      <span class="expect" title="${esc(d.label ?? '')}">${d.registryRef ? `${esc(d.registryRef)} · ` : ''}${d.role ? `${esc(d.role)} · ` : ''}${esc(d.expect)}</span>
      <span class="verdict pending" id="drill-verdict-${i}">${blocked ? '需切换角色' : '待运行'}</span>
    </div>`;
  }).join('');
  $$('[data-drill]').forEach((btn) => btn.addEventListener('click', () => runDrill(Number(btn.dataset.drill))));
}

async function runDrill(index) {
  const drill = DRILLS[index];
  const verdictEl = $(`#drill-verdict-${index}`);
  verdictEl.className = 'verdict pending';
  verdictEl.textContent = '执行中…';
  try {
    const payload = await api('/api/query', {
      method: 'POST',
      body: JSON.stringify({ text: drill.text, registryRef: drill.registryRef, cacheBypass: true }),
    });
    const verdict = evaluateDrill(drill, payload);
    verdictEl.className = `verdict ${verdict.pass ? 'pass' : 'fail'}`;
    verdictEl.textContent = verdict.pass ? '通过' : `不符：${verdict.actual}`;
    verdictEl.title = verdict.detail;
  } catch (error) {
    verdictEl.className = 'verdict fail';
    verdictEl.textContent = `报错：${error.message}`;
  }
}

function evaluateDrill(drill, payload) {
  if (drill.expect === 'ok') {
    return { pass: Boolean(payload.ok), actual: payload.ok ? 'ok' : payload.rejections?.[0]?.code ?? 'reject', detail: '' };
  }
  const expected = drill.expect.split(':')[1];
  if (payload.ok) return { pass: false, actual: 'allowed', detail: '期望拒绝但被放行' };
  const codes = payload.rejections.map((r) => r.code);
  const pass = expected ? codes.includes(expected) : codes.length > 0;
  return { pass, actual: codes.join(','), detail: payload.rejections.map((r) => r.message).join(' | ') };
}

$('#concurrent-btn').addEventListener('click', async () => {
  const out = $('#concurrent-output');
  out.innerHTML = '<p class="muted">同时发起…</p>';
  try {
    await refreshRegistry();
    const base = JSON.parse($('#draft-json').value || '{}');
    const draft = Object.keys(base).length ? base : null;
    if (!draft) {
      out.innerHTML = '<p class="err" style="color:var(--danger)">请先在“规则登记表”页载入草稿。</p>';
      return;
    }
    const expected = state.registry.registryVersion;
    const notes = $('#concurrent-notes').value;
    const [a, b] = await Promise.all([submitDraft({ notes: `${notes}（A）`, expectedVersion: expected }), submitDraft({ notes: `${notes}（B）`, expectedVersion: expected })]);
    out.innerHTML = `<div class="two-col">
      ${renderPublishOutcome('请求 A', a)}
      ${renderPublishOutcome('请求 B', b)}
    </div>
    <p class="muted" style="font-size:12px">期望：一个 201，一个 409（RULE_VERSION_CONFLICT）。</p>`;
    await refreshRules();
  } catch (error) {
    out.innerHTML = `<p style="color:var(--danger)">${esc(error.message)}</p>`;
  }
});

function renderPublishOutcome(name, result) {
  const ok = result.status === 201;
  return `<div class="outcome-card ${ok ? 'ok' : 'bad'}">
    <strong>${name} · HTTP ${result.status}</strong>
    <p>${ok ? `已发布 ${esc(result.payload.version.label)} · ${short(result.payload.version.registryVersion, 10)}` : `${esc(result.payload.error?.code)} · ${esc(result.payload.error?.message)}`}</p>
  </div>`;
}

$('#cache-stats-btn').addEventListener('click', async () => {
  const data = await api('/api/cache');
  const out = $('#cache-output');
  out.innerHTML = `
    <div class="two-col">
      <div class="outcome-card"><strong>命中 ${data.stats.hits}</strong><p>未命中 ${data.stats.misses} · 拒绝复用 ${data.stats.denied}</p></div>
      <div class="outcome-card"><strong>条目 ${data.stats.size}</strong><p>淘汰 ${data.stats.evictions} · 合并 ${data.stats.coalesced}</p></div>
    </div>
    ${data.entries.map((e) => `<dl class="kv"><dt>${esc(e.roleId)}</dt><dd>${short(e.registryVersion, 12)} · hits ${e.hits} · ${esc(e.queryId ?? '')}</dd></dl>`).join('')}
    <p class="muted" style="font-size:12px">缓存键包含 registryVersion + 角色 ACL 指纹 + 规范化意图 + 分区内容哈希；不同权限永不共享。</p>`;
});

$('#integrity-btn').addEventListener('click', async () => {
  const data = await api('/api/integrity');
  const out = $('#cache-output');
  out.innerHTML = data.integrity.partitions.map((p) => `
    <dl class="kv"><dt>${esc(p.month)}</dt><dd>${p.match ? '哈希一致 ✓' : '哈希不一致 ✗'} · ${short(p.onDisk, 16)}</dd></dl>`).join('')
    + `<p class="muted" style="font-size:12px">分区内容哈希由确定性生成器重算并与磁盘文件比对。</p>`;
});

/* ---------------- boot ---------------- */
(async function boot() {
  await loadDemoAccounts();
  try {
    const last = localStorage.getItem('rl:lastQuery');
    if (last) $('#replay-query-id').value = last;
  } catch { /* ignore */ }
  try {
    const session = await api('/api/session');
    if (session?.ok) await enterApp();
  } catch {
    /* not logged in */
  }
})();
