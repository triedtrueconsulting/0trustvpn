/* 0trust operations dashboard.
 *
 * No framework and no build step: the whole thing is one file served as-is,
 * which keeps the deploy story identical to the rest of the site and means an
 * operator can read exactly what their browser is running.
 *
 * Everything user-supplied is inserted with textContent or via el(), never
 * innerHTML. Account notes, device names and ban reasons are all attacker-
 * influenced, and this is a page an operator opens while signed in.
 */
'use strict';

const API = '/api/v1/admin';
let CSRF = null;
let REGIONS = ['zur', 'rey', 'buc'];

const $ = (id) => document.getElementById(id);

/* --- tiny DOM helper: children are text unless explicitly an element ------ */
function el(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c === null || c === undefined) continue;
    n.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

function toast(msg, bad = false) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.toggle('bad', bad);
  t.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add('hidden'), bad ? 6000 : 3000);
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (CSRF && method !== 'GET') headers['X-Admin-CSRF'] = CSRF;
  const res = await fetch(API + path, {
    method, headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
  if (res.status === 401) { showGate(); throw new Error('Session expired — sign in again'); }
  if (!res.ok) throw new Error((data && (data.detail || data.raw)) || `HTTP ${res.status}`);
  return data;
}

const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString() : '—';
const fmtDate = (ts) => ts ? new Date(ts * 1000).toISOString().slice(0, 10) : '—';
const fmtMoney = (n) => '$' + Number(n || 0).toFixed(2);
function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
const short = (s, n = 16) => (s && s.length > n ? s.slice(0, n) + '…' : (s || ''));

function table(headers, rows) {
  if (!rows.length) return el('div', { class: 'empty', text: 'Nothing here.' });
  const thead = el('thead', {}, [el('tr', {}, headers.map(
    (h) => el('th', { class: h.num ? 'num' : '', text: h.label || h })))]);
  const tbody = el('tbody', {}, rows.map((cells) => el('tr', {}, cells.map(
    (c) => (c && c.node) ? el('td', { class: c.cls || '' }, [c.node])
                         : el('td', { class: (c && c.cls) || '', text: (c && c.text !== undefined) ? c.text : c })))));
  return el('div', { class: 'table-wrap' }, [el('table', {}, [thead, tbody])]);
}

/* --- gate ---------------------------------------------------------------- */
function showGate(needsSetup = false) {
  $('app').classList.add('hidden');
  $('gate').classList.remove('hidden');
  $('login-form').classList.toggle('hidden', needsSetup);
  $('setup-form').classList.toggle('hidden', !needsSetup);
}

async function boot() {
  const state = await (await fetch(API + '/state', { credentials: 'same-origin' })).json();
  if (state.signed_in) {
    CSRF = state.csrf;
    $('who-name').textContent = state.username;
    $('gate').classList.add('hidden');
    $('app').classList.remove('hidden');
    loadTab('overview');
  } else {
    showGate(state.needs_setup);
  }
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('gate-err').classList.add('hidden');
  try {
    const r = await api('/login', { method: 'POST', body: {
      username: $('li-user').value, password: $('li-pass').value } });
    CSRF = r.csrf;
    $('li-pass').value = '';
    await boot();
  } catch (err) {
    $('gate-err').textContent = err.message;
    $('gate-err').classList.remove('hidden');
  }
});

$('setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('gate-err');
  err.classList.add('hidden');
  if ($('su-pass').value !== $('su-pass2').value) {
    err.textContent = 'Passwords do not match'; err.classList.remove('hidden'); return;
  }
  try {
    const r = await api('/setup', { method: 'POST', body: {
      username: $('su-user').value, password: $('su-pass').value } });
    CSRF = r.csrf;
    await boot();
    toast('Operator created. Write the password down somewhere safe.');
  } catch (e2) {
    err.textContent = e2.message; err.classList.remove('hidden');
  }
});

$('logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); } catch { /* going anyway */ }
  CSRF = null;
  location.reload();
});

/* --- tabs ---------------------------------------------------------------- */
$('tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-tab]');
  if (b) loadTab(b.dataset.tab);
});

function loadTab(name) {
  document.querySelectorAll('#tabs button').forEach(
    (b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('[data-panel]').forEach(
    (p) => p.classList.toggle('hidden', p.dataset.panel !== name));
  ({ overview: loadOverview, accounts: loadAccounts,
     nodes: () => { loadNodes(); loadPtokens(); },
     payments: loadPayments, notices: loadNotices, settings: loadSettings,
     events: loadEvents, audit: loadAudit }[name] || (() => {}))();
}

/* --- overview ------------------------------------------------------------ */
async function loadOverview() {
  const d = await api('/overview');
  // Refresh the badge whenever the dashboard is opened, so bad news is
  // visible from the first screen rather than only inside its own tab.
  api('/events?limit=1').then((e) => paintEventsBadge(e.unresolved)).catch(() => {});
  const a = d.accounts, r = d.revenue;
  const stats = [
    ['Active', a.active, 'good'], ['On trial', a.trial, ''],
    ['Expired', a.expired, ''], ['Banned', a.banned, a.banned ? 'bad' : ''],
    ['Awaiting payment', a.pending, ''], ['Devices', d.devices, ''],
    ['30-day revenue', fmtMoney(r.settled_30d), 'good'],
    ['All-time', fmtMoney(r.settled_all), ''],
  ];
  $('stat-row').replaceChildren(...stats.map(([k, v, cls]) =>
    el('div', { class: 'stat ' + cls }, [
      el('div', { class: 'v', text: String(v) }), el('div', { class: 'k', text: k })])));

  // Conversion, from rows the service keeps anyway. There is no visit or
  // click measurement here and there will not be: that needs a third-party
  // script or a per-visitor identifier, and privacy.html says we have
  // neither. So the funnel starts at "someone asked for a trial" — earlier
  // than that is deliberately invisible to us.
  const f = d.funnel || {};
  const pct = (v) => (v === null || v === undefined ? 'n/a' : v + '%');
  $('funnel').replaceChildren(
    table(['Stage', 'Count', 'Rate'], [
      ['Trials started', f.trials_started, '\u2014'],
      ['Trials that went on to pay', f.trials_converted,
       pct(f.trial_conversion_pct)],
      ['Paid without a trial', f.paid_direct, '\u2014'],
      ['Invoices created', f.invoices_created, '\u2014'],
      ['Invoices settled', f.invoices_settled, pct(f.checkout_completion_pct)],
      ['Trials started (30d)', f.trials_started_30d, '\u2014'],
      ['Invoices settled (30d)', f.invoices_settled_30d, '\u2014'],
    ].map((r) => [r[0], String(r[1] === undefined ? '\u2014' : r[1]), r[2]])),
    el('p', { class: 'note', text:
      'Counted from accounts and invoices. No visitor tracking exists to '
      + 'count from \u2014 see privacy.html \u00a75.' }));

  const unhealthy = d.nodes.filter((n) => !n.healthy).length;
  $('node-health').replaceChildren(
    table(['Node', 'Region', 'Role', 'State', 'Heartbeat'],
      d.nodes.map((n) => [
        { node: el('code', { text: n.id }) }, n.region, n.role,
        { node: el('span', {
            class: 'pill ' + (n.healthy ? 'ok' : 'bad'),
            text: n.healthy ? 'healthy' : (n.active ? 'stale' : 'inactive') }) },
        n.ephemeral ? ago(n.last_heartbeat) : 'static',
      ])),
    unhealthy
      ? el('p', { class: 'note', text: `${unhealthy} node(s) need attention.` })
      : el('p', { class: 'note', text: 'All nodes reporting.' }));

  $('recent').replaceChildren(table(['When', 'Who', 'Action', 'Target'],
    d.recent_activity.map((x) => [ago(x.at), x.username, x.action, short(x.target, 28)])));
}

/* --- accounts ------------------------------------------------------------ */
async function loadAccounts() {
  const q = encodeURIComponent($('acct-q').value.trim());
  const st = $('acct-status').value, pl = $('acct-plan').value;
  const d = await api(`/accounts?q=${q}&status=${st}&plan=${pl}&limit=50`);
  $('acct-list').replaceChildren(
    el('p', { class: 'note', text: `${d.total} account(s)` }),
    table(['ID', 'Status', 'Plan', 'Expires', 'Devices', ''],
      d.accounts.map((a) => [
        { node: el('code', { text: '#' + a.id }) },
        { node: el('span', {
            class: 'pill ' + ({ active: 'ok', banned: 'bad', expired: 'neutral' }[a.status] || 'warn'),
            text: a.status }) },
        a.plan, fmtDate(a.expires_at), { text: String(a.devices), cls: 'num' },
        { node: el('button', { class: 'small', text: 'Open',
            onclick: () => showAccount(a.id) }) },
      ])));
}

async function showAccount(id) {
  const d = await api(`/accounts/${id}`);
  const a = d.account;
  const box = $('acct-detail');
  box.classList.remove('hidden');

  const banned = a.status === 'banned';
  const actions = el('div', { class: 'row-actions' }, [
    banned
      ? el('button', { class: 'small', text: 'Unban', onclick: async () => {
          await api(`/accounts/${id}/unban`, { method: 'POST' });
          toast('Account unbanned'); showAccount(id); loadAccounts(); } })
      : el('button', { class: 'small danger', text: 'Ban', onclick: async () => {
          const reason = prompt('Reason for the ban (recorded in the audit log):');
          if (reason === null) return;
          const r = await api(`/accounts/${id}/ban`, { method: 'POST', body: { reason } });
          toast(`Banned. ${r.devices_removed} device(s) cut off.`);
          showAccount(id); loadAccounts(); } }),
    el('button', { class: 'small', text: '+30 days', onclick: () => extend(id, 30) }),
    el('button', { class: 'small', text: '+7 days', onclick: () => extend(id, 7) }),
    el('button', { class: 'small', text: '−7 days', onclick: () => extend(id, -7) }),
    el('button', { class: 'small', text: 'Message', onclick: () => {
        loadTab('notices');
        document.querySelector('#notice-form [name=account_id]').value = id;
        document.querySelector('#notice-form [name=subject]').focus(); } }),
    el('button', { class: 'small danger', text: 'Delete', onclick: async () => {
        if (!confirm(`Permanently delete account #${id} and all its data? This cannot be undone.`)) return;
        await api(`/accounts/${id}`, { method: 'DELETE' });
        toast('Account deleted'); box.classList.add('hidden'); loadAccounts(); } }),
  ]);

  const note = el('textarea', { rows: '2', placeholder: 'Operator note — never shown to the customer' });
  note.value = a.note || '';

  box.replaceChildren(
    el('h2', { text: `Account #${a.id}` }),
    table(['Status', 'Plan', 'Created', 'Expires', 'Banned'],
      [[a.status, a.plan, fmtDate(a.created_at), fmtDate(a.expires_at),
        a.banned_reason ? `${a.banned_reason} (${fmtDate(a.banned_at)})` : '—']]),
    actions,
    el('h2', { text: 'Devices' }),
    table(['Name', 'Mesh IP', 'Key', 'Last seen', 'Route', ''],
      d.devices.map((x) => [
        x.device_name || '—', x.mesh_ip,
        { node: el('span', { class: 'k', text: short(x.pubkey, 18) }) },
        ago(x.last_seen),
        x.entry_node ? `${x.entry_node} → ${x.exit_node}` : 'single-hop',
        { node: el('button', { class: 'small danger', text: 'Remove', onclick: async () => {
            await api(`/devices/${x.id}`, { method: 'DELETE' });
            toast('Device removed'); showAccount(id); } }) },
      ])),
    el('h2', { text: 'Invoices' }),
    table(['ID', 'Months', 'Amount', 'Status', 'Created'],
      d.invoices.map((i) => [
        { node: el('code', { text: short(i.id, 20) }) }, String(i.months),
        fmtMoney(i.amount_usd), i.status, fmtDate(i.created_at)])),
    el('h2', { text: 'Note' }), note,
    el('button', { class: 'small', text: 'Save note', onclick: async () => {
        await api(`/accounts/${id}/note`, { method: 'POST', body: { note: note.value } });
        toast('Note saved'); } }));
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function extend(id, days) {
  const reason = prompt(`Reason for ${days > 0 ? 'adding' : 'removing'} ${Math.abs(days)} days:`);
  if (reason === null) return;
  const r = await api(`/accounts/${id}/extend`, { method: 'POST', body: { days, reason } });
  toast(`Now expires ${fmtDate(r.expires_at)}`);
  showAccount(id); loadAccounts();
}

$('acct-search').addEventListener('click', loadAccounts);
$('acct-q').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadAccounts(); });

/* --- nodes --------------------------------------------------------------- */
async function loadNodes() {
  const d = await api('/nodes');
  REGIONS = [...new Set(d.nodes.map((n) => n.region))].sort();
  if (!REGIONS.length) REGIONS = ['zur', 'rey', 'buc'];
  for (const sel of ['node-region', 'ptok-region']) {
    $(sel).replaceChildren(...REGIONS.map((r) => el('option', { value: r, text: r })));
  }
  $('node-list').replaceChildren(table(
    ['Node', 'Region', 'Role', 'Endpoint', 'State', 'Devices', 'Heartbeat', ''],
    d.nodes.map((n) => [
      { node: el('code', { text: n.id }) }, n.region, n.role, n.endpoint,
      { node: el('span', {
          class: 'pill ' + (n.healthy ? 'ok' : 'bad'),
          text: n.healthy ? 'healthy' : (n.active ? 'stale' : 'inactive') }) },
      { text: String(n.devices), cls: 'num' },
      n.ephemeral ? ago(n.last_heartbeat) : 'static',
      { node: el('div', { class: 'row-actions' }, [
          el('button', { class: 'small', text: n.active ? 'Disable' : 'Enable',
            onclick: async () => {
              await api(`/nodes/${n.id}`, { method: 'PATCH', body: { active: !n.active } });
              toast(`${n.id} ${n.active ? 'disabled' : 'enabled'}`); loadNodes(); } }),
          el('button', { class: 'small danger', text: 'Remove', onclick: async () => {
              if (!confirm(`Remove ${n.id}? Sessions routed through it are released.`)) return;
              const r = await api(`/nodes/${n.id}`, { method: 'DELETE' });
              toast(`${n.id} removed, ${r.pairs_released} session(s) released`); loadNodes(); } }),
        ]) },
    ])));
}

$('node-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target).entries());
  f.wg_port = Number(f.wg_port); f.capacity = Number(f.capacity);
  try {
    await api('/nodes', { method: 'POST', body: f });
    toast(`Node ${f.id} added`); e.target.reset(); loadNodes();
  } catch (err) { toast(err.message, true); }
});

$('ptok-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target).entries());
  f.ttl_hours = Number(f.ttl_hours); f.uses = Number(f.uses || 1);
  try {
    const r = await api('/nodes/provision-token', { method: 'POST', body: f });
    const cmd = `sudo ./scripts/install.sh --mode node \\\n` +
      `     --control-url ${location.origin} \\\n` +
      `     --region ${r.region} --role ${r.role} \\\n` +
      `     --provision-token ${r.token}`;
    $('ptok-out').replaceChildren(
      el('div', { class: 'secret-out', text: r.token }),
      el('p', { class: 'note', text:
        `Valid until ${fmtTime(r.expires_at)}, ${r.uses} use${r.uses === 1 ? '' : 's'}. Shown once — copy it now.` }),
      el('pre', { class: 'secret-out', text: cmd }),
      el('p', { class: 'note', text: r.uses === 1
        ? 'One-shot: this node will not be able to rejoin after a reboot.'
        : 'It binds to the first node\'s public IP and rejoins after a reboot.' }));
    loadPtokens();
  } catch (err) { toast(err.message, true); }
});

async function loadPtokens() {
  const r = await api('/nodes/provision-tokens');
  const rows = (r.tokens || []).map((t) => [
    { node: el('code', { text: t.id }) },
    `${t.region}/${t.role}`,
    { node: el('span', { class: 'pill ' + (t.state === 'live' ? 'ok' : 'bad'),
                         text: t.state }) },
    `${t.uses}/${t.max_uses}`,
    t.bound_to || '—',
    t.node_id || '—',
    fmtTime(t.expires_at),
    { node: t.state === 'live'
        ? el('button', { class: 'small danger', text: 'Revoke',
            onclick: async () => {
              if (!confirm(`Revoke token ${t.id}? Its node keeps running but cannot re-register.`)) return;
              try {
                await api(`/nodes/provision-tokens/${t.id}/revoke`, { method: 'POST' });
                toast(`Token ${t.id} revoked`); loadPtokens();
              } catch (err) { toast(err.message, true); }
            } })
        : el('span', { class: 'note', text: '—' }) },
  ]);
  $('ptok-list').replaceChildren(rows.length
    ? table(['Id', 'Scope', 'State', 'Used', 'Bound to', 'Node', 'Expires', ''], rows)
    : el('p', { class: 'note', text: 'No tokens have been minted.' }));
}

/* --- payments ------------------------------------------------------------ */
async function loadPayments() { await Promise.all([loadPayHealth(), loadInvoices()]); }

async function loadPayHealth() {
  const h = await api('/payments/health');
  const ok = h.reachable;
  $('pay-health').replaceChildren(
    table(['Provider', 'Reachable', 'Accepts', 'Detail'], [[
      { node: el('code', { text: h.provider }) },
      { node: el('span', { class: 'pill ' + (ok ? 'ok' : 'bad'),
          text: ok ? 'yes' : 'no' }) },
      (h.currencies || []).join(', '),
      h.detail || '',
    ]]),
    h.missing_settings && h.missing_settings.length
      ? el('p', { class: 'note', text:
          'Not configured yet: ' + h.missing_settings.join(', ') +
          ' — set these under Settings, then re-check.' })
      : null);
}

async function loadInvoices() {
  const d = await api(`/invoices?status=${$('inv-status').value}&limit=50`);
  $('inv-list').replaceChildren(table(
    ['Invoice', 'Account', 'Months', 'Amount', 'Status', 'Created', ''],
    d.invoices.map((i) => [
      { node: el('code', { text: short(i.id, 22) }) },
      { node: el('code', { text: '#' + i.account_id }) },
      String(i.months), fmtMoney(i.amount_usd),
      { node: el('span', {
          class: 'pill ' + ({ settled: 'ok', pending: 'warn' }[i.status] || 'neutral'),
          text: i.status }) },
      fmtDate(i.created_at),
      { node: i.status === 'settled' ? el('span', { class: 'dim', text: '—' })
          : el('button', { class: 'small', text: 'Mark paid', onclick: async () => {
              if (!confirm(`Credit invoice ${i.id} by hand? Use this when the payment landed on chain but the webhook never arrived.`)) return;
              const r = await api(`/invoices/${i.id}/settle`, { method: 'POST' });
              toast(r.duplicate ? 'Already settled' : 'Credited'); loadInvoices(); } }) },
    ])));
}

$('pay-recheck').addEventListener('click', () => loadPayHealth().then(() => toast('Re-checked')));
$('inv-refresh').addEventListener('click', loadInvoices);

/* --- notices ------------------------------------------------------------- */
async function loadNotices() {
  const d = await api('/notices');
  $('notice-list').replaceChildren(table(
    ['Severity', 'Subject', 'Audience', 'Read', 'Posted', ''],
    d.notices.map((n) => [
      { node: el('span', {
          class: 'pill ' + ({ urgent: 'bad', warning: 'warn' }[n.severity] || 'neutral'),
          text: n.severity }) },
      n.subject,
      n.account_id ? `account #${n.account_id}` : 'everyone',
      { text: String(n.reads), cls: 'num' },
      fmtDate(n.created_at),
      { node: el('button', { class: 'small danger', text: 'Withdraw', onclick: async () => {
          await api(`/notices/${n.id}`, { method: 'DELETE' });
          toast('Notice withdrawn'); loadNotices(); } }) },
    ])));
}

$('notice-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target).entries());
  const body = { subject: f.subject, body: f.body, severity: f.severity,
                 expires_days: Number(f.expires_days) };
  if (String(f.account_id).trim()) body.account_id = Number(f.account_id);
  try {
    const r = await api('/notices', { method: 'POST', body });
    toast(`Posted. ${r.reach} account(s) will see it on their next check-in.`);
    e.target.reset(); loadNotices();
  } catch (err) { toast(err.message, true); }
});

/* --- settings ------------------------------------------------------------ */
const GROUP_LABELS = {
  payments: 'Active provider', btcpay: 'BTCPay Server',
  hosted: 'Hosted crypto gateway', stripe: 'Stripe (cards)',
  square: 'Square (cards)', wallets: 'Business wallets',
  monero: 'Monero (view-only wallet)',
  chain: 'Public chain endpoints', trial: 'Free trial', ops: 'Operations',
  other: 'Other',
};
const GROUP_NOTES = {
  wallets: 'Where funds actually land. The watch-only provider derives a fresh receive address per invoice from these — paste the PUBLIC key (xpub/ypub/zpub), never a private one. A plain address works but is reused for every customer, which makes two payments of the same amount impossible to tell apart. BTC and ZEC are live; ZEC means transparent t1 addresses, since shielded ones cannot be watched from a public key. ETH is read only by BTCPay and hosted gateways.',
  monero: 'Monero has no address to paste. The chain publishes neither recipient nor amount, so detecting a payment needs the private view key and a block scan — a wallet, not a derivation. Point this at a monero-wallet-rpc running VIEW-ONLY against a public remote node: no chain on disk, and nothing here can spend. scripts/setup-monero-watch.sh walks it. Leave the URL blank and XMR is simply not offered at checkout.',
  chain: 'Whose node we borrow. This deployment never syncs a chain locally. The BTC endpoint speaks Esplora (blank = mempool.space); the ZEC one speaks Blockchair or Esplora, chosen automatically from the URL. The price ticker converts USD to each coin — blank uses Kraken\'s public endpoint, which needs no account. The ETH row is reference only; nothing reads it.',
  stripe: 'Cards mean a real identity behind every payment, and a processor that can reverse one. See privacy.html before enabling.',
  square: 'Same trade-off as Stripe: identity behind the card, reversible payments, a third party in the middle.',
  ops: 'Where node-down and disk alerts get pushed. Any endpoint that takes a JSON POST — Slack, ntfy, Discord, your own. Leave it blank and events still appear under Events; the webhook is only a nudge.',
};

async function loadSettings() {
  const d = await api('/settings');
  const groups = {};
  for (const [key, spec] of Object.entries(d.settings)) {
    (groups[spec.group] ||= []).push([key, spec]);
  }
  const order = ['payments', 'wallets', 'chain', 'btcpay', 'hosted', 'stripe',
                 'square', 'trial', 'ops', 'other'];
  const container = $('settings-groups');
  container.replaceChildren(...order.filter((g) => groups[g]).map((g) =>
    el('div', { class: 'set-group' }, [
      el('h3', { text: GROUP_LABELS[g] || g }),
      GROUP_NOTES[g] ? el('p', { class: 'note', text: GROUP_NOTES[g] }) : null,
      el('div', { class: 'set-grid' }, groups[g].map(([key, spec]) => {
        const id = 'set-' + key;
        let field;
        if (spec.type === 'choice') {
          field = el('select', { id, name: key }, (spec.choices || []).map(
            (c) => el('option', { value: c, text: c, ...(c === spec.value ? { selected: 'selected' } : {}) })));
        } else if (spec.type === 'bool') {
          field = el('select', { id, name: key }, ['1', '0'].map(
            (c) => el('option', { value: c, text: c === '1' ? 'enabled' : 'disabled',
              ...(String(spec.value) === c ? { selected: 'selected' } : {}) })));
        } else {
          field = el('input', { id, name: key,
            type: spec.type === 'int' ? 'number' : 'text',
            placeholder: spec.secret ? 'not set' : '' });
          field.value = spec.value || '';
        }
        return el('div', {}, [
          el('label', { for: id }, [spec.label,
            spec.secret ? el('span', { class: 'dim', text: ' — secret' }) : null]),
          field]);
      })),
    ])));
}

$('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const values = {};
  for (const f of e.target.querySelectorAll('input[name], select[name]')) {
    values[f.name] = f.value;
  }
  try {
    const r = await api('/settings', { method: 'POST', body: { values } });
    toast(r.changed.length
      ? `Saved: ${r.changed.join(', ')}`
      : 'Nothing changed');
    loadSettings();
  } catch (err) { toast(err.message, true); }
});

$('pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target).entries());
  try {
    await api('/password', { method: 'POST', body: f });
    toast('Password changed. Signing out.');
    setTimeout(() => location.reload(), 1500);
  } catch (err) { toast(err.message, true); }
});

/* --- operational events --------------------------------------------------- */
async function loadEvents() {
  const d = await api('/events?limit=200');
  $('events-webhook').textContent = d.webhook_configured
    ? 'A webhook is configured; new events are pushed to it as well.'
    : 'No webhook configured — set one under Settings → Operations to be told '
      + 'about these without opening the dashboard.';
  $('events-list').replaceChildren(
    d.events.length
      ? table(['When', 'Severity', 'Kind', 'Subject', 'Detail'],
          d.events.map((x) => [
            fmtTime(x.created_at), x.severity, x.kind, x.subject || '',
            x.detail || '']))
      : el('p', { class: 'note', text: 'Nothing has gone wrong yet.' }));
  paintEventsBadge(d.unresolved);
}

// The badge is the whole point: an operator who has to open a tab to find out
// something broke will find out from a customer instead.
function paintEventsBadge(n) {
  const b = $('events-badge');
  if (!b) return;
  b.textContent = n > 99 ? '99+' : String(n);
  b.classList.toggle('hidden', !n);
}

/* --- audit --------------------------------------------------------------- */
async function loadAudit() {
  const d = await api(`/audit?limit=200&action=${encodeURIComponent($('audit-filter').value.trim())}`);
  $('audit-list').replaceChildren(
    el('p', { class: 'note', text: `${d.total} entr${d.total === 1 ? 'y' : 'ies'}` }),
    table(['When', 'Who', 'Action', 'Target', 'Detail'],
      d.entries.map((x) => [
        fmtTime(x.at), x.username, x.action, short(x.target, 30), x.detail || ''])));
}
$('events-refresh').addEventListener('click', loadEvents);
$('audit-refresh').addEventListener('click', loadAudit);
$('audit-filter').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadAudit(); });

boot().catch((e) => { showGate(); toast(e.message, true); });
