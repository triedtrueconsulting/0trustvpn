// ============================================================================
// 0trust GUI client
// ============================================================================

const $ = (id) => document.getElementById(id);

// True when the kill-switch setting has changed under a tunnel that is
// already up, so the running tunnel does not yet reflect it.
let ksPending = false;

let state = null;
let pollHandle = null;

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function render() {
  if (!state) return;
  const loggedIn = state.logged_in;
  $('view-login').classList.toggle('hidden', loggedIn);
  $('view-main').classList.toggle('hidden', !loggedIn);
  if (!loggedIn) return;

  // Kill switch. Rendered from state every poll so it can never drift from
  // what the client will actually write on the next connect. ksPending
  // carries the one thing state cannot tell us — that the running tunnel was
  // built before the setting changed, so the change is not in force yet.
  const ks = $('ks-toggle'), ksLabel = $('ks-label'), ksHint = $('ks-hint');
  if (ks) {
    ks.checked = !!state.kill_switch;
    ks.disabled = !state.kill_switch_supported;
    ksLabel.textContent = state.kill_switch ? 'on' : 'off';
    if (!state.kill_switch_supported) {
      ksHint.textContent =
        'Not available on this platform — wg-quick here drives pf, not iptables.';
    } else if (state.kill_switch) {
      ksHint.textContent =
        'Traffic outside the tunnel is blocked, including your local network.';
    } else {
      ksHint.textContent =
        'If the tunnel drops, traffic falls back to your normal connection.';
    }
    if (ksPending) {
      // The rules go in as wg-quick PostUp/PreDown, so they land when the
      // interface next comes up. Someone who ticked the box and saw nothing
      // else would reasonably assume they were already covered.
      ksHint.textContent += ' Not in force yet — applies the next time you connect.';
    }
  }

  // Status block
  const light = $('status-light');
  const text = $('status-text');
  const sub = $('status-sub');
  light.classList.remove('connected', 'busy');
  if (state.tunnel_up) {
    light.classList.add('connected');
    text.textContent = 'Connected';
    sub.textContent = state.multihop
      ? `multi-hop · ${state.entry_region} → ${state.exit_region}`
      : `single-hop · ${state.entry_region || 'unknown'}`;
    $('toggle-btn').textContent = 'Disconnect';
    $('toggle-btn').classList.add('connected');
  } else {
    text.textContent = 'Disconnected';
    sub.textContent = 'no tunnel';
    $('toggle-btn').textContent = 'Connect';
    $('toggle-btn').classList.remove('connected');
  }

  // Restore region pickers from state (only if user hasn't touched them)
  const entrySel = $('entry-select');
  const exitSel = $('exit-select');
  if (state.entry_region && entrySel.value === entrySel.dataset.lastFromState) {
    entrySel.value = state.entry_region;
    entrySel.dataset.lastFromState = state.entry_region;
  }
  if (exitSel.value === exitSel.dataset.lastFromState) {
    exitSel.value = state.exit_region || '';
    exitSel.dataset.lastFromState = state.exit_region || '';
  }
  updateRouteHint();

  // Multi-hop details card
  if (state.multihop && state.tunnel_up) {
    $('hop-details').classList.remove('hidden');
    $('kv-mode').textContent = 'multi-hop';
    $('kv-entry').textContent = state.entry_region || '—';
    $('kv-exit').textContent = state.exit_region || '—';
    $('kv-rotates').textContent = formatRotate(state.hop_expires_at);
  } else {
    $('hop-details').classList.add('hidden');
  }

  // Account card
  $('kv-token').textContent = state.token || '—';
  // Say "active (trial)" rather than just "active": the difference is a
  // hard expiry and a smaller device cap, and the user should see it here
  // rather than discover it when a third device is refused.
  $('kv-sub').textContent = state.status
    ? state.status + (state.plan === 'trial' ? ' (trial)' : '')
    : '—';
  $('kv-exp').textContent = state.expires_at
    ? new Date(state.expires_at * 1000).toISOString().slice(0, 10)
    : '—';
  // No `|| 8`. The cap is 8 paid and 2 on trial, and printing the paid
  // number when the API did not send one told trial customers they had six
  // slots spare until the next register returned 409 — CLAUDE.md's recurring
  // bug class #11, which has shipped three times. If max_devices is absent,
  // say so rather than guessing.
  $('kv-dev').textContent =
    state.device_count == null ? '—'
      : state.max_devices ? `${state.device_count} / ${state.max_devices}`
      : `${state.device_count}`;
}

function formatRotate(ts) {
  if (!ts) return '—';
  const diffMs = ts * 1000 - Date.now();
  if (diffMs <= 0) return 'due now';
  const hrs = Math.floor(diffMs / 3600000);
  const mins = Math.floor((diffMs % 3600000) / 60000);
  return hrs ? `in ${hrs}h ${mins}m` : `in ${mins}m`;
}

function updateRouteHint() {
  const exit = $('exit-select').value;
  const el = $('route-hint');
  if (!exit) {
    el.textContent =
      'Single-hop: one node terminates your tunnel and routes to the internet.';
    el.classList.remove('warn');
    return;
  }
  // On a single-VPS test deployment the control plane resolves entry and exit
  // to the same machine. The routing is real and worth testing; the privacy
  // property is not, and repeating the usual claim there would be a plain
  // lie. The CLI and both mobile apps already said so — the window did not.
  if (state && state.same_host) {
    el.textContent =
      'Entry and exit are the SAME machine on this deployment. The routing ' +
      'is real; nothing is hidden. Multi-hop proves nothing here.';
    el.classList.add('warn');
    return;
  }
  el.textContent =
    'Multi-hop: entry decrypts nothing; exit never sees your IP. The pair rotates every 24h.';
  el.classList.remove('warn');
}

// ---------------------------------------------------------------------------
// Toast
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(msg, kind = 'info') {
  const el = $('toast');
  el.textContent = msg;
  el.className = 'toast' + (kind === 'error' ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3500);
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

async function refresh() {
  try {
    state = await api('/api/state');
    render();
  } catch (e) {
    console.warn('state poll failed:', e);
  }
}

function startPolling() {
  if (pollHandle) clearInterval(pollHandle);
  pollHandle = setInterval(refresh, 3000);
  refreshNotices();
  // Far slower than the state poll: a notice is posted by an hourly sweeper,
  // so checking every three seconds would be pure noise on the control plane.
  if (noticeHandle) clearInterval(noticeHandle);
  noticeHandle = setInterval(refreshNotices, 120000);
}

// ---------------------------------------------------------------------------
// Notices
//
// The service has no email address for this account — that is the product —
// so this banner is the only way a renewal warning reaches anyone. If it is
// not rendered here, it is not delivered at all.
// ---------------------------------------------------------------------------

let noticeHandle = null;

async function refreshNotices() {
  const box = $('notices');
  if (!box) return;
  let list;
  try {
    list = await api('/api/notices');
  } catch (e) {
    return;   // not signed in, or the control plane is unreachable
  }
  if (!Array.isArray(list) || list.length === 0) {
    box.classList.add('hidden');
    box.innerHTML = '';
    return;
  }
  box.innerHTML = '';
  for (const n of list) {
    const el = document.createElement('div');
    el.className = 'notice ' + (n.severity || 'info');
    const h = document.createElement('h3');
    h.textContent = n.subject || '';
    const btn = document.createElement('button');
    btn.className = 'dismiss';
    btn.textContent = 'Dismiss';
    btn.addEventListener('click', async () => {
      try {
        await api('/api/notices/read', {
          method: 'POST',
          body: JSON.stringify({ id: n.id }),
        });
      } catch (e) { /* it comes back on the next poll if this failed */ }
      refreshNotices();
    });
    const p = document.createElement('p');
    p.textContent = n.body || '';
    el.append(h, btn, p);
    box.appendChild(el);
  }
  box.classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Region picker
// ---------------------------------------------------------------------------

async function loadRegions() {
  const regions = await api('/api/regions');
  const entrySel = $('entry-select');
  const exitSel = $('exit-select');
  entrySel.innerHTML = '';
  for (const r of regions) {
    const o1 = document.createElement('option');
    o1.value = r.code; o1.textContent = `${r.code.toUpperCase()}  ${r.name}`;
    entrySel.appendChild(o1);
    const o2 = document.createElement('option');
    o2.value = r.code; o2.textContent = `${r.code.toUpperCase()}  ${r.name}`;
    exitSel.appendChild(o2);
  }
}

// ---------------------------------------------------------------------------
// Token input — auto-format and uppercase
// ---------------------------------------------------------------------------

$('token-input').addEventListener('input', (e) => {
  let v = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (v.length > 16) v = v.slice(0, 16);
  const parts = [];
  for (let i = 0; i < v.length; i += 4) parts.push(v.slice(i, i + 4));
  e.target.value = parts.join('-');
});

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

$('login-btn').addEventListener('click', async () => {
  const token = $('token-input').value.trim();
  $('login-err').classList.add('hidden');
  try {
    await api('/api/login', { method: 'POST', body: JSON.stringify({ token }) });
    toast('Signed in');
    await refresh();
  } catch (e) {
    $('login-err').textContent = e.message;
    $('login-err').classList.remove('hidden');
  }
});

$('logout-btn').addEventListener('click', async () => {
  if (!confirm('Sign out? Your account token is the only way back. Make sure it\'s saved somewhere.')) return;
  try {
    await api('/api/logout', { method: 'POST' });
    toast('Signed out');
    state = { logged_in: false };
    render();
  } catch (e) {
    toast(e.message, 'error');
  }
});

$('toggle-btn').addEventListener('click', async () => {
  const light = $('status-light');
  light.classList.add('busy');
  try {
    if (state.tunnel_up) {
      await api('/api/disconnect', { method: 'POST' });
      toast('Disconnected');
    } else {
      const body = {
        region: $('entry-select').value,
        exit_region: $('exit-select').value,
      };
      const r = await api('/api/connect', { method: 'POST', body: JSON.stringify(body) });
      ksPending = false;   // this tunnel was built with the current setting
      toast(r.multihop ? `Connected — multi-hop via ${r.entry_node} → ${r.exit_node}` : 'Connected');
    }
    await refresh();
  } catch (e) {
    toast(e.message, 'error');
    light.classList.remove('busy');
  }
});

$('rotate-btn').addEventListener('click', async () => {
  const light = $('status-light');
  light.classList.add('busy');
  try {
    const r = await api('/api/rotate', { method: 'POST' });
    if (r.skipped) {
      toast('Single-hop has no pair to rotate');
    } else {
      toast(`Rotated → ${r.entry_node} → ${r.exit_node}`);
    }
    await refresh();
  } catch (e) {
    toast(e.message, 'error');
    light.classList.remove('busy');
  }
});

$('exit-select').addEventListener('change', updateRouteHint);

// ---------------------------------------------------------------------------
// Export modal
// ---------------------------------------------------------------------------

let lastExportConfig = '';

function openExportModal() {
  $('export-modal').classList.remove('hidden');
  $('export-step1').classList.remove('hidden');
  $('export-step2').classList.add('hidden');
  $('export-name').focus();
}
function closeExportModal() {
  $('export-modal').classList.add('hidden');
}

$('export-btn').addEventListener('click', openExportModal);
$('export-close').addEventListener('click', closeExportModal);
$('export-modal').addEventListener('click', (e) => {
  if (e.target.id === 'export-modal') closeExportModal();
});

$('export-go').addEventListener('click', async () => {
  const btn = $('export-go');
  btn.disabled = true;
  btn.textContent = 'Creating…';
  try {
    const body = {
      region: $('entry-select').value,
      exit_region: $('exit-select').value,
      name: $('export-name').value || 'phone',
    };
    const r = await api('/api/export', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    lastExportConfig = r.config;
    $('export-qr').src = r.qr_data_url;
    $('export-mode').textContent = r.multihop
      ? `multi-hop  ${r.entry_node} → ${r.exit_node}`
      : 'single-hop';
    $('export-step1').classList.add('hidden');
    $('export-step2').classList.remove('hidden');
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create QR code';
  }
});

$('export-copy').addEventListener('click', () => {
  navigator.clipboard.writeText(lastExportConfig).then(() => {
    toast('Config copied');
  });
});

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

function fmtSeen(ts) {
  if (!ts) return 'never';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {
    hour: '2-digit', minute: '2-digit',
  });
}

// Keys are base64 and long; show enough to tell two apart without wrapping.
function shortKey(k) {
  return k.length > 20 ? k.slice(0, 10) + '…' + k.slice(-6) : k;
}

async function loadDevices() {
  const list = $('devices-list');
  const err = $('devices-err');
  err.classList.add('hidden');
  list.textContent = 'Loading…';
  let devices;
  try {
    devices = await api('/api/devices');
  } catch (e) {
    list.textContent = '';
    err.textContent = e.message;
    err.classList.remove('hidden');
    return;
  }

  // Same reason as kv-dev above: never substitute the paid cap for a cap the
  // control plane did not send.
  const cap = state && state.max_devices;
  $('devices-count').textContent =
    (cap ? `${devices.length} of ${cap} slots used`
         : `${devices.length} registered`) +
    (state && state.plan === 'trial' ? ' (trial)' : '');

  list.textContent = '';
  if (!devices.length) {
    list.textContent = 'No devices registered yet.';
    return;
  }
  for (const d of devices) {
    const row = document.createElement('div');
    row.className = 'kv-row device-row';

    const meta = document.createElement('div');
    const name = document.createElement('div');
    name.textContent = (d.device_name || 'unnamed') + (d.this ? '  · this device' : '');
    // Its own class, not the .k label style — that uppercases, and a device
    // the user named "MacBook" should not come back as "MACBOOK".
    name.className = 'device-name' + (d.this ? ' is-this' : '');
    const sub = document.createElement('div');
    sub.className = 'hint mono';
    sub.textContent = `${d.mesh_ip}  ${shortKey(d.pubkey)}` +
      (d.multihop ? `  ${d.entry_node} → ${d.exit_node}` : '  single-hop') +
      `  seen ${fmtSeen(d.last_seen)}`;
    meta.appendChild(name);
    meta.appendChild(sub);

    const btn = document.createElement('button');
    btn.className = 'btn-ghost danger';
    btn.textContent = 'Remove';
    btn.addEventListener('click', async () => {
      const warning = d.this
        ? 'Remove THIS device? The tunnel will drop and a new key is generated on next connect.'
        : `Remove "${d.device_name || 'unnamed'}"? It stops being routed at the next sync.`;
      if (!confirm(warning)) return;
      btn.disabled = true;
      btn.textContent = 'Removing…';
      try {
        const r = await api('/api/devices/remove', {
          method: 'POST', body: JSON.stringify({ pubkey: d.pubkey }),
        });
        toast(r.removed_self ? 'Device removed — tunnel down' : 'Device removed');
        await loadDevices();
        await refresh();
      } catch (e) {
        err.textContent = e.message;
        err.classList.remove('hidden');
        btn.disabled = false;
        btn.textContent = 'Remove';
      }
    });

    row.appendChild(meta);
    row.appendChild(btn);
    list.appendChild(row);
  }
}

$('devices-btn').addEventListener('click', async () => {
  $('devices-modal').classList.remove('hidden');
  await loadDevices();
});
$('devices-close').addEventListener('click', () => {
  $('devices-modal').classList.add('hidden');
});

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

$('ks-toggle').addEventListener('change', async (e) => {
  const want = e.target.checked;
  const hint = $('ks-hint');
  e.target.disabled = true;
  try {
    await api('/api/killswitch', {
      method: 'POST', body: JSON.stringify({ enabled: want }),
    });
    // Tearing a live tunnel down under someone who ticked a box is not a
    // thing to do quietly, so the change waits for the next connect — and
    // the page has to keep saying so, not just once before the next poll
    // repaints over it.
    ksPending = !!(state && state.tunnel_up);
    toast(want ? 'Kill switch enabled' : 'Kill switch disabled');
  } catch (err) {
    e.target.checked = !want;
    ksPending = false;
    hint.textContent = err.message;
  } finally {
    e.target.disabled = false;
    await refresh();
  }
});

// ---------------------------------------------------------------------------
// Free trial
// ---------------------------------------------------------------------------

$('trial-btn').addEventListener('click', async () => {
  const btn = $('trial-btn');
  const status = $('trial-status');
  const err = $('trial-err');
  err.classList.add('hidden');
  status.classList.remove('hidden');
  // The proof-of-work runs in the Go process, not here, so the page stays
  // responsive and the puzzle finishes in a fraction of the time.
  status.textContent = 'Solving the anti-abuse puzzle…';
  btn.disabled = true;

  try {
    const r = await api('/api/trial', { method: 'POST', body: '{}' });
    status.textContent =
      `Signed in on a ${r.days}-day trial · ${r.max_devices} devices`;
    toast(`Trial activated — ${r.days} days`);
    await refresh();
  } catch (e) {
    status.classList.add('hidden');
    err.textContent = e.message;
    err.classList.remove('hidden');
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

// The trial length is an operator setting, so the sign-in copy asks the
// control plane rather than stating a number this file was compiled with.
// A failure here is not worth surfacing: the served wording still stands.
async function loadOffer() {
  try {
    const cfg = await api('/api/config');
    const t = cfg.trial || {};
    if (!t.days) return;
    const unit = (t.label || '').replace(/^(one|two|three|four|five|six)\s+/, '');
    document.querySelectorAll('[data-trial="label"]')
      .forEach(e => e.textContent = t.label);
    document.querySelectorAll('[data-trial="unit"]')
      .forEach(e => e.textContent = unit);
    document.querySelectorAll('[data-trial="days"]')
      .forEach(e => e.textContent = t.days);
    if (t.enabled === false) $('trial-card').classList.add('hidden');
  } catch (e) { /* keep the served copy */ }
}

(async function init() {
  await loadRegions();
  await loadOffer();
  await refresh();
  startPolling();
})();
