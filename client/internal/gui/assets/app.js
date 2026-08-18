// ============================================================================
// 0trust GUI client
// ============================================================================

const $ = (id) => document.getElementById(id);

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
  $('kv-sub').textContent = state.status || '—';
  $('kv-exp').textContent = state.expires_at
    ? new Date(state.expires_at * 1000).toISOString().slice(0, 10)
    : '—';
  $('kv-dev').textContent = state.device_count ? `${state.device_count} / 8` : '—';
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
  $('route-hint').textContent = exit
    ? 'Multi-hop: entry decrypts nothing; exit never sees your IP. The pair rotates every 24h.'
    : 'Single-hop: one node terminates your tunnel and routes to the internet.';
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
// Boot
// ---------------------------------------------------------------------------

(async function init() {
  await loadRegions();
  await refresh();
  startPolling();
})();
