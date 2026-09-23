// The trial offer, rendered from the control plane rather than from whatever
// this file last said.
//
// /api/v1/config publishes trial.days and a phrased trial.label, and the
// invariant is that nothing hardcodes the length in copy — an operator who
// changes it in the dashboard must not leave a page advertising the old
// offer. index.html and trial.html each grew their own copy of this fetch
// because each also does page-specific work with the result; this is the
// generic core, so a page that only needs to say "a week" does not need a
// third one.
//
// Everything it touches has a server-rendered fallback in the markup, so a
// blocked or failed fetch leaves the page saying something true-ish rather
// than blank. That is why there is no error path here: the fallback IS the
// error path.
(async () => {
  try {
    const cfg = await (await fetch('/api/v1/config')).json();
    const t = cfg.trial || {};
    if (!t.days) return;

    const label = t.label || '';
    // "one week" -> "week", for copy that already supplies its own article.
    const unit = label.replace(/^(one|two|three|four|five|six|seven)\s+/i, '');
    const cap = label.replace(/^./, c => c.toUpperCase());

    const fill = (sel, value) => {
      if (value === undefined || value === null || value === '') return;
      document.querySelectorAll(sel).forEach(e => { e.textContent = value; });
    };
    fill('[data-trial="label"]', label);
    fill('[data-trial="label-cap"]', cap);
    fill('[data-trial="unit"]', unit);
    fill('[data-trial="days"]', t.days);
    fill('[data-trial="devs"]', t.max_devices);
    fill('[data-paid="devs"]', cfg.max_devices);

    // What this deployment can actually take. The static copy says Bitcoin,
    // because a fresh install has only WALLET_BTC set and that is the state
    // it launches in; an operator who has added a Zcash xpub or stood up the
    // Monero view-only wallet should not be underselling it, and one who has
    // not must never see a coin advertised that produces no address.
    const cur = cfg.currencies || [];
    if (cur.length) {
      const list = cur.length === 1 ? cur[0]
        : cur.slice(0, -1).join(', ') + ' and ' + cur[cur.length - 1];
      fill('[data-pay="codes"]', cfg.takes_cards ? 'card payments' : list);
    }

    // A paused trial must not leave a page shouting about a free week that
    // cannot be claimed. Pages opt in by marking the elements that promise
    // one; nothing is hidden unless the page asked for it to be.
    if (t.enabled === false) {
      document.querySelectorAll('[data-trial-when="enabled"]')
        .forEach(e => { e.hidden = true; });
      document.querySelectorAll('[data-trial-when="disabled"]')
        .forEach(e => { e.hidden = false; });
    }
  } catch (e) { /* keep the served copy */ }
})();
