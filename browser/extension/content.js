// Cortmed icerik betigi: yalnizca sifre alani gonderimini dinler, sayfa icerigini okumaz.
// Sifre yalnizca service worker'a mesajla gider; burada saklanmaz.
(function () {
  'use strict';
  if (window.top !== window) return;
  if (location.protocol !== 'https:' && location.protocol !== 'http:') return;
  if (window.__cortmedContentLoaded) return;
  window.__cortmedContentLoaded = true;

  const PW = 'input[type="password"]';
  const CONTROL = 'button, input[type="submit"], input[type="button"], input[type="image"], [role="button"]';
  const DEDUPE_MS = 2000;
  const CARD_MS = 30000;

  function send(msg, cb) {
    try {
      chrome.runtime.sendMessage(msg, function (reply) {
        void (chrome.runtime && chrome.runtime.lastError);
        if (cb) cb(reply);
      });
    } catch (e) { /* eklenti yeniden yuklendiyse baglam gecersiz; sessiz kal */ }
  }

  // ---------- Kartlar (kapali shadow root) ----------
  const CSS = [
    ':host{all:initial}',
    '.stack{display:flex;flex-direction:column;gap:10px;align-items:flex-end;font-family:"Segoe UI",system-ui,-apple-system,sans-serif}',
    '.card{box-sizing:border-box;width:340px;max-width:calc(100vw - 32px);background:#13223A;color:#F1F5FB;border:1px solid #0B1526;',
    'border-left:6px solid #29B6F6;border-radius:12px;padding:14px 16px;box-shadow:0 8px 28px rgba(0,0,0,.45);font-size:15px;line-height:1.45}',
    '.card.leak{border-left-color:#EF5350}',
    '.card.reuse{border-left-color:#FFB300}',
    '.card.mfa{border-left-color:#29B6F6}',
    '.brand{font-size:12px;color:#93A4BD;margin:0 0 6px;letter-spacing:.02em}',
    '.brand .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:#29B6F6}',
    '.leak .brand .dot{background:#EF5350}.reuse .brand .dot{background:#FFB300}',
    'p.text{margin:0 0 12px}',
    'b{color:#FFFFFF;font-weight:700}',
    '.btns{display:flex;flex-wrap:wrap;gap:8px}',
    'button{all:unset;cursor:pointer;box-sizing:border-box;padding:7px 12px;border-radius:8px;font-size:14px;font-family:inherit;',
    'background:#0B1526;color:#F1F5FB;border:1px solid #93A4BD}',
    'button.primary{background:#29B6F6;color:#0B1526;border-color:#29B6F6;font-weight:600}',
    '.leak button.primary{background:#EF5350;border-color:#EF5350;color:#FFFFFF}',
    '.reuse button.primary{background:#FFB300;border-color:#FFB300;color:#0B1526}',
    'button:focus-visible{outline:2px solid #F1F5FB;outline-offset:2px}',
    'button:hover{filter:brightness(1.1)}'
  ].join('');

  let host = null, stack = null;

  function ensureStack() {
    if (host && host.isConnected) return stack;
    host = document.createElement('cortmed-koruma');
    host.setAttribute('style', [
      'all:initial !important', 'position:fixed !important', 'right:16px !important', 'bottom:16px !important',
      'z-index:2147483647 !important', 'display:block !important', 'margin:0 !important', 'padding:0 !important'
    ].join(';'));
    const root = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = CSS;
    stack = document.createElement('div');
    stack.className = 'stack';
    root.appendChild(style);
    root.appendChild(stack);
    document.documentElement.appendChild(host);
    return stack;
  }

  // parts: dizeler ya da {b: 'kalin'}; hepsi textContent ile yazilir (HTML yok).
  function para(parts) {
    const p = document.createElement('p');
    p.className = 'text';
    parts.forEach(function (x) {
      if (typeof x === 'string') p.appendChild(document.createTextNode(x));
      else { const b = document.createElement('b'); b.textContent = x.b; p.appendChild(b); }
    });
    return p;
  }

  // buttons: [{label, act, primary, onClick, keep}]
  // Ayni turden yeni kart eskisinin yerini alir (her turden en fazla bir kart).
  const openCards = {};
  function showCard(kind, parts, buttons) {
    const s = ensureStack();
    if (openCards[kind]) openCards[kind]();
    const card = document.createElement('div');
    card.className = 'card ' + kind;
    card.setAttribute('data-kind', kind);
    card.setAttribute('role', kind === 'leak' ? 'alert' : 'status');
    const brand = document.createElement('div');
    brand.className = 'brand';
    const dot = document.createElement('span');
    dot.className = 'dot';
    brand.appendChild(dot);
    brand.appendChild(document.createTextNode('Cortmed Security'));
    card.appendChild(brand);
    card.appendChild(para(parts));
    let closed = false;
    function close() {
      if (closed) return;
      closed = true;
      if (openCards[kind] === close) delete openCards[kind];
      if (card.parentNode) card.parentNode.removeChild(card);
    }
    openCards[kind] = close;
    const row = document.createElement('div');
    row.className = 'btns';
    buttons.forEach(function (b) {
      const el = document.createElement('button');
      el.type = 'button';
      el.textContent = b.label;
      el.setAttribute('data-act', b.act);
      if (b.primary) el.className = 'primary';
      el.addEventListener('click', function (e) {
        e.stopPropagation();
        if (b.onClick) b.onClick();
        if (!b.keep) close();
      });
      row.appendChild(el);
    });
    card.appendChild(row);
    // Kirmizi kart her zaman en ustte
    if (kind === 'leak') s.insertBefore(card, s.firstChild); else s.appendChild(card);
    setTimeout(close, CARD_MS);
    return card;
  }

  function showLeaked(count) {
    showCard('leak', [
      'Bu şifre daha önce internete sızmış (', { b: Number(count).toLocaleString('tr-TR') }, ' kez görülmüş). Hemen değiştirin.'
    ], [{ label: 'Tamam', act: 'close', primary: true }]);
  }

  function showReuse(sites) {
    const shown = sites.slice(0, 5).join(', ') + (sites.length > 5 ? ', …' : '');
    showCard('reuse', [
      'Bu şifreyi başka ', { b: String(sites.length) }, ' sitede de kullanıyorsunuz: ' + shown +
      '. Bir site sızarsa hepsi tehlikeye girer. Bu site için farklı bir şifre seçin.'
    ], [
      { label: 'Tamam', act: 'close', primary: true },
      { label: 'Bu site için bir daha gösterme', act: 'mute', onClick: function () { send({ type: 'reuseMute', site: location.hostname }); } }
    ]);
  }

  function showResult(r) {
    if (!r || typeof r !== 'object') return;
    const leaked = Number(r.leaked) || 0;
    const reuse = Array.isArray(r.reuse) ? r.reuse.map(String) : [];
    if (leaked > 0) showLeaked(leaked);
    if (reuse.length) showReuse(reuse);
    if (leaked > 0 || reuse.length) send({ type: 'cardsShown' });
  }

  // ---------- Giris denemesi algilama ----------
  function filledIn(scope) {
    if (!scope || !scope.querySelectorAll) return null;
    const list = scope.querySelectorAll(PW);
    for (let i = list.length - 1; i >= 0; i--) if (list[i].value) return list[i];
    return null;
  }

  function fieldForControl(ctl) {
    const form = ctl.form || ctl.closest('form');
    const inForm = filledIn(form);
    if (inForm) return inForm;
    let n = ctl.parentElement;
    for (let i = 0; i < 5 && n && n !== document.body && n !== document.documentElement; i++, n = n.parentElement) {
      const f = filledIn(n);
      if (f) return f;
    }
    return null;
  }

  let last = null, lastTimer = 0;
  function attempt(field) {
    const value = field && field.value;
    if (!value) return;
    const t = Date.now();
    if (last && last.field === field && last.value === value && t - last.t < DEDUPE_MS) return;
    last = { field: field, value: value, t: t };
    clearTimeout(lastTimer);
    lastTimer = setTimeout(function () { last = null; }, DEDUPE_MS);
    send({ type: 'pwSubmit', site: location.hostname, password: value }, showResult);
  }

  function origin(e) {
    const p = e.composedPath ? e.composedPath() : null;
    const t = p && p.length ? p[0] : e.target;
    return t instanceof Element ? t : null;
  }

  document.addEventListener('submit', function (e) {
    const f = filledIn(e.target);
    if (f) attempt(f);
  }, true);

  document.addEventListener('click', function (e) {
    const t = origin(e);
    if (!t || (host && (t === host || host.contains(t)))) return;
    const ctl = t.closest(CONTROL);
    if (!ctl || ctl.matches(PW)) return;
    const f = fieldForControl(ctl);
    if (f) attempt(f);
  }, true);

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' || e.isComposing) return;
    const t = origin(e);
    if (!t || !t.matches(PW)) return;
    const f = filledIn(t.form) || (t.value ? t : null);
    if (f) attempt(f);
  }, true);

  // ---------- MFA karti (sayfa basina en fazla bir kez) ----------
  let mfaShown = false;
  send({ type: 'mfaCheck', site: location.hostname }, function (r) {
    if (mfaShown || !r || !r.show || typeof r.name !== 'string') return;
    mfaShown = true;
    const site = location.hostname;
    showCard('mfa', [
      { b: r.name }, ' hesabınızda iki adımlı doğrulama açık mı? Açıksa şifreniz çalınsa bile hesabınıza girilemez.'
    ], [
      { label: 'Nasıl açılır?', act: 'how', primary: true, keep: true, onClick: function () { send({ type: 'mfaOpen', id: r.id, site: site }); } },
      { label: 'Açık', act: 'ok', onClick: function () { send({ type: 'mfaAnswer', site: site, answer: 'ok' }); } },
      { label: 'Sonra', act: 'later', onClick: function () { send({ type: 'mfaAnswer', site: site, answer: 'later' }); } }
    ]);
  });

  // Onceki sayfa gonderimden hemen sonra kapandiysa kartlar burada gosterilir.
  send({ type: 'pendingCards' }, showResult);
})();
