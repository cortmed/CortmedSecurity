// Cortmed icerik betigi: yalnizca sifre alani gonderimini dinler, sayfa icerigini okumaz.
// Sifre yalnizca service worker'a mesajla gider; burada saklanmaz.
(function () {
  'use strict';
  if (window.top !== window) return;
  if (location.protocol !== 'https:' && location.protocol !== 'http:') return;
  // document_start'ta calisir: dinleyiciler yalnizca window'a, sayfa betiklerinden once kurulur.
  // Kart ve MFA isleri DOM hazir olunca yapilir.

  const PW = 'input[type="password"]';
  const CARDS_SHOWN_DELAY_MS = 1500;
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

  // Giristen sonra baska siteye yonlenildiyse kart sifrenin girildigi siteyi adlandirir.
  function fromParts(from) {
    return from ? [{ b: from }, ' sitesinde girdiğiniz şifre için: '] : [];
  }

  function showLeaked(count, from) {
    showCard('leak', fromParts(from).concat([
      'Bu şifre daha önce internete sızmış (', { b: Number(count).toLocaleString('tr-TR') }, ' kez görülmüş). Hemen değiştirin.'
    ]), [{ label: 'Tamam', act: 'close', primary: true }]);
  }

  function showReuse(sites, from) {
    const shown = sites.slice(0, 5).join(', ') + (sites.length > 5 ? ' ve ' + (sites.length - 5) + ' site daha' : '');
    const buttons = [{ label: 'Tamam', act: 'close', primary: true }];
    // "Bir daha gösterme" bu sayfanin sitesine yazilir; baska siteden gelen kartta gosterilmez.
    if (!from) {
      buttons.push({ label: 'Bu site için bir daha gösterme', act: 'mute', onClick: function () { send({ type: 'reuseMute', site: location.hostname }); } });
    }
    showCard('reuse', fromParts(from).concat([
      'Bu şifreyi başka ', { b: String(sites.length) }, ' sitede de kullanıyorsunuz: ' + shown +
      '. Bir site sızarsa hepsi tehlikeye girer. Bu site için farklı bir şifre seçin.'
    ]), buttons);
  }

  function showResult(r) {
    if (!r || typeof r !== 'object') return;
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { showResult(r); }, { once: true });
      return;
    }
    const leaked = Number(r.leaked) || 0;
    const reuse = Array.isArray(r.reuse) ? r.reuse.map(String) : [];
    const from = typeof r.from === 'string' && r.from ? r.from.slice(0, 100) : null;
    if (leaked > 0) showLeaked(leaked, from);
    if (reuse.length) showReuse(reuse, from);
    // Form gonderiminde eski sayfa birazdan kapanir; kart gercekten goruldukten sonra bildir,
    // kapanirsa zamanlayici calismaz ve kart yeni sayfada yeniden gosterilir.
    if (leaked > 0 || reuse.length) setTimeout(function () { send({ type: 'cardsShown' }); }, CARDS_SHOWN_DELAY_MS);
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

  // ---------- Guven: yalnizca kullanicidan gelen olay ve deger ----------
  // Test kapisi: yalnizca test sayfasinin kendi dunyasinda tanimlanan bir degisken ve 127.0.0.1 uzerinde.
  // Gercek eklentide icerik betigi yalitilmis dunyada calisir; sayfanin tanimladigi degiskenleri goremez.
  function testTrust() {
    return self.__cortmedTestTrust === true && location.protocol === 'http:' && location.hostname === '127.0.0.1';
  }
  function trusted(e) { return !!(e && e.isTrusted) || testTrust(); }

  // Her sifre alaninin son GUVENILIR input olayindaki degeri (yapistirma ve otomatik doldurma da input uretir).
  const userValues = new WeakMap();
  const TRUST_RECENT_MS = 60000;
  function remember(field) {
    if (field && field.value) userValues.set(field, { value: field.value, t: Date.now() });
  }
  function userTyped(field) {
    const v = userValues.get(field);
    return !!v && !!field.value && v.value === field.value;
  }
  function recentlyTyped(field) {
    const v = userValues.get(field);
    return !!v && Date.now() - v.t < TRUST_RECENT_MS;
  }
  function onValue(e) {
    if (!trusted(e)) return;
    const t = origin(e);
    if (!t || !t.matches(PW)) return;
    remember(t);
  }

  // Banka sifresi / SMS kodu: yalnizca rakam ve en fazla 8 hane ya da one-time-code alani. Hic gonderilmez.
  function skipField(field) {
    const ac = String(field.getAttribute('autocomplete') || '').toLowerCase();
    return ac.indexOf('one-time-code') >= 0 || /^\d{1,8}$/.test(field.value);
  }

  let last = null, lastTimer = 0;
  function attempt(field) {
    const value = field && field.value;
    if (!value || !userTyped(field) || skipField(field)) return;
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

  // ---------- Hangi dugme giris sayilir ----------
  // "gir" ve "ileri" yalnizca tam kelime (Turkce harfler dahil sinir): "girdi", "bilgileri" eslesmez.
  const WB_L = '(?<![a-zçğıöşüâîû0-9])', WB_R = '(?![a-zçğıöşüâîû0-9])';
  const LOGIN_RX = new RegExp('giri[sş]|oturum|log ?in|sign ?in|devam|next|continue|g[öo]nder|kaydet|de[gğ]i[sş]tir|onayla|submit' +
    '|sonraki|g[üu]ncelle|update|save|change|do[gğ]rula|verify' +
    '|' + WB_L + '(?:gir|ileri)' + WB_R);
  const TOGGLE_RX = /g[öo]ster|gizle|show|hide|eye|g[öo]z/;

  function lowerBoth(s) {
    s = String(s || '').slice(0, 200);
    return [s.toLowerCase(), s.toLocaleLowerCase('tr-TR')];
  }
  function anyMatch(rx, parts) {
    for (let i = 0; i < parts.length; i++) {
      const v = lowerBoth(parts[i]);
      if (rx.test(v[0]) || rx.test(v[1])) return true;
    }
    return false;
  }
  function isRealSubmit(ctl) {
    if (!ctl.form) return false;
    if (ctl.tagName === 'BUTTON') return ctl.type === 'submit';
    return ctl.tagName === 'INPUT' && (ctl.type === 'submit' || ctl.type === 'image');
  }
  function isToggle(ctl, field) {
    if (ctl.hasAttribute('aria-pressed')) return true;
    if (field.id && ctl.getAttribute('aria-controls') === field.id) return true;
    return anyMatch(TOGGLE_RX, [ctl.textContent, ctl.getAttribute('aria-label'), ctl.getAttribute('title')]);
  }
  function isLoginControl(ctl, field) {
    if (isToggle(ctl, field)) return false;
    if (isRealSubmit(ctl)) return true;
    return anyMatch(LOGIN_RX, [ctl.textContent, ctl.getAttribute('aria-label'), ctl.value, ctl.getAttribute('title')]);
  }

  window.addEventListener('input', onValue, true);

  window.addEventListener('submit', function (e) {
    const f = filledIn(e.target);
    if (!f) return;
    // requestSubmit() de guvenilir submit uretir; kullanici etkinligi aranir.
    const ua = navigator.userActivation;
    const active = testTrust() || (ua ? ua.isActive : recentlyTyped(f));
    if (active) attempt(f);
  }, true);

  window.addEventListener('click', function (e) {
    if (!trusted(e)) return;
    const t = origin(e);
    if (!t || (host && (t === host || host.contains(t)))) return;
    const ctl = t.closest(CONTROL);
    if (!ctl || ctl.matches(PW)) return;
    const f = fieldForControl(ctl);
    if (f && isLoginControl(ctl, f)) attempt(f);
  }, true);

  window.addEventListener('keydown', function (e) {
    if (!trusted(e) || e.key !== 'Enter' || e.isComposing) return;
    const t = origin(e);
    if (!t || !t.matches(PW)) return;
    const f = filledIn(t.form) || (t.value ? t : null);
    if (f) attempt(f);
  }, true);

  // ---------- DOM hazir olunca: MFA karti ve bekleyen kartlar ----------
  function whenReady(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn, { once: true });
    else fn();
  }

  whenReady(function () {
  // MFA karti (sayfa basina en fazla bir kez)
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
  });
})();
