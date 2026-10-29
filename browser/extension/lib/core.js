// Cortmed cekirdek mantik: sayfa, service worker ve content script'te ayni dosya.
(function (root) {
  'use strict';

  const TWO_PART = ['co.uk', 'com.tr', 'gov.tr', 'edu.tr', 'org.tr', 'net.tr', 'k12.tr', 'com.au', 'co.jp'];
  const SCAN_EXT = ['exe', 'msi', 'scr', 'bat', 'cmd', 'ps1', 'js', 'vbs', 'jar', 'zip', 'rar', '7z', 'iso', 'img'];

  function etld1(hostname) {
    const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.indexOf(':') >= 0) return h;
    const p = h.split('.');
    if (p.length <= 2) return h;
    const last2 = p.slice(-2).join('.');
    return TWO_PART.indexOf(last2) >= 0 ? p.slice(-3).join('.') : last2;
  }

  function toHex(buf, max) {
    const b = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length && (max === undefined || i < max); i++) {
      s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    }
    return s;
  }

  function fromHex(hex) {
    if (typeof hex !== 'string' || !/^[0-9a-f]{32}$/i.test(hex)) throw new Error('bad salt');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  // PBKDF2-SHA256, 100000 tur, ilk 16 bayt -> 32 kucuk hex
  async function fingerprint(password, saltHex) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: fromHex(saltHex), iterations: 100000, hash: 'SHA-256' }, key, 256);
    return toHex(bits, 16);
  }

  async function sha1Hex(text) {
    const d = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
    return toHex(d).toUpperCase();
  }

  // Ayni sitede parola degisirse eski fp'den cikarilir.
  function recordUse(index, fp, site) {
    const next = {};
    Object.keys(index || {}).forEach(function (k) {
      const sites = index[k].filter(function (s) { return k === fp || s !== site; });
      if (sites.length) next[k] = sites;
    });
    const list = next[fp] || [];
    const otherSites = list.filter(function (s) { return s !== site; });
    if (list.indexOf(site) < 0) list.push(site);
    next[fp] = list;
    return { index: next, otherSites: otherSites };
  }

  function mfaState(entry, now) {
    if (!entry) return 'ask';
    if (entry.status === 'ok') return 'ok';
    if (entry.status === 'never') return 'never';
    if (entry.status === 'later') return entry.until > now ? 'snoozed' : 'ask';
    return 'ask';
  }

  function isScannable(filename) {
    const m = /\.([^.\\/]+)$/.exec(String(filename || ''));
    return !!m && SCAN_EXT.indexOf(m[1].toLowerCase()) >= 0;
  }

  // HIBP range govdesi: "SUFFIX:COUNT" satirlari
  function parseRange(body, suffix) {
    const want = String(suffix).toUpperCase();
    const lines = String(body || '').split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const c = lines[i].indexOf(':');
      if (c > 0 && lines[i].slice(0, c).trim().toUpperCase() === want) {
        const n = parseInt(lines[i].slice(c + 1), 10);
        return isNaN(n) ? 0 : n;
      }
    }
    return 0;
  }

  // --- Service worker isleyicileri (saf; depo, fetch ve saat disaridan verilir) ---
  const DAY = 24 * 3600 * 1000;
  const HIBP_TTL = 30 * DAY;
  const LATER_MS = 7 * DAY;
  const SHOWN_MS = 7 * DAY; // gosterilip cevaplanmayan kart "Sonra" gibi sayilir
  const HIBP_URL = 'https://api.pwnedpasswords.com/range/';
  const HIBP_TIMEOUT_MS = 5000;
  const HIBP_CACHE_MAX = 300;
  const RATE_MAX = 5;
  const RATE_WINDOW = 10 * 60 * 1000;
  const PENDING_MS = 60000;

  function direct(fn) { return fn(); }

  function timeoutSignal(ms) {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') return AbortSignal.timeout(ms);
    if (typeof AbortController === 'undefined') return undefined;
    const c = new AbortController();
    setTimeout(function () { c.abort(); }, ms);
    return c.signal;
  }

  function randomHex(deps, n) {
    const b = deps.randomBytes ? deps.randomBytes(n) : crypto.getRandomValues(new Uint8Array(n));
    return toHex(b);
  }

  async function getSalt(deps) {
    const got = await deps.store.get(['salt']);
    if (typeof got.salt === 'string' && /^[0-9a-f]{32}$/.test(got.salt)) return got.salt;
    const salt = randomHex(deps, 16);
    await deps.store.set({ salt: salt });
    return salt;
  }

  async function hibpCount(prefix, suffix, deps) {
    try {
      const res = await deps.fetch(HIBP_URL + prefix, {
        headers: { 'Add-Padding': 'true' }, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
        signal: timeoutSignal(HIBP_TIMEOUT_MS)
      });
      if (!res || !res.ok) return null;
      return parseRange(await res.text(), suffix);
    } catch (e) {
      return null; // ag hatasinda sessiz kal
    }
  }

  function freshEntry(e, now) { return !!e && typeof e.t === 'number' && now >= e.t && now - e.t < HIBP_TTL; }

  // Suresi gecenleri atar, en yeni HIBP_CACHE_MAX kaydi tutar.
  function pruneCache(old, now) {
    const keys = Object.keys(old || {}).filter(function (k) { return freshEntry(old[k], now); });
    keys.sort(function (a, b) { return old[b].t - old[a].t; });
    const out = {};
    keys.slice(0, HIBP_CACHE_MAX).forEach(function (k) { out[k] = old[k]; });
    return out;
  }

  // msg: {site, password}. Sifre yalnizca burada, iz ve SHA-1 icin kullanilir; hicbir yere yazilmaz.
  // deps.serial: depo oku-degistir-yaz adimlarini siraya koyar. Ozet ve HIBP sorgusu sira disinda calisir.
  async function handlePwSubmit(msg, deps) {
    const empty = { reuse: [], leaked: 0 };
    const run = deps.serial || direct;
    const site = etld1(msg && msg.site);
    let password = msg && typeof msg.password === 'string' ? msg.password : '';
    if (!site || !password) return empty;
    const salt = await run(function () { return getSalt(deps); });
    const fp = await fingerprint(password, salt);
    const sha = await sha1Hex(password);
    password = null;
    const prefix = sha.slice(0, 5), suffix = sha.slice(5);

    const cached = ((await deps.store.get(['hibpCache'])).hibpCache || {})[fp];
    let fresh = null;
    if (!freshEntry(cached, deps.now())) fresh = await hibpCount(prefix, suffix, deps);

    return run(async function () {
      const now = deps.now();
      const st = await deps.store.get(['pwIndex', 'hibpCache', 'noReuseWarn']);
      const rec = recordUse(st.pwIndex || {}, fp, site);
      const all = st.hibpCache || {};
      if (fresh !== null) all[fp] = { n: fresh, t: now };
      const cache = pruneCache(all, now);
      const leaked = cache[fp] ? cache[fp].n : 0;
      await deps.store.set({ pwIndex: rec.index, hibpCache: cache });
      const muted = (st.noReuseWarn || {})[site];
      return { reuse: muted ? [] : rec.otherSites, leaked: leaked };
    });
  }

  async function handleReuseMute(msg, deps) {
    const site = etld1(msg && msg.site);
    if (!site) return { ok: false };
    const st = await deps.store.get(['noReuseWarn']);
    const m = st.noReuseWarn || {};
    m[site] = true;
    await deps.store.set({ noReuseWarn: m });
    return { ok: true };
  }

  function findMfaSite(sites, hostname) {
    const d = etld1(hostname);
    if (!d || !Array.isArray(sites)) return null;
    for (let i = 0; i < sites.length; i++) {
      if (sites[i] && Array.isArray(sites[i].domains) && sites[i].domains.indexOf(d) >= 0) return sites[i];
    }
    return null;
  }

  // Liste sitesinde ilk giriste kart; cevapsiz kalan kart "Sonra" gibi 7 gun sonra yeniden sorulur.
  async function handleMfaCheck(msg, deps) {
    const s = findMfaSite(deps.sites, msg && msg.site);
    if (!s) return { show: false };
    const now = deps.now();
    const st = await deps.store.get(['mfa']);
    const mfa = st.mfa || {};
    if (mfaState(mfa[s.id], now) !== 'ask') return { show: false };
    mfa[s.id] = { status: 'later', until: now + SHOWN_MS, auto: true };
    await deps.store.set({ mfa: mfa });
    return { show: true, id: s.id, name: s.name, url: s.url };
  }

  async function handleMfaAnswer(msg, deps) {
    const s = findMfaSite(deps.sites, msg && msg.site);
    const answer = msg && msg.answer;
    if (!s || ['ok', 'later', 'never'].indexOf(answer) < 0) return { ok: false };
    const now = deps.now();
    const st = await deps.store.get(['mfa']);
    const mfa = st.mfa || {};
    if (answer === 'ok') mfa[s.id] = { status: 'ok', at: now };
    else if (answer === 'later') mfa[s.id] = { status: 'later', until: now + LATER_MS };
    else mfa[s.id] = { status: 'never', at: now };
    await deps.store.set({ mfa: mfa });
    return { ok: true };
  }

  // Acilir pencere durumu: 'ok' (acik), 'later' (ertelendi), 'unknown' (bilinmiyor)
  function mfaLabel(entry, now) {
    if (entry && entry.status === 'ok') return 'ok';
    if (entry && entry.status === 'later' && !entry.auto && entry.until > now) return 'later';
    return 'unknown';
  }

  // Dosya adi: yon/denetim karakterleri atilir (uzanti sahteciligi), 60 karakterle sinirlanir; uzanti gorunur kalir.
  function baseName(path) {
    const p = String(path || '').split(/[\\/]/);
    let f = (p[p.length - 1] || String(path || ''))
      .replace(/[\u0000-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩]/g, '');
    if (f.length > 60) f = f.slice(0, 40) + '…' + f.slice(-19);
    return f;
  }

  function reasonText(res, max) {
    const r = Array.isArray(res.reasons) ? res.reasons : [];
    return r.slice(0, max).map(function (x) { return String(x).slice(0, 200); }).join('\n');
  }

  // Kopru cevabindan bildirim metni; ERROR ya da bozuk cevapta null.
  function downloadNotice(path, res) {
    if (!res || typeof res !== 'object') return null;
    const f = baseName(path);
    if (res.level === 'OK') {
      return { level: 'OK', title: '✓ ' + f + ' temiz görünüyor', message: 'Cortmed Security bu dosyada bir sorun bulmadı.' };
    }
    if (res.level === 'RED') {
      return { level: 'RED', title: '⚠ ' + f + ' tehlikeli olabilir', message: reasonText(res, 2) || 'Bu dosyayı açmayın.' };
    }
    if (res.level === 'YELLOW') {
      return { level: 'YELLOW', title: f + ' şüpheli görünüyor', message: reasonText(res, 3) || 'Açmadan önce emin olun.' };
    }
    return null;
  }

  // Kopru cevabinin sonucu: yalnizca baglanti hatasi (lastError) "kurulu degil" demektir.
  // ERROR ya da bos cevap gorunur hicbir sey degistirmez.
  function downloadOutcome(lastError, res, path) {
    if (lastError) return { hostMissing: true, notice: null };
    if (!res || typeof res !== 'object' || res.level === 'ERROR') return { notice: null };
    return { hostMissing: false, notice: downloadNotice(path, res) };
  }

  // --- Service worker mesaj yonlendiricisi (saf) ---
  // Site her zaman sender.url'den alinir (yalnizca ust cerceve, http/https); mesajdaki site yok sayilir.
  function senderHost(sender) {
    try {
      if (!sender || sender.frameId !== 0 || typeof sender.url !== 'string') return null;
      const u = new URL(sender.url);
      return (u.protocol === 'https:' || u.protocol === 'http:') && u.hostname ? u.hostname : null;
    } catch (e) { return null; }
  }

  // Site basina 10 dakikada en fazla 5 pwSubmit (oturum deposunda).
  async function rateAllow(deps, site) {
    const now = deps.now();
    const st = await deps.session.get(['pwRate']);
    const all = st.pwRate || {};
    const out = {};
    Object.keys(all).forEach(function (k) {
      const kept = (all[k] || []).filter(function (t) { return now >= t && now - t < RATE_WINDOW; });
      if (kept.length) out[k] = kept;
    });
    const list = out[site] || [];
    const ok = list.length < RATE_MAX;
    if (ok) { list.push(now); out[site] = list; }
    await deps.session.set({ pwRate: out });
    return ok;
  }

  // deps: {selfId, store, session, fetch, now, serial, loadSites, openTab}
  // Donus: null (islenmedi, cevap yok) ya da cevabi veren Promise.
  function routeMessage(msg, sender, deps) {
    if (!sender || sender.id !== deps.selfId || !msg || typeof msg.type !== 'string') return null;
    const host = senderHost(sender);
    if (!host) return null;
    const site = etld1(host);
    const tabId = sender.tab && typeof sender.tab.id === 'number' ? sender.tab.id : -1;
    const run = deps.serial || direct;
    const empty = { reuse: [], leaked: 0 };

    function pendingUpdate(fn) {
      return run(async function () {
        const st = await deps.session.get(['pending']);
        const p = st.pending || {};
        const r = fn(p);
        await deps.session.set({ pending: p });
        return r;
      });
    }

    switch (msg.type) {
      case 'pwSubmit': {
        let password = typeof msg.password === 'string' ? msg.password : '';
        msg.password = null;
        if (!password) return Promise.resolve(empty);
        return (async function () {
          const allowed = await run(function () { return rateAllow(deps, site); });
          if (!allowed) { password = null; return empty; }
          const job = handlePwSubmit({ site: host, password: password }, deps);
          password = null;
          const r = await job;
          if (r.leaked > 0 || r.reuse.length) {
            await pendingUpdate(function (p) { p[tabId] = { site: site, result: r, t: deps.now() }; });
          }
          return r;
        })();
      }
      case 'cardsShown':
        return pendingUpdate(function (p) { delete p[tabId]; }).then(function () { return undefined; });
      case 'pendingCards':
        return pendingUpdate(function (p) {
          const e = p[tabId];
          delete p[tabId];
          return e && e.site === site && deps.now() - e.t < PENDING_MS ? e.result : null;
        });
      case 'reuseMute':
        return run(function () { return handleReuseMute({ site: host }, deps); });
      case 'mfaCheck':
        return Promise.resolve(deps.loadSites()).then(function (sites) {
          return run(function () { return handleMfaCheck({ site: host }, Object.assign({}, deps, { sites: sites })); });
        });
      case 'mfaAnswer':
        return Promise.resolve(deps.loadSites()).then(function (sites) {
          return run(function () { return handleMfaAnswer({ site: host, answer: msg.answer }, Object.assign({}, deps, { sites: sites })); });
        });
      case 'mfaOpen':
        // Adres sayfadan alinmaz; paketteki listeden bulunur.
        return Promise.resolve(deps.loadSites()).then(function (sites) {
          const s = findMfaSite(sites, host);
          if (s && /^https:\/\//.test(s.url)) { deps.openTab(s.url); return { ok: true }; }
          return { ok: false };
        });
      default:
        return null;
    }
  }

  root.CortmedLib = {
    etld1: etld1, fingerprint: fingerprint, sha1Hex: sha1Hex, recordUse: recordUse,
    mfaState: mfaState, isScannable: isScannable, parseRange: parseRange,
    handlePwSubmit: handlePwSubmit, handleReuseMute: handleReuseMute, findMfaSite: findMfaSite,
    handleMfaCheck: handleMfaCheck, handleMfaAnswer: handleMfaAnswer, mfaLabel: mfaLabel,
    downloadNotice: downloadNotice, downloadOutcome: downloadOutcome,
    senderHost: senderHost, routeMessage: routeMessage
  };
})(self);
