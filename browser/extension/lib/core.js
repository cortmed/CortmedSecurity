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
  const SHOWN_MS = 1 * DAY; // gosterilip cevaplanmayan kart 1 gun sonra yeniden sorulur
  const HIBP_URL = 'https://api.pwnedpasswords.com/range/';

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
      const res = await deps.fetch(HIBP_URL + prefix, { headers: { 'Add-Padding': 'true' }, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
      if (!res || !res.ok) return null;
      return parseRange(await res.text(), suffix);
    } catch (e) {
      return null; // ag hatasinda sessiz kal
    }
  }

  // msg: {site, password}. Sifre yalnizca burada, iz ve SHA-1 icin kullanilir; hicbir yere yazilmaz.
  async function handlePwSubmit(msg, deps) {
    const empty = { reuse: [], leaked: 0 };
    const site = etld1(msg && msg.site);
    const password = msg && typeof msg.password === 'string' ? msg.password : '';
    if (!site || !password) return empty;
    const now = deps.now();
    const salt = await getSalt(deps);
    const fp = await fingerprint(password, salt);
    const sha = await sha1Hex(password);
    const prefix = sha.slice(0, 5), suffix = sha.slice(5);

    const st = await deps.store.get(['pwIndex', 'hibpCache', 'noReuseWarn']);
    const rec = recordUse(st.pwIndex || {}, fp, site);

    const cache = {};
    const old = st.hibpCache || {};
    Object.keys(old).forEach(function (k) {
      if (old[k] && now - old[k].t < HIBP_TTL && now >= old[k].t) cache[k] = old[k];
    });
    let leaked = 0;
    if (cache[fp]) {
      leaked = cache[fp].n;
    } else {
      const n = await hibpCount(prefix, suffix, deps);
      if (n !== null) { leaked = n; cache[fp] = { n: n, t: now }; }
    }
    await deps.store.set({ pwIndex: rec.index, hibpCache: cache });
    const muted = (st.noReuseWarn || {})[site];
    return { reuse: muted ? [] : rec.otherSites, leaked: leaked };
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

  // Liste sitesinde ilk giriste kart; gosterildiginde 1 gun sessiz kalir (cevap gelmezse yeniden sorar).
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

  function baseName(path) {
    const p = String(path || '').split(/[\\/]/);
    return p[p.length - 1] || String(path || '');
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

  root.CortmedLib = {
    etld1: etld1, fingerprint: fingerprint, sha1Hex: sha1Hex, recordUse: recordUse,
    mfaState: mfaState, isScannable: isScannable, parseRange: parseRange,
    handlePwSubmit: handlePwSubmit, handleReuseMute: handleReuseMute, findMfaSite: findMfaSite,
    handleMfaCheck: handleMfaCheck, handleMfaAnswer: handleMfaAnswer, mfaLabel: mfaLabel,
    downloadNotice: downloadNotice
  };
})(self);
