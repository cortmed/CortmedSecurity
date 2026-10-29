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

  // Ayni hesabin birden cok alan adi tek site sayilir. Kaynak: mfa-sites.json'daki her domains dizisi + bu tablo.
  // Her grubun ilk alan adi kanonik addir; buradaki ilk adlar listedekiyle aynidir (liste yuklenemese de ayni kayit).
  const EXTRA_ALIASES = [
    ['steampowered.com', 'steamcommunity.com'],
    ['garantibbva.com.tr', 'garanti.com.tr'],
    ['microsoft.com', 'live.com', 'microsoftonline.com', 'outlook.com'],
    ['google.com', 'youtube.com']
  ];

  function aliasMap(sites) {
    const map = {};
    const groups = [];
    (Array.isArray(sites) ? sites : []).forEach(function (s) { if (s && Array.isArray(s.domains)) groups.push(s.domains); });
    EXTRA_ALIASES.forEach(function (g) { groups.push(g); });
    groups.forEach(function (g) {
      const ds = g.map(function (d) { return String(d || '').toLowerCase(); }).filter(Boolean);
      if (!ds.length) return;
      let canon = null;
      ds.forEach(function (d) { if (!canon && map[d]) canon = map[d]; });
      if (!canon) canon = ds[0];
      // Gruplar kesisirse birlesir
      const old = ds.map(function (d) { return map[d]; }).filter(function (c) { return c && c !== canon; });
      Object.keys(map).forEach(function (k) { if (old.indexOf(map[k]) >= 0) map[k] = canon; });
      ds.forEach(function (d) { map[d] = canon; });
    });
    return map;
  }

  // site: eTLD+1. Donus: grubun kanonik adi ya da sitenin kendisi.
  function canonicalSite(site, sites) {
    const s = etld1(site);
    return aliasMap(sites)[s] || s;
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
  const FP_CAP = 30;            // 24 saatte en fazla 30 farkli iz (tum siteler)
  const FP_WINDOW = DAY;

  // Kayan 24 saatlik pencerede farkli iz sayisi; yeniden yuklemelerde kalsin diye local depoda, zaman damgasiyla.
  async function fpAllow(deps, fp) {
    const now = deps.now();
    const st = await deps.store.get(['fpSeen']);
    const old = st.fpSeen || {};
    const seen = {};
    Object.keys(old).forEach(function (k) {
      if (typeof old[k] === 'number' && now >= old[k] && now - old[k] < FP_WINDOW) seen[k] = old[k];
    });
    const known = Object.prototype.hasOwnProperty.call(seen, fp);
    const ok = known || Object.keys(seen).length < FP_CAP;
    if (ok && !known) seen[fp] = now;
    await deps.store.set({ fpSeen: seen });
    return ok;
  }

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

  // Banka sifresi ve SMS kodu: yalnizca rakam, en fazla 8 hane. Hic kontrol edilmez (HIBP'de hemen hepsi var).
  const DIGITS_RX = /^\d{1,8}$/;
  function skipSecret(password) { return DIGITS_RX.test(password); }

  // msg: {site, password}. Sifre yalnizca burada, iz ve SHA-1 icin kullanilir; hicbir yere yazilmaz.
  // deps.serial: depo oku-degistir-yaz adimlarini siraya koyar. Ozet ve HIBP sorgusu sira disinda calisir.
  async function handlePwSubmit(msg, deps) {
    const empty = { reuse: [], leaked: 0 };
    const run = deps.serial || direct;
    const site = canonicalSite(msg && msg.site, deps.sites);
    let password = msg && typeof msg.password === 'string' ? msg.password : '';
    if (!site || !password || skipSecret(password)) return empty;
    const salt = await run(function () { return getSalt(deps); });
    const fp = await fingerprint(password, salt);
    const sha = await sha1Hex(password);
    password = null;
    const prefix = sha.slice(0, 5), suffix = sha.slice(5);
    if (!(await run(function () { return fpAllow(deps, fp); }))) return empty;

    const cached = ((await deps.store.get(['hibpCache'])).hibpCache || {})[fp];
    const known = freshEntry(cached, deps.now()) ? cached.n : null;

    // Ayni-sifre sonucu once yazilir ve bildirilir (deps.onEarly); HIBP sonra sorulur.
    const early = await run(async function () {
      const st = await deps.store.get(['pwIndex', 'noReuseWarn']);
      const rec = recordUse(st.pwIndex || {}, fp, site);
      await deps.store.set({ pwIndex: rec.index });
      const muted = (st.noReuseWarn || {})[site];
      return { reuse: muted ? [] : rec.otherSites, leaked: known || 0 };
    });
    if (deps.onEarly) await deps.onEarly(early);

    let fresh = null;
    if (known === null) fresh = await hibpCount(prefix, suffix, deps);

    return run(async function () {
      const now = deps.now();
      const st = await deps.store.get(['hibpCache']);
      const all = st.hibpCache || {};
      if (fresh !== null) all[fp] = { n: fresh, t: now };
      const cache = pruneCache(all, now);
      const leaked = cache[fp] ? cache[fp].n : 0;
      await deps.store.set({ hibpCache: cache });
      return { reuse: early.reuse, leaked: leaked };
    });
  }

  async function handleReuseMute(msg, deps) {
    const site = canonicalSite(msg && msg.site, deps.sites);
    if (!site) return { ok: false };
    const st = await deps.store.get(['noReuseWarn']);
    const m = st.noReuseWarn || {};
    m[site] = true;
    await deps.store.set({ noReuseWarn: m });
    return { ok: true };
  }

  // hosts varsa (genis alan adlari: Google, Microsoft, Apple) yalnizca o hesap adresleri eslesir; yoksa domains (eTLD+1).
  function findMfaSite(sites, hostname) {
    const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
    const d = etld1(h);
    if (!d || !Array.isArray(sites)) return null;
    for (let i = 0; i < sites.length; i++) {
      const s = sites[i];
      if (!s) continue;
      if (Array.isArray(s.hosts)) { if (s.hosts.indexOf(h) >= 0) return s; continue; }
      if (Array.isArray(s.domains) && s.domains.indexOf(d) >= 0) return s;
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

  // Yon/denetim karakterleri atilir (uzanti sahteciligi); uzunsa ortadan kirpilir, son 19 karakter (uzanti) gorunur kalir.
  function cleanText(text, max) {
    let f = String(text || '').replace(/[\u0000-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩]/g, '');
    if (f.length > max) f = f.slice(0, max - 20) + '…' + f.slice(-19);
    return f;
  }

  // Dosya adi: en fazla 60 karakter.
  function baseName(path) {
    const p = String(path || '').split(/[\\/]/);
    return cleanText(p[p.length - 1] || String(path || ''), 60);
  }

  function reasonText(res, max) {
    const r = Array.isArray(res.reasons) ? res.reasons : [];
    return r.slice(0, max).map(function (x) { return String(x).slice(0, 200); }).join('\n');
  }

  // Kirmizi ve sari bildirimin sonu: kopru komut almadigi icin dugme yok, panele yonlendirilir.
  const PANEL_NOTE = 'Ayrıntılar için Cortmed panelini açın.';

  // Kopru cevabindan bildirim metni; ERROR ya da bozuk cevapta null.
  function downloadNotice(path, res) {
    if (!res || typeof res !== 'object') return null;
    const f = baseName(path);
    if (res.level === 'OK') {
      return { level: 'OK', title: '✓ ' + f + ' temiz görünüyor', message: 'Cortmed Security bu dosyada bir sorun bulmadı.' };
    }
    if (res.level === 'RED') {
      return { level: 'RED', title: '⚠ ' + f + ' tehlikeli olabilir', message: (reasonText(res, 2) || 'Bu dosyayı açmayın.') + '\n' + PANEL_NOTE };
    }
    if (res.level === 'YELLOW') {
      // Taramanin kendi basligi derecelidir ("Tanınmayan program: ..."); imzasiz her dosyaya "şüpheli" denmez.
      const t = typeof res.title === 'string' ? cleanText(res.title, 80).trim() : '';
      return { level: 'YELLOW', title: t || f + ' şüpheli görünüyor', message: (reasonText(res, 3) || 'Açmadan önce emin olun.') + '\n' + PANEL_NOTE };
    }
    return null;
  }

  // Kopru cevabinin sonucu: baglanti hatasi (lastError) "kurulu degil", herhangi bir cevap (ERROR dahil) "kurulu" demektir.
  // ERROR ya da bos cevapta bildirim yok.
  function downloadOutcome(lastError, res, path) {
    if (lastError) return { hostMissing: true, notice: null };
    if (!res || typeof res !== 'object') return { notice: null };
    if (res.level === 'ERROR') return { hostMissing: false, notice: null };
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

  const PENDING_WAIT_MS = 6000;
  let jobSeq = 0;
  function noop() {}
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  // deps: {selfId, store, session, fetch, now, serial, loadSites, openTab, inflight (Map sekme -> suren kontrol), sleep}
  // Donus: null (islenmedi, cevap yok) ya da cevabi veren Promise.
  function routeMessage(msg, sender, deps) {
    if (!sender || sender.id !== deps.selfId || !msg || typeof msg.type !== 'string') return null;
    const host = senderHost(sender);
    if (!host) return null;
    const site = etld1(host);
    // Bekleyen kart eslesmesi icin hesap grubu (ek tablo; es zamanli): garanti.com.tr -> garantibbva.com.tr ayni site
    const cardSite = canonicalSite(site);
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

    function hasCards(r) { return !!r && (r.leaked > 0 || r.reuse.length > 0); }

    switch (msg.type) {
      case 'pwSubmit': {
        let password = typeof msg.password === 'string' ? msg.password : '';
        msg.password = null;
        if (!password || skipSecret(password)) { password = null; return Promise.resolve(empty); }
        const id = ++jobSeq;
        let early = null;
        const work = (async function () {
          const allowed = await run(function () { return rateAllow(deps, site); });
          if (!allowed) { password = null; return empty; }
          let sites = [];
          try { sites = deps.loadSites ? await deps.loadSites() : []; } catch (e) { sites = []; }
          // Sayfa gonderimle kapanirsa yeni sayfa sonucu bekleyen karttan alir: ayni-sifre sonucu hemen yazilir.
          const job = handlePwSubmit({ site: host, password: password }, Object.assign({}, deps, {
            sites: sites,
            onEarly: function (e) {
              early = e;
              if (!hasCards(e)) return undefined;
              return pendingUpdate(function (p) { p[tabId] = { id: id, site: cardSite, result: e, t: deps.now() }; });
            }
          }));
          password = null;
          const r = await job;
          await pendingUpdate(function (p) {
            const cur = p[tabId];
            if (cur && cur.id === id) {
              if (hasCards(r)) { cur.result = r; cur.t = deps.now(); } else delete p[tabId];
            } else if (!cur) {
              // Erken kart alindiysa yalnizca sonradan gelen sizinti eklenir.
              if (!hasCards(early)) { if (hasCards(r)) p[tabId] = { id: id, site: cardSite, result: r, t: deps.now() }; }
              else if (r.leaked > 0 && !(early.leaked > 0)) p[tabId] = { id: id, site: cardSite, result: { reuse: [], leaked: r.leaked }, t: deps.now() };
            }
          });
          return r;
        })();
        const inflight = deps.inflight;
        if (inflight) {
          inflight.set(tabId, work);
          const done = function () { if (inflight.get(tabId) === work) inflight.delete(tabId); };
          work.then(done, done);
        }
        return work;
      }
      case 'cardsShown':
        return pendingUpdate(function (p) { delete p[tabId]; }).then(function () { return undefined; });
      case 'pendingCards': {
        // Suren kontrol varsa en fazla 6 sn beklenir.
        const busy = deps.inflight && deps.inflight.get(tabId);
        const ready = busy ? Promise.race([busy.then(noop, noop), (deps.sleep || sleep)(PENDING_WAIT_MS)]) : Promise.resolve();
        return ready.then(function () {
          return pendingUpdate(function (p) {
            const e = p[tabId];
            delete p[tabId];
            if (!e || !(deps.now() - e.t < PENDING_MS)) return null;
            if (e.site === cardSite) return e.result;
            // Giristen sonra ayni sekmede baska siteye yonlenildi: kart ilk siteyi adlandirir.
            return Object.assign({}, e.result, { from: e.site });
          });
        });
      }
      case 'reuseMute':
        return Promise.resolve(deps.loadSites ? deps.loadSites() : []).then(function (sites) {
          return run(function () { return handleReuseMute({ site: host }, Object.assign({}, deps, { sites: sites })); });
        });
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
    senderHost: senderHost, routeMessage: routeMessage, skipSecret: skipSecret, canonicalSite: canonicalSite
  };
})(self);
