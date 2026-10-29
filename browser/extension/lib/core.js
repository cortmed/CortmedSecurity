// Cortmed cekirdek mantik: sayfa, service worker ve content script'te ayni dosya.
(function (root) {
  'use strict';

  const TWO_PART = ['co.uk', 'com.tr', 'gov.tr', 'edu.tr', 'org.tr', 'net.tr', 'k12.tr', 'com.au', 'co.jp'];
  const SCAN_EXT = ['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'scr', 'com', 'dll', 'lnk',
    'zip', 'rar', '7z', 'iso', 'img', 'apk', 'docm', 'xlsm'];

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

  root.CortmedLib = {
    etld1: etld1, fingerprint: fingerprint, sha1Hex: sha1Hex, recordUse: recordUse,
    mfaState: mfaState, isScannable: isScannable, parseRange: parseRange
  };
})(self);
