// Cortmed service worker: sifre izi, sizinti sorgusu, MFA durumu, indirme kontrolu.
importScripts('lib/core.js');

(function () {
  'use strict';
  const L = self.CortmedLib;
  const HOST = 'com.cortmed.security';
  const PENDING_MS = 60000;

  const store = {
    get: function (keys) { return chrome.storage.local.get(keys); },
    set: function (obj) { return chrome.storage.local.set(obj); }
  };

  let sitesPromise = null;
  function mfaSites() {
    if (!sitesPromise) {
      sitesPromise = fetch(chrome.runtime.getURL('mfa-sites.json'))
        .then(function (r) { return r.json(); })
        .catch(function () { sitesPromise = null; return []; });
    }
    return sitesPromise;
  }

  function deps(extra) {
    return Object.assign({
      store: store,
      fetch: function (url, init) { return fetch(url, init); },
      now: function () { return Date.now(); }
    }, extra || {});
  }

  // Depoya yazan isler sirayla calisir (ayni anda iki gonderim kaydi ezmesin).
  let queue = Promise.resolve();
  function serial(fn) {
    const p = queue.then(fn, fn);
    queue = p.catch(function () {});
    return p;
  }

  // Site, mesajdaki degil gonderen sekmenin adresinden alinir (yalnizca ust cerceve, http/https).
  function senderHost(sender) {
    try {
      if (!sender || sender.frameId !== 0 || !sender.url) return null;
      const u = new URL(sender.url);
      return (u.protocol === 'https:' || u.protocol === 'http:') ? u.hostname : null;
    } catch (e) { return null; }
  }

  // Gonderimden hemen sonra sayfa degistiyse kart bir sonraki sayfada gosterilir (bellekte, 60 sn).
  const pending = new Map();

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (!sender || sender.id !== chrome.runtime.id || !msg || typeof msg.type !== 'string') return false;
    const host = senderHost(sender);
    const tabId = sender.tab ? sender.tab.id : -1;
    let work = null;

    switch (msg.type) {
      case 'pwSubmit': {
        let password = typeof msg.password === 'string' ? msg.password : '';
        msg.password = null;
        if (!host || !password) { sendResponse({ reuse: [], leaked: 0 }); return false; }
        work = serial(function () {
          const p = L.handlePwSubmit({ site: host, password: password }, deps());
          password = null;
          return p;
        }).then(function (r) {
          if (r && (r.leaked > 0 || r.reuse.length)) pending.set(tabId, { site: L.etld1(host), result: r, t: Date.now() });
          return r;
        }, function () { return { reuse: [], leaked: 0 }; });
        break;
      }
      case 'cardsShown':
        pending.delete(tabId);
        return false;
      case 'pendingCards': {
        const p = pending.get(tabId);
        pending.delete(tabId);
        const ok = p && host && p.site === L.etld1(host) && Date.now() - p.t < PENDING_MS;
        sendResponse(ok ? p.result : null);
        return false;
      }
      case 'reuseMute':
        if (!host) return false;
        work = serial(function () { return L.handleReuseMute({ site: host }, deps()); });
        break;
      case 'mfaCheck':
        if (!host) { sendResponse({ show: false }); return false; }
        work = mfaSites().then(function (sites) {
          return serial(function () { return L.handleMfaCheck({ site: host }, deps({ sites: sites })); });
        });
        break;
      case 'mfaAnswer':
        if (!host) return false;
        work = mfaSites().then(function (sites) {
          return serial(function () { return L.handleMfaAnswer({ site: host, answer: msg.answer }, deps({ sites: sites })); });
        });
        break;
      case 'mfaOpen':
        // Adres sayfadan alinmaz; paketteki listeden bulunur.
        if (!host) return false;
        work = mfaSites().then(function (sites) {
          const s = L.findMfaSite(sites, host);
          if (s && /^https:\/\//.test(s.url)) chrome.tabs.create({ url: s.url });
          return { ok: !!s };
        });
        break;
      default:
        return false;
    }

    work.then(function (r) { try { sendResponse(r); } catch (e) {} },
      function () { try { sendResponse(null); } catch (e) {} });
    return true;
  });

  chrome.tabs.onRemoved.addListener(function (tabId) { pending.delete(tabId); });

  // ---------- Indirme kontrolu ----------
  function notify(n) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/128.png'),
      title: n.title,
      message: n.message,
      priority: n.level === 'RED' ? 2 : 0,
      requireInteraction: n.level === 'RED'
    }, function () { void chrome.runtime.lastError; });
  }

  chrome.downloads.onChanged.addListener(function (delta) {
    if (!delta || !delta.state || delta.state.current !== 'complete') return;
    chrome.downloads.search({ id: delta.id }, function (items) {
      if (chrome.runtime.lastError) return;
      const item = items && items[0];
      if (!item || !item.filename || !L.isScannable(item.filename)) return;
      const path = item.filename;
      chrome.runtime.sendNativeMessage(HOST, { path: path }, function (res) {
        const err = chrome.runtime.lastError;
        if (err || !res || res.level === 'ERROR') {
          chrome.storage.local.set({ hostMissing: true });
          return;
        }
        chrome.storage.local.set({ hostMissing: false, hostSeen: Date.now() });
        const n = L.downloadNotice(path, res);
        if (n) notify(n);
      });
    });
  });
})();
