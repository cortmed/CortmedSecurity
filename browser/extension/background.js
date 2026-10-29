// Cortmed service worker: sifre izi, sizinti sorgusu, MFA durumu, indirme kontrolu.
importScripts('lib/core.js');

(function () {
  'use strict';
  const L = self.CortmedLib;
  const HOST = 'com.cortmed.security';

  function area(a) {
    return {
      get: function (keys) { return a.get(keys); },
      set: function (obj) { return a.set(obj); }
    };
  }

  let sitesPromise = null;
  function loadSites() {
    if (!sitesPromise) {
      sitesPromise = fetch(chrome.runtime.getURL('mfa-sites.json'))
        .then(function (r) { return r.json(); })
        .catch(function () { sitesPromise = null; return []; });
    }
    return sitesPromise;
  }

  // Depo oku-degistir-yaz adimlari sirayla calisir; ozet ve HIBP sorgusu bu sirayi tutmaz.
  let queue = Promise.resolve();
  function serial(fn) {
    const p = queue.then(fn, fn);
    queue = p.catch(function () {});
    return p;
  }

  const deps = {
    selfId: chrome.runtime.id,
    store: area(chrome.storage.local),
    session: area(chrome.storage.session),
    fetch: function (url, init) { return fetch(url, init); },
    now: function () { return Date.now(); },
    serial: serial,
    loadSites: loadSites,
    openTab: function (url) { chrome.tabs.create({ url: url }); }
  };

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    let work = null;
    try { work = L.routeMessage(msg, sender, deps); } catch (e) { work = null; }
    if (!work) return false;
    work.then(function (r) { try { sendResponse(r); } catch (e) {} },
      function () { try { sendResponse(null); } catch (e) {} });
    return true;
  });

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
        const out = L.downloadOutcome(chrome.runtime.lastError, res, path);
        if (out.hostMissing === true) chrome.storage.local.set({ hostMissing: true });
        else if (out.hostMissing === false) chrome.storage.local.set({ hostMissing: false, hostSeen: Date.now() });
        if (out.notice) notify(out.notice);
      });
    });
  });
})();
