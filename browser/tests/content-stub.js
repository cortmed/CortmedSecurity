// content.js icin sahte chrome API ve gozlem kancalari (yalnizca test sayfasinda).
(function () {
  'use strict';
  // Test kapisi: sentetik olaylari "kullanicidan" sayar. Yalnizca bu sayfanin dunyasinda ve 127.0.0.1'de etkili.
  window.__cortmedTestTrust = true;
  window.__sent = [];
  window.__replies = {
    mfaCheck: { show: true, id: 'discord', name: 'Discord', url: 'https://support.discord.com/x' },
    pwSubmit: { reuse: ['a.com', 'b.com'], leaked: 1234567 }
  };
  const stub = {
    runtime: {
      lastError: undefined,
      sendMessage: function (msg, cb) {
        window.__sent.push(JSON.parse(JSON.stringify(msg)));
        const reply = window.__replies[msg && msg.type];
        if (typeof cb === 'function') window.__origSetTimeout(function () { cb(reply); }, 0);
      }
    }
  };
  Object.defineProperty(window, 'chrome', { value: stub, configurable: true, writable: true });

  // Kapali shadow root'u testte gorebilmek icin attachShadow kaydedilir.
  window.__shadows = [];
  const origAttach = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (opts) {
    const root = origAttach.call(this, opts);
    window.__shadows.push({ host: this, mode: opts && opts.mode, root: root });
    return root;
  };

  // Zamanlayicilar kaydedilir (30 sn kapanma testi icin).
  window.__timers = [];
  window.__origSetTimeout = window.setTimeout.bind(window);
  window.setTimeout = function (fn, ms) {
    const id = window.__origSetTimeout.apply(window, arguments);
    window.__timers.push({ fn: fn, ms: ms, id: id });
    return id;
  };

  // Date.now kontrol edilebilir (2 sn tekrar penceresi icin).
  window.__fakeNow = null;
  const origNow = Date.now;
  Date.now = function () { return window.__fakeNow === null ? origNow() : window.__fakeNow; };
})();
