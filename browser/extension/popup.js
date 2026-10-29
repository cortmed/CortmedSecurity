// Acilir pencere: indirme kontrolu durumu ve "Hesaplarim" listesi.
(function () {
  'use strict';
  const L = self.CortmedLib;
  const LABELS = { ok: '✓ açık', later: '⏱ ertelendi', unknown: '? bilinmiyor' };

  function render(sites, st) {
    const status = document.getElementById('status');
    if (st.hostMissing === true) {
      status.textContent = 'Bu özellik için Cortmed Security kurulu olmalı';
      status.className = 'status missing';
    } else if (st.hostMissing !== false) {
      status.textContent = 'İndirme kontrolü ilk indirmede denenecek';
      status.className = 'status neutral';
    } else {
      status.textContent = 'İndirme kontrolü açık ✓';
      status.className = 'status';
    }
    const list = document.getElementById('sites');
    list.textContent = '';
    const mfa = st.mfa || {};
    const now = Date.now();
    sites.forEach(function (s) {
      const kind = L.mfaLabel(mfa[s.id], now);
      const li = document.createElement('li');
      const name = document.createElement('span');
      name.textContent = s.name;
      const state = document.createElement('span');
      state.className = 'st ' + kind;
      state.textContent = LABELS[kind];
      li.appendChild(name);
      li.appendChild(state);
      list.appendChild(li);
    });
  }

  Promise.all([
    fetch('mfa-sites.json').then(function (r) { return r.json(); }).catch(function () { return []; }),
    chrome.storage.local.get(['mfa', 'hostMissing'])
  ]).then(function (v) { render(v[0], v[1] || {}); });
})();
