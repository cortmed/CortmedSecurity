// content.js testleri: login-fixture.html uzerinde, sahte chrome.runtime ile.
(async function () {
  const out = document.getElementById('result');
  const fails = [];
  let n = 0;
  function assertEq(name, got, want) {
    n++;
    if (JSON.stringify(got) !== JSON.stringify(want)) fails.push(name + ' (got ' + JSON.stringify(got) + ')');
  }
  function tick() { return new Promise(function (r) { window.__origSetTimeout(r, 5); }); }
  function pwCount() { return window.__sent.filter(function (m) { return m.type === 'pwSubmit'; }).length; }
  function shadowRoot() { return window.__shadows.length ? window.__shadows[0].root : null; }
  function cards(kind) {
    const r = shadowRoot();
    return r ? Array.prototype.slice.call(r.querySelectorAll('[data-kind' + (kind ? '="' + kind + '"' : '') + ']')) : [];
  }
  function enter(el) { el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })); }

  try {
    const pw = document.getElementById('pw');
    const pw2 = document.getElementById('pw2');
    const loginBtn = document.getElementById('loginBtn');
    await tick(); await tick();

    // Sayfa yuklenince MFA sorulur, kart bir kez cizilir
    const mfaMsgs = window.__sent.filter(function (m) { return m.type === 'mfaCheck'; });
    assertEq('mfaCheck sent once', mfaMsgs.length, 1);
    assertEq('mfaCheck site', mfaMsgs[0] && mfaMsgs[0].site, location.hostname);
    assertEq('one shadow host', window.__shadows.length, 1);
    const sh = window.__shadows[0] || {};
    assertEq('shadow closed', sh.mode, 'closed');
    assertEq('host on documentElement', !!sh.host && sh.host.parentNode === document.documentElement, true);
    if (sh.host) {
      const cs = getComputedStyle(sh.host);
      assertEq('host fixed max z', [cs.position, cs.zIndex], ['fixed', '2147483647']);
    }
    const mfa = cards('mfa');
    assertEq('mfa card shown', mfa.length, 1);
    const mfaText = mfa[0] ? mfa[0].textContent : '';
    assertEq('mfa text', mfaText.indexOf('Discord hesabınızda iki adımlı doğrulama açık mı? Açıksa şifreniz çalınsa bile hesabınıza girilemez.') >= 0, true);
    assertEq('mfa bold name', !!(mfa[0] && mfa[0].querySelector('b') && mfa[0].querySelector('b').textContent === 'Discord'), true);
    const mfaBtns = mfa[0] ? Array.prototype.map.call(mfa[0].querySelectorAll('button'), function (b) { return b.textContent; }) : [];
    assertEq('mfa buttons', mfaBtns, ['Nasıl açılır?', 'Açık', 'Sonra']);
    if (mfa[0]) {
      mfa[0].querySelector('[data-act="how"]').click();
      const open = window.__sent.filter(function (m) { return m.type === 'mfaOpen'; });
      assertEq('mfa how sends open', open.length === 1 && open[0].id === 'discord', true);
      mfa[0].querySelector('[data-act="ok"]').click();
      const ans = window.__sent.filter(function (m) { return m.type === 'mfaAnswer'; });
      assertEq('mfa ok answer', ans.length === 1 && ans[0].answer === 'ok' && ans[0].site === location.hostname, true);
      assertEq('mfa card closed', cards('mfa').length, 0);
    }

    // 1) Yalnizca JS ile giris: dugme tiklamasi tek pwSubmit
    pw.value = 'Gizli-Parola-1';
    loginBtn.click();
    assertEq('js click one', pwCount(), 1);
    const m1 = window.__sent.filter(function (m) { return m.type === 'pwSubmit'; })[0] || {};
    assertEq('pwSubmit payload', [m1.site, m1.password], [location.hostname, 'Gizli-Parola-1']);
    await tick(); await tick();

    // Kartlar: once kirmizi, sonra sari; metinlerde sifre yok
    const all = cards();
    assertEq('cards order red then yellow', all.map(function (c) { return c.getAttribute('data-kind'); }), ['leak', 'reuse']);
    const leakText = all[0] ? all[0].textContent : '';
    const reuseText = all[1] ? all[1].textContent : '';
    assertEq('leak text', leakText.indexOf('Bu şifre daha önce internete sızmış (1.234.567 kez görülmüş). Hemen değiştirin.') >= 0, true);
    assertEq('reuse text', reuseText.indexOf('Bu şifreyi başka 2 sitede de kullanıyorsunuz: a.com, b.com. Bir site sızarsa hepsi tehlikeye girer. Bu site için farklı bir şifre seçin.') >= 0, true);
    const reuseBtns = all[1] ? Array.prototype.map.call(all[1].querySelectorAll('button'), function (b) { return b.textContent; }) : [];
    assertEq('reuse buttons', reuseBtns, ['Tamam', 'Bu site için bir daha gösterme']);
    const rootText = shadowRoot() ? shadowRoot().textContent : '';
    assertEq('no password in cards', rootText.indexOf('Gizli-Parola'), -1);
    assertEq('no password in host attrs', document.documentElement.outerHTML.indexOf('Gizli-Parola'), -1);

    // 30 sn sonra kendiliginden kapanir
    const t30 = window.__timers.filter(function (t) { return t.ms === 30000; });
    assertEq('auto close 30s timers', t30.length >= 2, true);
    t30.forEach(function (t) { try { t.fn(); } catch (e) { } });
    assertEq('auto close removes cards', cards().length, 0);

    // 2) Enter tek pwSubmit
    pw.value = 'Gizli-Parola-2';
    enter(pw);
    assertEq('enter one', pwCount(), 2);

    // 3) Tiklama + Enter 2 sn icinde: tek
    pw.value = 'Gizli-Parola-3';
    loginBtn.click();
    enter(pw);
    loginBtn.click();
    assertEq('click+enter one', pwCount(), 3);

    // 4) Bos sifre: hic
    pw.value = '';
    loginBtn.click();
    enter(pw);
    assertEq('empty zero', pwCount(), 3);

    // 5) Sifre alani olmayan bolumdeki dugme: hic
    pw.value = 'Gizli-Parola-4';
    document.getElementById('otherBtn').click();
    assertEq('unrelated button zero', pwCount(), 3);

    // 6) Klasik form: tiklama + submit tek
    pw2.value = 'Form-Parola-1';
    document.getElementById('formBtn').click();
    assertEq('form click+submit one', pwCount(), 4);
    pw2.value = 'Form-Parola-2';
    enter(pw2);
    pw2.form.requestSubmit();
    assertEq('form enter+submit one', pwCount(), 5);
    const last = window.__sent.filter(function (m) { return m.type === 'pwSubmit'; }).pop() || {};
    assertEq('form value sent', last.password, 'Form-Parola-2');

    // 7) Ayni deger 2 sn sonra yeniden: ikinci gonderim
    window.__fakeNow = Date.now();
    pw.value = 'Gizli-Parola-5';
    loginBtn.click();
    window.__fakeNow += 2500;
    loginBtn.click();
    assertEq('same value after 2s counts', pwCount(), 7);
    window.__fakeNow = null;
    await tick(); await tick();

    // Her turden tek kart: yeni sonuc eskisinin yerini alir, kirmizi ustte
    assertEq('one card per kind', [cards('leak').length, cards('reuse').length], [1, 1]);
    assertEq('red stays on top', cards().map(function (c) { return c.getAttribute('data-kind'); }), ['leak', 'reuse']);

    // 8) "Bu site icin bir daha gosterme"
    const reuseCard = cards('reuse')[0];
    if (reuseCard) reuseCard.querySelector('[data-act="mute"]').click();
    const mute = window.__sent.filter(function (m) { return m.type === 'reuseMute'; });
    assertEq('mute sent', mute.length === 1 && mute[0].site === location.hostname, true);
    assertEq('mute never carries password', JSON.stringify(mute).indexOf('Parola'), -1);
    const leakCard = cards('leak')[0];
    if (leakCard) leakCard.querySelector('[data-act="close"]').click();
    assertEq('tamam closes', cards('leak').length, 0);
    assertEq('still one shadow host', window.__shadows.length, 1);
  } catch (e) {
    fails.push('exception: ' + e.message);
  }
  out.textContent = fails.length ? 'FAIL: ' + fails.join('; ') : 'PASS ' + n;
})();
