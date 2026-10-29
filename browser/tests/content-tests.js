// content.js testleri: login-fixture.html uzerinde, sahte chrome.runtime ile.
// window.__cortmedTestTrust: sentetik olaylari "kullanicidan" sayan test kapisi (yalnizca 127.0.0.1).
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
  // Kullanici yazmis gibi: deger + input olayi (test kapisi acikken guvenilir sayilir)
  function type(el, v) { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }
  function $(id) { return document.getElementById(id); }
  let seq = 0;
  function fresh() { return 'Gizli-Parola-' + (++seq); }

  try {
    const pw = $('pw');
    const pw2 = $('pw2');
    const loginBtn = $('loginBtn');
    await tick(); await tick();

    // Sayfa yuklenince MFA sorulur, kart bir kez cizilir
    const mfaMsgs = window.__sent.filter(function (m) { return m.type === 'mfaCheck'; });
    assertEq('mfaCheck sent once', mfaMsgs.length, 1);
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
      assertEq('mfa how sends open', window.__sent.filter(function (m) { return m.type === 'mfaOpen'; }).length, 1);
      mfa[0].querySelector('[data-act="ok"]').click();
      const ans = window.__sent.filter(function (m) { return m.type === 'mfaAnswer'; });
      assertEq('mfa ok answer', ans.length === 1 && ans[0].answer === 'ok', true);
      assertEq('mfa card closed', cards('mfa').length, 0);
    }

    // ===== Saldiri senaryolari: test kapisi KAPALI (gercek sayfa betigi gibi) =====
    window.__cortmedTestTrust = false;
    pw.value = 'Tahmin-1';
    loginBtn.click();
    assertEq('NEG script value + click', pwCount(), 0);
    pw.value = 'Tahmin-2';
    enter(pw);
    assertEq('NEG script value + Enter', pwCount(), 0);
    pw2.value = 'Tahmin-3';
    pw2.form.requestSubmit();
    assertEq('NEG script value + requestSubmit', pwCount(), 0);
    type(pw, 'Tahmin-4'); loginBtn.click(); enter(pw);
    assertEq('NEG untrusted input event + click/Enter', pwCount(), 0);
    window.__cortmedTestTrust = true;

    // Kapi acik ama deger betikle yazilmis (guvenilir input yok): gonderilmez
    pw.value = 'Tahmin-5';
    loginBtn.click(); enter(pw);
    assertEq('NEG value without trusted input', pwCount(), 0);
    // Kullanici yazdi, sonra betik degistirdi: gonderilmez
    type(pw, 'Kullanici-1'); pw.value = 'Tahmin-6';
    loginBtn.click();
    assertEq('NEG value changed by script after typing', pwCount(), 0);

    // ===== Gecerli girisler =====
    // 1) Yalnizca JS ile giris: dugme tiklamasi tek pwSubmit
    const v1 = fresh();
    type(pw, v1);
    loginBtn.click();
    assertEq('js click one', pwCount(), 1);
    const m1 = window.__sent.filter(function (m) { return m.type === 'pwSubmit'; })[0] || {};
    assertEq('pwSubmit payload', m1.password, v1);
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
    type(pw, fresh());
    enter(pw);
    assertEq('enter one', pwCount(), 2);

    // 3) Tiklama + Enter 2 sn icinde: tek
    type(pw, fresh());
    loginBtn.click(); enter(pw); loginBtn.click();
    assertEq('click+enter one', pwCount(), 3);

    // 4) Bos sifre: hic
    type(pw, '');
    loginBtn.click(); enter(pw);
    assertEq('empty zero', pwCount(), 3);

    // 5) Dugme sezgisi: goster/gizle ve ilgisiz dugmeler reddedilir
    type(pw, fresh());
    $('eyeBtn').click();
    assertEq('REJ eye (göster) button', pwCount(), 3);
    $('pressBtn').click();
    assertEq('REJ aria-pressed', pwCount(), 3);
    $('ctrlBtn').click();
    assertEq('REJ aria-controls=password id', pwCount(), 3);
    $('helpBtn').click();
    assertEq('REJ unrelated text', pwCount(), 3);
    $('otherBtn').click();
    assertEq('REJ button far from password', pwCount(), 3);
    type(pw2, 'Form-Ara-1');
    $('searchBtn').click();
    assertEq('REJ type=button in form, no login text', pwCount(), 3);

    // Kabul edilen dugmeler
    $('signBtn').click();
    assertEq('ACC "Sign in"', pwCount(), 4);
    type(pw, fresh());
    $('roleBtn').click();
    assertEq('ACC role=button "Oturum aç"', pwCount(), 5);
    type(pw, fresh());
    $('upBtn').click();
    assertEq('ACC aria-label "GİRİŞ"', pwCount(), 6);
    type(pw, fresh());
    $('girdiBtn').click();
    assertEq('REJ "girdileri" (gir only as whole word)', pwCount(), 6);
    $('nextBtn').click();
    assertEq('ACC "İleri"', pwCount(), 7);
    type(pw, fresh());
    $('sonrakiBtn').click();
    assertEq('ACC "Sonraki"', pwCount(), 8);
    type(pw, fresh());
    $('girBtn').click();
    assertEq('ACC "Gir"', pwCount(), 9);

    // Yalnizca input olayi kaydeder: change ve paste kaydetmez
    pw.value = 'Degisim-1';
    pw.dispatchEvent(new Event('change', { bubbles: true }));
    loginBtn.click();
    assertEq('NEG change event does not record', pwCount(), 9);
    pw.value = 'Yapistir-1';
    pw.dispatchEvent(new Event('paste', { bubbles: true }));
    await tick();
    loginBtn.click();
    assertEq('NEG paste event does not record', pwCount(), 9);

    // 6) Klasik form: gercek gonder dugmesi (metni "Tamam") tiklama + submit tek
    type(pw2, 'Form-Parola-1');
    $('formBtn').click();
    assertEq('form submit button click+submit one', pwCount(), 10);
    type(pw2, 'Form-Parola-2');
    enter(pw2);
    pw2.form.requestSubmit();
    assertEq('form enter+submit one', pwCount(), 11);
    const last = window.__sent.filter(function (m) { return m.type === 'pwSubmit'; }).pop() || {};
    assertEq('form value sent', last.password, 'Form-Parola-2');

    // 7) Ayni deger 2 sn sonra yeniden: ikinci gonderim
    window.__fakeNow = Date.now();
    type(pw, fresh());
    loginBtn.click();
    window.__fakeNow += 2500;
    loginBtn.click();
    assertEq('same value after 2s counts', pwCount(), 13);
    window.__fakeNow = null;
    await tick(); await tick();

    // Her turden tek kart: yeni sonuc eskisinin yerini alir, kirmizi ustte
    assertEq('one card per kind', [cards('leak').length, cards('reuse').length], [1, 1]);
    assertEq('red stays on top', cards().map(function (c) { return c.getAttribute('data-kind'); }), ['leak', 'reuse']);

    // 8) "Bu site icin bir daha gosterme"
    const reuseCard = cards('reuse')[0];
    if (reuseCard) reuseCard.querySelector('[data-act="mute"]').click();
    const mute = window.__sent.filter(function (m) { return m.type === 'reuseMute'; });
    assertEq('mute sent', mute.length, 1);
    assertEq('mute never carries password', JSON.stringify(mute).indexOf('Parola'), -1);
    assertEq('card clicks never send pwSubmit', pwCount(), 13);
    const leakCard = cards('leak')[0];
    if (leakCard) leakCard.querySelector('[data-act="close"]').click();
    assertEq('tamam closes', cards('leak').length, 0);
    assertEq('still one shadow host', window.__shadows.length, 1);

    // Uzun liste metni
    window.__replies.pwSubmit = { reuse: ['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com', 'g.com'], leaked: 0 };
    type(pw, fresh()); loginBtn.click();
    await tick(); await tick();
    const rc = cards('reuse')[0];
    assertEq('reuse long list', !!rc && rc.textContent.indexOf('başka 7 sitede de kullanıyorsunuz: a.com, b.com, c.com, d.com, e.com ve 2 site daha. Bir site') >= 0, true);

    // Banka sifresi (6 rakam) ve SMS kodu alani: hic gonderilmez
    const before = pwCount();
    type($('pin'), '123456');
    $('pinBtn').click(); enter($('pin')); $('pinForm').requestSubmit();
    assertEq('6-digit PIN sends nothing', pwCount(), before);
    type($('pin'), '12345678');
    $('pinBtn').click();
    assertEq('8-digit PIN sends nothing', pwCount(), before);
    type($('otp'), 'Kod-Abc-91');
    $('otpBtn').click(); enter($('otp'));
    assertEq('one-time-code field sends nothing', pwCount(), before);
    type($('pin'), '123456789');
    $('pinBtn').click();
    assertEq('9 digits still checked', pwCount(), before + 1);

    // Sayfa dunyasindan kapi yalnizca 127.0.0.1'de anlam tasir (ayni betik, kosul kodda)
    assertEq('fixture served from 127.0.0.1', location.hostname, '127.0.0.1');
    assertEq('content.js loaded before body existed', window.__bodyAtStart, false);
  } catch (e) {
    fails.push('exception: ' + e.message);
  }
  out.textContent = fails.length ? 'FAIL: ' + fails.join('; ') : 'PASS ' + n;
})();
