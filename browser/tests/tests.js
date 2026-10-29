// Cekirdek mantik testleri; sonuc #result icine yazilir.
(async function () {
  const out = document.getElementById('result');
  // Headless sanal zaman, bekleyen fetch varken ilerlemez; WebCrypto bitene kadar /hold ile bekletilir.
  let finished = false;
  if (location.protocol === 'http:') {
    (async function () { while (!finished) { try { await fetch('/hold'); } catch (e) { break; } } })();
  }
  const fails = [];
  let n = 0;
  function assertEq(name, got, want) {
    n++;
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      fails.push(name + ' (got ' + JSON.stringify(got) + ')');
    }
  }
  try {
    const L = self.CortmedLib;
    if (!L) throw new Error('CortmedLib yok');

    assertEq('etld1 google', L.etld1('accounts.google.com'), 'google.com');
    assertEq('etld1 garanti', L.etld1('www.garanti.com.tr'), 'garanti.com.tr');
    assertEq('etld1 co.uk', L.etld1('a.b.co.uk'), 'b.co.uk');
    assertEq('etld1 localhost', L.etld1('localhost'), 'localhost');
    assertEq('etld1 ip', L.etld1('192.168.1.1'), '192.168.1.1');

    const salt = '00112233445566778899aabbccddeeff';
    const f1 = await L.fingerprint('hunter2', salt);
    assertEq('fp same', await L.fingerprint('hunter2', salt), f1);
    assertEq('fp salt differs', f1 === await L.fingerprint('hunter2', 'ffeeddccbbaa99887766554433221100'), false);
    assertEq('fp hex32', /^[0-9a-f]{32}$/.test(f1), true);
    assertEq('fp long', /^[0-9a-f]{32}$/.test(await L.fingerprint('x'.repeat(500), salt)), true);
    assertEq('fp emoji', /^[0-9a-f]{32}$/.test(await L.fingerprint('\u{1F512}\u{1F511}pw', salt)), true);

    let r = L.recordUse({}, 'fpA', 'discord.com');
    assertEq('use first', r.otherSites, []);
    r = L.recordUse(r.index, 'fpA', 'steampowered.com');
    assertEq('use reuse', r.otherSites, ['discord.com']);
    r = L.recordUse(r.index, 'fpA', 'discord.com');
    assertEq('use again', r.otherSites, ['steampowered.com']);
    assertEq('use no dup', r.index.fpA.filter(s => s === 'discord.com').length, 1);
    r = L.recordUse(r.index, 'fpB', 'discord.com');
    assertEq('use moved', r.index.fpA, ['steampowered.com']);
    assertEq('use moved new', r.index.fpB, ['discord.com']);
    assertEq('use moved others', r.otherSites, []);

    const now = 1000000;
    assertEq('mfa undef', L.mfaState(undefined, now), 'ask');
    assertEq('mfa ok', L.mfaState({ status: 'ok' }, now), 'ok');
    assertEq('mfa snoozed', L.mfaState({ status: 'later', until: now + 1 }, now), 'snoozed');
    assertEq('mfa expired', L.mfaState({ status: 'later', until: now - 1 }, now), 'ask');
    assertEq('mfa never', L.mfaState({ status: 'never' }, now), 'never');

    assertEq('scan exe', L.isScannable('a.EXE'), true);
    assertEq('scan pdf', L.isScannable('b.pdf'), false);
    assertEq('scan tar.gz', L.isScannable('c.tar.gz'), false);
    assertEq('scan 7z', L.isScannable('d.7z'), true);

    const sfx = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';
    assertEq('range hit', L.parseRange('ABC:3\r\n' + sfx + ':42\r\n', sfx), 42);
    assertEq('range miss', L.parseRange('ABC:3\r\n', sfx), 0);

    for (const ext of ['dll', 'com', 'docm']) assertEq('scan ' + ext, L.isScannable('x.' + ext), false);
    for (const ext of ['msi', 'scr', 'bat', 'cmd', 'ps1', 'js', 'vbs', 'jar', 'zip', 'rar', 'iso', 'img']) {
      assertEq('scan ' + ext, L.isScannable('x.' + ext), true);
    }

    // Bilinen cevap: PowerShell Rfc2898DeriveBytes ile bagimsiz hesaplandi
    assertEq('fp known answer', await L.fingerprint('Cortmed-Test-1', salt), '3242b8cc3de4f67d744c0e192cbb8efe');
    for (const bad of ['', 'zz', '00112233445566778899aabbccddeef', salt + '00']) {
      let threw = false;
      try { await L.fingerprint('x', bad); } catch (e) { threw = true; }
      assertEq('fp bad salt ' + bad.length, threw, true);
    }

    assertEq('mfa until==now', L.mfaState({ status: 'later', until: now }, now), 'ask');
    assertEq('range lower suffix', L.parseRange('ABC:3\r\n' + sfx + ':42\r\n', sfx.toLowerCase()), 42);
    assertEq('range LF only', L.parseRange('ABC:3\n' + sfx + ':7\n', sfx), 7);
    assertEq('range padding 0', L.parseRange(sfx + ':0\r\nABC:3\r\n', sfx), 0);
    assertEq('etld1 upper', L.etld1('WWW.Google.COM'), 'google.com');
    assertEq('etld1 trailing dot', L.etld1('accounts.google.com.'), 'google.com');
    assertEq('etld1 empty', L.etld1(''), '');
    assertEq('etld1 bare co.uk', L.etld1('co.uk'), 'co.uk');
    const e1 = L.recordUse({ fpOld: ['a.com'], fpKeep: ['b.com'] }, 'fpNew', 'a.com');
    assertEq('use emptied removed', Object.keys(e1.index).sort(), ['fpKeep', 'fpNew']);

    assertEq('sha1', await L.sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');

    await backgroundLogic(L, assertEq);
    await extensionFiles(L, assertEq);
  } catch (e) {
    fails.push('exception: ' + e.message);
  }
  finished = true;
  out.textContent = fails.length ? 'FAIL: ' + fails.join('; ') : 'PASS ' + n;
})();

// --- Arka plan mantigi: sahte depo ve sahte fetch ile (gercek ag yok) ---
function fakeStore(init) {
  const data = JSON.parse(JSON.stringify(init || {}));
  return {
    data: data,
    writes: 0,
    get: async function (keys) {
      const o = {};
      (Array.isArray(keys) ? keys : [keys]).forEach(function (k) {
        if (Object.prototype.hasOwnProperty.call(data, k)) o[k] = JSON.parse(JSON.stringify(data[k]));
      });
      return o;
    },
    set: async function (obj) { this.writes++; Object.assign(data, JSON.parse(JSON.stringify(obj))); }
  };
}

function fakeFetch(body, opts) {
  const f = async function (url, init) {
    f.calls.push({ url: url, headers: (init && init.headers) || {} });
    if (opts && opts.fail) throw new TypeError('Failed to fetch');
    const status = (opts && opts.status) || 200;
    return { ok: status >= 200 && status < 300, status: status, text: async function () { return body; } };
  };
  f.calls = [];
  return f;
}

async function backgroundLogic(L, assertEq) {
  const DAY = 24 * 3600 * 1000;
  const T = 1700000000000;
  const PWSFX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8'; // "password" SHA-1 son 35 karakter
  const miss = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\r\n';

  assertEq('bg handlers exist', [typeof L.handlePwSubmit, typeof L.handleMfaCheck, typeof L.handleMfaAnswer,
    typeof L.handleReuseMute, typeof L.findMfaSite, typeof L.mfaLabel, typeof L.downloadNotice],
    ['function', 'function', 'function', 'function', 'function', 'function', 'function']);

  // Aynı şifre: ikinci site birinciyi döndürür; tuz ilk kullanımda üretilir; şifre depoya yazılmaz
  let st = fakeStore();
  let ff = fakeFetch(miss);
  const deps = { store: st, fetch: ff, now: function () { return T; } };
  let r = await L.handlePwSubmit({ site: 'discord.com', password: 'Kedi-Parola-77' }, deps);
  assertEq('pw first', r, { reuse: [], leaked: 0 });
  assertEq('pw salt made', /^[0-9a-f]{32}$/.test(st.data.salt || ''), true);
  const salt1 = st.data.salt;
  r = await L.handlePwSubmit({ site: 'store.steampowered.com', password: 'Kedi-Parola-77' }, deps);
  assertEq('pw reuse second site', r.reuse, ['discord.com']);
  assertEq('pw salt kept', st.data.salt, salt1);
  assertEq('pw never stored', JSON.stringify(st.data).indexOf('Kedi-Parola-77'), -1);
  assertEq('pw cache one fetch', ff.calls.length, 1);
  const sha = await L.sha1Hex('Kedi-Parola-77');
  assertEq('pw hibp url', ff.calls[0].url, 'https://api.pwnedpasswords.com/range/' + sha.slice(0, 5));
  assertEq('pw hibp padding', ff.calls[0].headers['Add-Padding'], 'true');
  assertEq('pw full hash not sent', ff.calls[0].url.indexOf(sha.slice(5)), -1);

  // Sızmış şifre: aralıkta bulunan sayı döner
  st = fakeStore(); ff = fakeFetch('ABCDEF0123456789ABCDEF0123456789ABC:2\r\n' + PWSFX + ':9545824\r\n');
  r = await L.handlePwSubmit({ site: 'example.com', password: 'password' }, { store: st, fetch: ff, now: function () { return T; } });
  assertEq('pw leaked count', r.leaked, 9545824);
  assertEq('pw leaked prefix', ff.calls[0].url, 'https://api.pwnedpasswords.com/range/5BAA6');
  // Önbellek 30 gün: ikinci gönderimde fetch yok, 31 gün sonra yeniden sorulur
  r = await L.handlePwSubmit({ site: 'example.com', password: 'password' }, { store: st, fetch: ff, now: function () { return T + 29 * DAY; } });
  assertEq('pw cache hit leaked', r.leaked, 9545824);
  assertEq('pw cache hit no fetch', ff.calls.length, 1);
  r = await L.handlePwSubmit({ site: 'example.com', password: 'password' }, { store: st, fetch: ff, now: function () { return T + 31 * DAY; } });
  assertEq('pw cache expired fetch', ff.calls.length, 2);

  // Ağ hatası: sessiz, leaked 0, önbelleğe yazılmaz
  st = fakeStore(); ff = fakeFetch('', { fail: true });
  r = await L.handlePwSubmit({ site: 'example.com', password: 'password' }, { store: st, fetch: ff, now: function () { return T; } });
  assertEq('pw net error leaked 0', r.leaked, 0);
  ff = fakeFetch(PWSFX + ':12\r\n');
  r = await L.handlePwSubmit({ site: 'example.com', password: 'password' }, { store: st, fetch: ff, now: function () { return T; } });
  assertEq('pw net error not cached', [ff.calls.length, r.leaked], [1, 12]);
  st = fakeStore(); ff = fakeFetch('oops', { status: 503 });
  r = await L.handlePwSubmit({ site: 'example.com', password: 'password' }, { store: st, fetch: ff, now: function () { return T; } });
  assertEq('pw http error leaked 0', r.leaked, 0);

  // Boş şifre: hiçbir şey yapılmaz
  st = fakeStore(); ff = fakeFetch(miss);
  r = await L.handlePwSubmit({ site: 'example.com', password: '' }, { store: st, fetch: ff, now: function () { return T; } });
  assertEq('pw empty', [r, ff.calls.length, st.writes], [{ reuse: [], leaked: 0 }, 0, 0]);

  // Banka şifresi / SMS kodu (yalnızca rakam, 8 haneye kadar): hiç kontrol edilmez, hiçbir şey yazılmaz
  st = fakeStore({ pwIndex: { fpBank: ['ziraatbank.com.tr'] } }); ff = fakeFetch('');
  for (const pin of ['123456', '0', '12345678']) {
    r = await L.handlePwSubmit({ site: 'ziraatbank.com.tr', password: pin }, { store: st, fetch: ff, now: function () { return T; } });
    assertEq('pw digits ' + pin.length + ' skipped', [r, ff.calls.length, st.writes], [{ reuse: [], leaked: 0 }, 0, 0]);
  }
  assertEq('pw digits index untouched', st.data.pwIndex, { fpBank: ['ziraatbank.com.tr'] });
  r = await L.handlePwSubmit({ site: 'ziraatbank.com.tr', password: '123456789' }, { store: st, fetch: ff, now: function () { return T; } });
  assertEq('pw 9 digits checked', ff.calls.length, 1);
  r = await L.handlePwSubmit({ site: 'ziraatbank.com.tr', password: '12345a' }, { store: fakeStore(), fetch: ff, now: function () { return T; } });
  assertEq('pw digits+letter checked', ff.calls.length, 2);

  // "Bu site için bir daha gösterme"
  st = fakeStore(); ff = fakeFetch(miss);
  const d2 = { store: st, fetch: ff, now: function () { return T; } };
  await L.handlePwSubmit({ site: 'a.com', password: 'Ortak-Sifre-1' }, d2);
  await L.handleReuseMute({ site: 'www.b.com' }, d2);
  r = await L.handlePwSubmit({ site: 'b.com', password: 'Ortak-Sifre-1' }, d2);
  assertEq('pw muted site', r.reuse, []);
  r = await L.handlePwSubmit({ site: 'c.com', password: 'Ortak-Sifre-1' }, d2);
  assertEq('pw other site still warns', r.reuse.slice().sort(), ['a.com', 'b.com']);

  // Ayni hesabin alan adlari tek site sayilir (MFA listesindeki domains + ek tablo)
  const aliasSites = [
    { id: 'steam', name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'], url: 'https://help.steampowered.com/x' },
    { id: 'apple', name: 'Apple', domains: ['apple.com', 'icloud.com'], hosts: ['appleid.apple.com'], url: 'https://support.apple.com/x' }
  ];
  st = fakeStore(); ff = fakeFetch(miss);
  const da = { store: st, fetch: ff, now: function () { return T; }, sites: aliasSites };
  await L.handlePwSubmit({ site: 'store.steampowered.com', password: 'Oyun-Sifre-1' }, da);
  r = await L.handlePwSubmit({ site: 'steamcommunity.com', password: 'Oyun-Sifre-1' }, da);
  assertEq('alias steam two domains no warning', r.reuse, []);
  r = await L.handlePwSubmit({ site: 'discord.com', password: 'Oyun-Sifre-1' }, da);
  assertEq('alias other site still warns, canonical name', r.reuse, ['steampowered.com']);
  await L.handlePwSubmit({ site: 'www.icloud.com', password: 'Elma-1' }, da);
  assertEq('alias from mfa domains (apple/icloud)', (await L.handlePwSubmit({ site: 'apple.com', password: 'Elma-1' }, da)).reuse, []);
  // Ek tablo listesiz de calisir
  st = fakeStore(); ff = fakeFetch(miss);
  const dx = { store: st, fetch: ff, now: function () { return T; } };
  for (const pair of [['steamcommunity.com', 'steampowered.com'], ['garanti.com.tr', 'garantibbva.com.tr'],
    ['login.live.com', 'login.microsoftonline.com'], ['outlook.com', 'account.microsoft.com'], ['www.youtube.com', 'accounts.google.com']]) {
    const pw = 'Ek-' + pair[0];
    await L.handlePwSubmit({ site: pair[0], password: pw }, dx);
    assertEq('alias extra ' + pair.join('~'), (await L.handlePwSubmit({ site: pair[1], password: pw }, dx)).reuse, []);
  }
  assertEq('alias unrelated', L.canonicalSite('example.com', aliasSites), 'example.com');
  assertEq('alias canonical first domain', [L.canonicalSite('steamcommunity.com', aliasSites), L.canonicalSite('garanti.com.tr'), L.canonicalSite('youtube.com'), L.canonicalSite('outlook.com')],
    ['steampowered.com', 'garantibbva.com.tr', 'google.com', 'microsoft.com']);
  // "Bir daha gösterme" de grup icin
  st = fakeStore(); ff = fakeFetch(miss);
  const dm = { store: st, fetch: ff, now: function () { return T; }, sites: aliasSites };
  await L.handlePwSubmit({ site: 'discord.com', password: 'Sessiz-1' }, dm);
  await L.handleReuseMute({ site: 'steamcommunity.com' }, dm);
  assertEq('alias mute applies to group', (await L.handlePwSubmit({ site: 'store.steampowered.com', password: 'Sessiz-1' }, dm)).reuse, []);

  // Bozuk tuz yeniden üretilir
  st = fakeStore({ salt: 'bozuk' });
  await L.handlePwSubmit({ site: 'a.com', password: 'x1' }, { store: st, fetch: fakeFetch(miss), now: function () { return T; } });
  assertEq('pw bad salt replaced', /^[0-9a-f]{32}$/.test(st.data.salt), true);

  // MFA
  const sites = [
    { id: 'discord', name: 'Discord', domains: ['discord.com'], url: 'https://support.discord.com/x' },
    { id: 'google', name: 'Google', domains: ['google.com', 'google.com.tr'], url: 'https://support.google.com/y' }
  ];
  assertEq('mfa find sub', (L.findMfaSite(sites, 'canary.discord.com') || {}).id, 'discord');
  assertEq('mfa find tr', (L.findMfaSite(sites, 'www.google.com.tr') || {}).id, 'google');
  assertEq('mfa find none', L.findMfaSite(sites, 'notdiscord.com'), null);
  // hosts varsa domains yerine yalnizca o hesap adresleri eslesir
  const hsites = [{ id: 'g', name: 'G', domains: ['g.com'], hosts: ['accounts.g.com'], url: 'https://g.com/h' }];
  assertEq('mfa hosts override domain', [L.findMfaSite(hsites, 'www.g.com'), L.findMfaSite(hsites, 'g.com')], [null, null]);
  assertEq('mfa hosts exact host', (L.findMfaSite(hsites, 'accounts.g.com') || {}).id, 'g');
  assertEq('mfa hosts case/trailing dot', (L.findMfaSite(hsites, 'ACCOUNTS.G.COM.') || {}).id, 'g');
  assertEq('mfa hosts no sub-subdomain', L.findMfaSite(hsites, 'x.accounts.g.com'), null);

  let now = T;
  st = fakeStore();
  const md = { store: st, sites: sites, now: function () { return now; } };
  r = await L.handleMfaCheck({ site: 'discord.com' }, md);
  assertEq('mfa show first', r, { show: true, id: 'discord', name: 'Discord', url: 'https://support.discord.com/x' });
  r = await L.handleMfaCheck({ site: 'discord.com' }, md);
  assertEq('mfa show once', r.show, false);
  r = await L.handleMfaCheck({ site: 'example.com' }, md);
  assertEq('mfa unlisted', r.show, false);

  st = fakeStore(); now = T;
  const mo = { store: st, sites: sites, now: function () { return now; } };
  await L.handleMfaAnswer({ site: 'discord.com', answer: 'ok' }, mo);
  r = await L.handleMfaCheck({ site: 'discord.com' }, mo);
  assertEq('mfa ok no show', r.show, false);
  now = T + 400 * DAY;
  r = await L.handleMfaCheck({ site: 'discord.com' }, mo);
  assertEq('mfa ok forever', r.show, false);
  assertEq('mfa label ok', L.mfaLabel(st.data.mfa.discord, now), 'ok');

  st = fakeStore(); now = T;
  const ml = { store: st, sites: sites, now: function () { return now; } };
  await L.handleMfaCheck({ site: 'discord.com' }, ml);
  await L.handleMfaAnswer({ site: 'discord.com', answer: 'later' }, ml);
  assertEq('mfa label later', L.mfaLabel(st.data.mfa.discord, now), 'later');
  now = T + 6 * DAY;
  assertEq('mfa later 6d', (await L.handleMfaCheck({ site: 'discord.com' }, ml)).show, false);
  now = T + 7 * DAY + 1;
  assertEq('mfa later 7d shows', (await L.handleMfaCheck({ site: 'discord.com' }, ml)).show, true);
  assertEq('mfa later 7d once', (await L.handleMfaCheck({ site: 'discord.com' }, ml)).show, false);

  st = fakeStore(); now = T;
  const mn = { store: st, sites: sites, now: function () { return now; } };
  await L.handleMfaAnswer({ site: 'discord.com', answer: 'never' }, mn);
  now = T + 400 * DAY;
  assertEq('mfa never', (await L.handleMfaCheck({ site: 'discord.com' }, mn)).show, false);
  await L.handleMfaAnswer({ site: 'discord.com', answer: 'hack' }, mn);
  assertEq('mfa bad answer ignored', st.data.mfa.discord.status, 'never');
  await L.handleMfaAnswer({ site: 'example.com', answer: 'ok' }, mn);
  assertEq('mfa unlisted answer ignored', Object.keys(st.data.mfa), ['discord']);

  // Gösterilip cevaplanmayan site açılır pencerede "bilinmiyor" görünür
  st = fakeStore(); now = T;
  await L.handleMfaCheck({ site: 'discord.com' }, { store: st, sites: sites, now: function () { return now; } });
  assertEq('mfa label shown unanswered', L.mfaLabel(st.data.mfa.discord, now), 'unknown');
  // Cevapsiz kart "Sonra" gibi: 1 gun ve 6 gun sonra sessiz, 7 gun sonra yeniden
  const mu = { store: st, sites: sites, now: function () { return now; } };
  now = T + 1 * DAY + 1;
  assertEq('mfa unanswered quiet 1d', (await L.handleMfaCheck({ site: 'discord.com' }, mu)).show, false);
  now = T + 6 * DAY;
  assertEq('mfa unanswered quiet 6d', (await L.handleMfaCheck({ site: 'discord.com' }, mu)).show, false);
  now = T + 7 * DAY + 1;
  assertEq('mfa unanswered asks 7d', (await L.handleMfaCheck({ site: 'discord.com' }, mu)).show, true);
  now = T;
  assertEq('mfa label none', L.mfaLabel(undefined, now), 'unknown');
  assertEq('mfa label later expired', L.mfaLabel({ status: 'later', until: now - 1 }, now), 'unknown');

  // İndirme bildirimi metinleri
  const p = 'C:\\Users\\ali\\Downloads\\kurulum.exe';
  assertEq('dl ok', L.downloadNotice(p, { level: 'OK', title: 't', reasons: [] }).title, '✓ kurulum.exe temiz görünüyor');
  const red = L.downloadNotice(p, { level: 'RED', title: 't', reasons: ['bir', 'iki', 'üç'] });
  assertEq('dl red title', red.title, '⚠ kurulum.exe tehlikeli olabilir');
  assertEq('dl red reasons', [red.message.indexOf('bir') >= 0, red.message.indexOf('iki') >= 0, red.message.indexOf('üç') >= 0], [true, true, false]);
  assertEq('dl red level', red.level, 'RED');
  const yel = L.downloadNotice('/home/a/b.zip', { level: 'YELLOW', reasons: ['imzasız'] });
  assertEq('dl yellow fallback title', [yel.title, yel.message.indexOf('imzasız') >= 0], ['b.zip şüpheli görünüyor', true]);
  // Kirmizi ve sari bildirimin sonunda panel notu; temizde yok
  const MORE = 'Ayrıntılar için Cortmed panelini açın.';
  function endsMore(n) { return n.message.slice(-MORE.length) === MORE; }
  assertEq('dl red ends with panel note', endsMore(red), true);
  assertEq('dl red empty reasons panel note', L.downloadNotice(p, { level: 'RED', reasons: [] }).message, 'Bu dosyayı açmayın.\n' + MORE);
  assertEq('dl yellow ends with panel note', endsMore(yel), true);
  assertEq('dl ok no panel note', L.downloadNotice(p, { level: 'OK', reasons: [] }).message.indexOf(MORE), -1);
  // Sari: kopru basligi kullanilir (imzasiz program "şüpheli" denmez), temizlenir ve 80 karakterle sinirlanir
  const uns = L.downloadNotice(p, { level: 'YELLOW', title: 'Tanınmayan program: imzasiz.exe', reasons: ['İmzasız'] });
  assertEq('dl yellow uses host title', uns.title, 'Tanınmayan program: imzasiz.exe');
  assertEq('dl yellow title strips bidi', L.downloadNotice(p, { level: 'YELLOW', title: 'Tanınmayan program: fatura\u202Efdp.exe\u0007' }).title, 'Tanınmayan program: faturafdp.exe');
  const lyt = L.downloadNotice(p, { level: 'YELLOW', title: 'Tanınmayan program: ' + 'y'.repeat(150) + '.exe' }).title;
  assertEq('dl yellow title capped 80, end kept', [lyt.length, /\.exe$/.test(lyt), lyt.indexOf('…') > 0], [80, true, true]);
  assertEq('dl yellow blank title fallback', L.downloadNotice(p, { level: 'YELLOW', title: ' \u202E ' }).title, 'kurulum.exe şüpheli görünüyor');
  assertEq('dl yellow non-string title fallback', L.downloadNotice(p, { level: 'YELLOW', title: 5 }).title, 'kurulum.exe şüpheli görünüyor');
  assertEq('dl error', L.downloadNotice(p, { level: 'ERROR', reasons: [] }), null);
  assertEq('dl garbage', L.downloadNotice(p, null), null);
  assertEq('dl unknown level', L.downloadNotice(p, { level: 'PURPLE' }), null);

  // Dosya adi: yon/denetim karakterleri atilir, 60 karaktere kirpilir, uzanti gorunur
  const spoof = 'C:\\d\\fatura\u202Efdp.exe';
  assertEq('dl strips bidi', L.downloadNotice(spoof, { level: 'OK' }).title, '✓ faturafdp.exe temiz görünüyor');
  assertEq('dl strips controls', L.downloadNotice('a\u0007b\u200E\u2066c.zip', { level: 'OK' }).title, '✓ abc.zip temiz görünüyor');
  const longName = 'x'.repeat(100) + '.exe';
  const lt = L.downloadNotice(longName, { level: 'RED', reasons: [] }).title;
  const shownName = lt.slice(2, lt.indexOf(' tehlikeli'));
  assertEq('dl name capped 60', [shownName.length, /\.exe$/.test(shownName), shownName.indexOf('…') > 0], [60, true, true]);

  // Kopru sonucu: yalnizca lastError "kurulu degil" der; ERROR/bos cevap gorunur bir sey yapmaz
  assertEq('outcome lastError', L.downloadOutcome({ message: 'Specified native messaging host not found.' }, undefined, p), { hostMissing: true, notice: null });
  assertEq('outcome ERROR silent, host present', L.downloadOutcome(undefined, { level: 'ERROR', reasons: ['x'] }, p), { hostMissing: false, notice: null });
  // Nabiz: {path:''} kopruye gider; kopru lastseen yazar ve ERROR doner. Herhangi bir cevap "kurulu" demektir.
  assertEq('heartbeat ERROR reply clears hostMissing', L.downloadOutcome(undefined, { level: 'ERROR', title: 'Geçersiz yol', reasons: [] }, ''), { hostMissing: false, notice: null });
  assertEq('heartbeat lastError sets hostMissing', L.downloadOutcome({ message: 'Specified native messaging host not found.' }, undefined, ''), { hostMissing: true, notice: null });
  assertEq('outcome empty silent', L.downloadOutcome(undefined, undefined, p), { notice: null });
  assertEq('outcome non-object silent', L.downloadOutcome(undefined, 'OK', p), { notice: null });
  const okOut = L.downloadOutcome(undefined, { level: 'OK', reasons: [] }, p);
  assertEq('outcome ok', [okOut.hostMissing, okOut.notice && okOut.notice.title], [false, '✓ kurulum.exe temiz görünüyor']);

  // HIBP: zaman asimi sinyali, iptal hatasi sessiz, sorgu ve ozet depo sirasinin DISINDA
  st = fakeStore(); ff = fakeFetch(miss);
  let sig = null;
  const sigFetch = async function (url, init) { sig = init && init.signal; return { ok: true, text: async function () { return miss; } }; };
  await L.handlePwSubmit({ site: 'a.com', password: 'zaman-1' }, { store: st, fetch: sigFetch, now: function () { return T; } });
  assertEq('hibp has abort signal', typeof AbortSignal !== 'undefined' && sig instanceof AbortSignal && !sig.aborted, true);
  const abortFetch = async function () { throw new DOMException('The operation was aborted.', 'TimeoutError'); };
  r = await L.handlePwSubmit({ site: 'a.com', password: 'password' }, { store: fakeStore(), fetch: abortFetch, now: function () { return T; } });
  assertEq('hibp timeout silent', r.leaked, 0);

  let inside = false, fetchInside = null, serialCalls = 0;
  const probeSerial = async function (fn) {
    serialCalls++;
    inside = true;
    try { return await fn(); } finally { inside = false; }
  };
  const probeFetch = async function () { fetchInside = inside; return { ok: true, text: async function () { return miss; } }; };
  await L.handlePwSubmit({ site: 'a.com', password: 'sira-1' }, { store: fakeStore(), fetch: probeFetch, now: function () { return T; }, serial: probeSerial });
  assertEq('hibp fetch outside serial', [fetchInside, serialCalls >= 1], [false, true]);

  // hibpCache en fazla 300 kayit; en eskiler atilir
  const big = {};
  for (let i = 0; i < 300; i++) big['f' + i] = { n: 0, t: T - 1000 - i };
  st = fakeStore({ hibpCache: big });
  await L.handlePwSubmit({ site: 'a.com', password: 'yeni-kayit' }, { store: st, fetch: fakeFetch(miss), now: function () { return T; } });
  const ck = Object.keys(st.data.hibpCache);
  assertEq('cache capped 300', ck.length, 300);
  assertEq('cache evicts oldest', [ck.indexOf('f299') < 0, ck.indexOf('f0') >= 0], [true, true]);

  // Genel sinir: 24 saatte en fazla 30 farkli iz (tum siteler); fazlasi sessiz
  st = fakeStore(); ff = fakeFetch(miss);
  let capNow = T;
  const cd = { store: st, fetch: ff, now: function () { return capNow; } };
  for (let i = 0; i < 30; i++) {
    await L.handlePwSubmit({ site: 's' + i + '.com', password: 'Sinir-' + i }, cd);
  }
  assertEq('fp cap 30 fetched', ff.calls.length, 30);
  const capIdx = JSON.stringify(st.data.pwIndex);
  r = await L.handlePwSubmit({ site: 'yeni.com', password: 'Sinir-31' }, cd);
  assertEq('fp cap 31st silent', [r, ff.calls.length, JSON.stringify(st.data.pwIndex)], [{ reuse: [], leaked: 0 }, 30, capIdx]);
  r = await L.handlePwSubmit({ site: 'baska.com', password: 'Sinir-0' }, cd);
  assertEq('fp cap known fp still works', r.reuse, ['s0.com']);
  assertEq('fp cap stored locally', Object.keys(st.data.fpSeen || {}).length, 30);
  capNow = T + 24 * 3600 * 1000 + 1;
  r = await L.handlePwSubmit({ site: 'yeni.com', password: 'Sinir-31' }, cd);
  assertEq('fp cap window rolls', ff.calls.length, 31);
  assertEq('fp cap pruned', Object.keys(st.data.fpSeen).length, 1);

  await routerTests(L, assertEq, sites, miss, PWSFX);
}

// --- Service worker yonlendiricisi ---
async function routerTests(L, assertEq, sites, miss, PWSFX) {
  const T = 1700000000000;
  const SELF = 'ccjadpibhajekoedbdplbkaofgijbnei';
  let now = T;
  function mk(body) {
    const opened = [];
    const d = {
      selfId: SELF, store: fakeStore(), session: fakeStore(), fetch: fakeFetch(body || miss),
      now: function () { return now; }, loadSites: async function () { return sites; },
      openTab: function (u) { opened.push(u); }
    };
    d.opened = opened;
    return d;
  }
  function snd(url, extra) { return Object.assign({ id: SELF, url: url, frameId: 0, tab: { id: 7 } }, extra || {}); }

  // Site mesajdan degil sender.url'den alinir
  let d = mk();
  let r = await L.routeMessage({ type: 'pwSubmit', site: 'bank.com', password: 'Yonlendirici-1' }, snd('https://login.evil.com/x'), d);
  assertEq('route pw reply', r, { reuse: [], leaked: 0 });
  assertEq('route site from sender.url', JSON.stringify(d.store.data.pwIndex).indexOf('evil.com') >= 0 && JSON.stringify(d.store.data.pwIndex).indexOf('bank.com') < 0, true);

  // Alt cerceve, yabanci kimlik, http disi, eksik url: hicbir sey yapilmaz
  d = mk();
  assertEq('route frameId 3 ignored', L.routeMessage({ type: 'pwSubmit', password: 'x' }, snd('https://a.com/', { frameId: 3 }), d), null);
  assertEq('route foreign id ignored', L.routeMessage({ type: 'pwSubmit', password: 'x' }, snd('https://a.com/', { id: 'abcdefghijabcdefghijabcdefghijab' }), d), null);
  assertEq('route file: ignored', L.routeMessage({ type: 'mfaCheck' }, snd('file:///C:/a.html'), d), null);
  assertEq('route no url ignored', L.routeMessage({ type: 'mfaCheck' }, { id: SELF, frameId: 0 }, d), null);
  assertEq('route unknown type', L.routeMessage({ type: 'xyz' }, snd('https://a.com/'), d), null);
  assertEq('route ignored wrote nothing', [d.store.writes, d.session.writes, d.fetch.calls.length], [0, 0, 0]);

  // pendingCards: ayni site alir; ayni sekmede baska siteye yonlenildiyse kart ilk siteyi adlandirir
  d = mk(PWSFX + ':77\r\n');
  r = await L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://www.evil.com/'), d);
  assertEq('route leaked', r.leaked, 77);
  assertEq('route pending cross-site same tab names origin', await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d), { reuse: [], leaked: 77, from: 'evil.com' });
  d = mk(PWSFX + ':77\r\n');
  await L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://www.evil.com/'), d);
  assertEq('route pending cross-site other tab rejected', await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/', { tab: { id: 9 } }), d), null);
  now = T + 61000;
  assertEq('route pending cross-site expires 60s', await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d), null);
  now = T;
  d = mk(PWSFX + ':77\r\n');
  await L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://www.evil.com/'), d);
  assertEq('route pending other tab', await L.routeMessage({ type: 'pendingCards' }, snd('https://evil.com/', { tab: { id: 8 } }), d), null);
  r = await L.routeMessage({ type: 'pendingCards' }, snd('https://app.evil.com/'), d);
  assertEq('route pending same site', r && r.leaked, 77);
  assertEq('route pending taken once', await L.routeMessage({ type: 'pendingCards' }, snd('https://app.evil.com/'), d), null);
  d = mk(PWSFX + ':77\r\n');
  await L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://evil.com/'), d);
  now = T + 61000;
  assertEq('route pending expires 60s', await L.routeMessage({ type: 'pendingCards' }, snd('https://evil.com/'), d), null);
  now = T;
  d = mk(PWSFX + ':77\r\n');
  await L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://evil.com/'), d);
  await L.routeMessage({ type: 'cardsShown' }, snd('https://evil.com/'), d);
  assertEq('route cardsShown clears', await L.routeMessage({ type: 'pendingCards' }, snd('https://evil.com/'), d), null);

  // Form gonderimiyle sayfa degisir: yeni sayfanin pendingCards'i suren kontrolu bekler (en fazla 6 sn)
  function gatedFetch(body) {
    let release, called;
    const gate = new Promise(function (r) { release = r; });
    const wasCalled = new Promise(function (r) { called = r; });
    const f = async function (url) { f.calls.push({ url: url }); called(); await gate; return { ok: true, text: async function () { return body; } }; };
    f.calls = []; f.release = release; f.wasCalled = wasCalled;
    return f;
  }
  const never = function () { return new Promise(function () {}); };
  const instant = function () { return Promise.resolve(); };
  const sleeps = [];
  d = mk(); d.inflight = new Map(); d.fetch = gatedFetch(PWSFX + ':77\r\n');
  d.sleep = function (ms) { sleeps.push(ms); return never(); };
  let sub = L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://bank.com/login'), d);
  assertEq('inflight set synchronously', d.inflight.has(7), true);
  let pend = L.routeMessage({ type: 'pendingCards' }, snd('https://www.bank.com/home'), d);
  await d.fetch.wasCalled;
  d.fetch.release();
  r = await pend;
  assertEq('pending waits for in-flight check', r, { reuse: [], leaked: 77 });
  assertEq('pending wait capped at 6s', sleeps, [6000]);
  await sub;
  assertEq('inflight cleared after check', d.inflight.size, 0);
  assertEq('pending without in-flight does not wait', [await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d), sleeps.length], [null, 1]);

  // Ayni-sifre sonucu HIBP donmeden bekleyen karta yazilir; sizinti sonucu gelince eklenir
  const esalt = '00112233445566778899aabbccddeeff';
  const efp = await L.fingerprint('Ortak-Erken-1', esalt);
  const eidx = {}; eidx[efp] = ['a.com'];
  d = mk(); d.inflight = new Map(); d.fetch = gatedFetch(PWSFX + ':0\r\n' + 'X'.repeat(35) + ':1\r\n');
  d.store = fakeStore({ salt: esalt, pwIndex: eidx });
  sub = L.routeMessage({ type: 'pwSubmit', password: 'Ortak-Erken-1' }, snd('https://bank.com/'), d);
  await d.fetch.wasCalled;
  assertEq('reuse stored before HIBP returns', d.session.data.pending && d.session.data.pending[7] && d.session.data.pending[7].result, { reuse: ['a.com'], leaked: 0 });
  d.sleep = instant; // 6 sn doldu
  r = await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d);
  assertEq('pending after timeout gets reuse only', r, { reuse: ['a.com'], leaked: 0 });
  d.fetch.release();
  r = await sub;
  assertEq('pw reply complete', r.reuse, ['a.com']);
  assertEq('no leak: nothing more pending', await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d), null);

  // Ayni senaryo, sifre sizmis: kart alindiktan sonra gelen sizinti ayrica bekler
  const lfp = await L.fingerprint('password', esalt);
  const lidx = {}; lidx[lfp] = ['a.com'];
  d = mk(); d.inflight = new Map(); d.fetch = gatedFetch(PWSFX + ':77\r\n'); d.sleep = instant;
  d.store = fakeStore({ salt: esalt, pwIndex: lidx });
  sub = L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://bank.com/'), d);
  await d.fetch.wasCalled;
  r = await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d);
  assertEq('early pending reuse', r, { reuse: ['a.com'], leaked: 0 });
  d.fetch.release();
  await sub;
  assertEq('late leak pending alone', await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d), { reuse: [], leaked: 77 });
  // Kart alinmadan sonuc geldiyse tek kayit, ikisi birlikte
  d = mk(); d.inflight = new Map(); d.fetch = gatedFetch(PWSFX + ':77\r\n'); d.sleep = never;
  d.store = fakeStore({ salt: esalt, pwIndex: lidx });
  sub = L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://bank.com/'), d);
  await d.fetch.wasCalled;
  d.fetch.release();
  await sub;
  assertEq('complete result replaces early', await L.routeMessage({ type: 'pendingCards' }, snd('https://bank.com/'), d), { reuse: ['a.com'], leaked: 77 });

  // Rakam şifre yönlendiricide de hız sınırına ve bekleyen karta sayılmaz
  d = mk();
  r = await L.routeMessage({ type: 'pwSubmit', password: '654321' }, snd('https://www.ziraatbank.com.tr/'), d);
  assertEq('route digits skipped', [r, d.fetch.calls.length, d.store.writes, d.session.writes], [{ reuse: [], leaked: 0 }, 0, 0, 0]);

  // Hiz siniri: site basina 10 dakikada 5
  d = mk();
  const got = [];
  for (let i = 0; i < 6; i++) {
    got.push((await L.routeMessage({ type: 'pwSubmit', password: 'Deneme-' + i }, snd('https://evil.com/'), d)) !== null);
  }
  assertEq('rate 6 replies', got, [true, true, true, true, true, true]);
  assertEq('rate only 5 fetched', d.fetch.calls.length, 5);
  const idxBefore = JSON.stringify(d.store.data.pwIndex);
  r = await L.routeMessage({ type: 'pwSubmit', password: 'Deneme-yeni' }, snd('https://evil.com/'), d);
  assertEq('rate over limit silent', [r, d.fetch.calls.length, JSON.stringify(d.store.data.pwIndex)], [{ reuse: [], leaked: 0 }, 5, idxBefore]);
  await L.routeMessage({ type: 'pwSubmit', password: 'Deneme-b' }, snd('https://other.com/'), d);
  assertEq('rate per site', d.fetch.calls.length, 6);
  now = T + 10 * 60 * 1000 + 1;
  await L.routeMessage({ type: 'pwSubmit', password: 'Deneme-sonra' }, snd('https://evil.com/'), d);
  assertEq('rate window resets', d.fetch.calls.length, 7);
  assertEq('rate in session store only', [d.session.data.pwRate !== undefined, d.store.data.pwRate], [true, undefined]);
  now = T;

  // MFA: site sender'dan; mfaOpen adresi listeden
  d = mk();
  r = await L.routeMessage({ type: 'mfaCheck', site: 'example.com' }, snd('https://discord.com/app'), d);
  assertEq('route mfaCheck from sender', r.show, true);
  r = await L.routeMessage({ type: 'mfaCheck', site: 'discord.com' }, snd('https://example.com/'), d);
  assertEq('route mfaCheck msg.site ignored', r.show, false);
  await L.routeMessage({ type: 'mfaOpen', id: 'google', url: 'https://evil.example/' }, snd('https://discord.com/'), d);
  assertEq('route mfaOpen url from list', d.opened, ['https://support.discord.com/x']);
  await L.routeMessage({ type: 'mfaAnswer', answer: 'ok', site: 'google.com' }, snd('https://discord.com/'), d);
  assertEq('route mfaAnswer from sender', [d.store.data.mfa.discord.status, d.store.data.mfa.google], ['ok', undefined]);
  await L.routeMessage({ type: 'reuseMute', site: 'bank.com' }, snd('https://evil.com/'), d);
  assertEq('route reuseMute from sender', d.store.data.noReuseWarn, { 'evil.com': true });

  // Yonlendirici: alias grubu listeden (loadSites) gelir
  d = mk();
  d.loadSites = async function () { return [{ id: 'k', name: 'K', domains: ['kedi.com', 'kedi-giris.com'], url: 'https://kedi.com/x' }]; };
  await L.routeMessage({ type: 'pwSubmit', password: 'Kedi-Ortak-1' }, snd('https://kedi.com/'), d);
  r = await L.routeMessage({ type: 'pwSubmit', password: 'Kedi-Ortak-1' }, snd('https://www.kedi-giris.com/'), d);
  assertEq('route alias from loaded list', r.reuse, []);
  r = await L.routeMessage({ type: 'pwSubmit', password: 'Kedi-Ortak-1' }, snd('https://baska.com/'), d);
  assertEq('route alias other site warns', r.reuse, ['kedi.com']);
  // Grup ici yonlendirme ayni site sayilir (from yok)
  d = mk(PWSFX + ':77\r\n');
  await L.routeMessage({ type: 'pwSubmit', password: 'password' }, snd('https://www.garanti.com.tr/'), d);
  assertEq('route pending alias redirect same site', await L.routeMessage({ type: 'pendingCards' }, snd('https://www.garantibbva.com.tr/'), d), { reuse: [], leaked: 77 });
}

// --- Eklenti dosyalari: manifest, kimlik, MFA listesi ---
async function extensionFiles(L, assertEq) {
  const mres = await fetch('../extension/manifest.json');
  const mtext = await mres.text();
  let m = null;
  try { m = JSON.parse(mtext); } catch (e) { m = null; }
  assertEq('manifest json', !!m, true);
  if (!m) return;
  assertEq('manifest no bom', mtext.charCodeAt(0) === 0xFEFF, false);
  assertEq('manifest v3', m.manifest_version, 3);
  assertEq('manifest name', m.name, 'Cortmed Tarayıcı Koruması');
  assertEq('manifest version', m.version, '1.0.0');
  assertEq('manifest perms', (m.permissions || []).slice().sort(), ['downloads', 'nativeMessaging', 'notifications', 'storage']);
  assertEq('manifest no host perms', m.host_permissions, undefined);
  assertEq('manifest sw', m.background && m.background.service_worker, 'background.js');
  const cs = (m.content_scripts || [])[0] || {};
  assertEq('manifest cs', [cs.matches, cs.js, cs.run_at, cs.all_frames, (m.content_scripts || []).length],
    [['<all_urls>'], ['content.js'], 'document_start', false, 1]);
  assertEq('manifest cs isolated world', cs.world === undefined || cs.world === 'ISOLATED', true);
  assertEq('manifest popup', m.action && m.action.default_popup, 'popup.html');
  assertEq('manifest icons', m.icons, { '16': 'icons/16.png', '48': 'icons/48.png', '128': 'icons/128.png' });
  assertEq('manifest min chrome', m.minimum_chrome_version, '110');
  assertEq('manifest no WAR', m.web_accessible_resources, undefined);
  assertEq('manifest no externally_connectable', m.externally_connectable, undefined);

  const bg = await (await fetch('../extension/background.js')).text();
  assertEq('bg importScripts core', bg.indexOf("importScripts('lib/core.js')") >= 0, true);
  // Yalnizca sozdizimi denetimi (calistirilmaz)
  for (const f of ['background.js', 'popup.js', 'content.js']) {
    const src = f === 'background.js' ? bg : await (await fetch('../extension/' + f)).text();
    let parsed = true;
    try { new Function(src); } catch (e) { parsed = false; }
    assertEq('parses ' + f, parsed, true);
  }
  const cjs = await (await fetch('../extension/content.js')).text();
  assertEq('content.js independent of core', cjs.indexOf('CortmedLib'), -1);
  assertEq('background uses router', bg.indexOf('L.routeMessage(') >= 0 && bg.indexOf('L.downloadOutcome(') >= 0, true);
  // Nabiz: tarayici acilisinda ve kurulumda kopruye bos yol gider (panel durumu icin)
  assertEq('background heartbeat on startup/installed', [bg.indexOf('chrome.runtime.onStartup.addListener(') >= 0,
    bg.indexOf('chrome.runtime.onInstalled.addListener(') >= 0, bg.indexOf("{ path: '' }") >= 0], [true, true, true]);
  const popup = await (await fetch('../extension/popup.html')).text();
  for (const s of ['Cortmed Tarayıcı Koruması', 'Hesaplarım', 'Şifreleriniz bilgisayarınızdan çıkmaz.']) {
    assertEq('popup text ' + s, popup.indexOf(s) >= 0, true);
  }
  const pjs = await (await fetch('../extension/popup.js')).text();
  for (const s of ['İndirme kontrolü açık ✓', 'Bu özellik için Cortmed Security kurulu olmalı', 'İndirme kontrolü ilk indirmede denenecek', '✓ açık', '? bilinmiyor', '⏱ ertelendi']) {
    assertEq('popup js text ' + s, pjs.indexOf(s) >= 0, true);
  }

  for (const sz of ['16', '48', '128']) {
    const ires = await fetch('../extension/icons/' + sz + '.png');
    const buf = new Uint8Array(await ires.arrayBuffer());
    const isPng = buf.length > 24 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47;
    const w = isPng ? ((buf[16] << 24) | (buf[17] << 16) | (buf[18] << 8) | buf[19]) : 0;
    assertEq('icon ' + sz, [isPng, w], [true, Number(sz)]);
  }

  // Kimlik: key -> SPKI DER -> SHA-256 -> ilk 32 hex -> a-p
  let der = null;
  try {
    const bin = atob(m.key || '');
    der = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  } catch (e) { der = null; }
  assertEq('key base64', !!der && der.length > 250, true);
  if (der) {
    let imported = false;
    try {
      const k = await crypto.subtle.importKey('spki', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
      imported = k.algorithm.modulusLength === 2048;
    } catch (e) { imported = false; }
    assertEq('key valid spki rsa2048', imported, true);
    const h = new Uint8Array(await crypto.subtle.digest('SHA-256', der));
    let id = '';
    for (let i = 0; i < 16; i++) {
      id += String.fromCharCode(97 + (h[i] >> 4)) + String.fromCharCode(97 + (h[i] & 15));
    }
    const idres = await fetch('../extension-id.txt');
    const want = idres.ok ? (await idres.text()).trim() : '(yok)';
    assertEq('extension id matches key', id, want);
  }

  // MFA listesi
  let sites = null;
  try { sites = await (await fetch('../extension/mfa-sites.json')).json(); } catch (e) { sites = null; }
  assertEq('mfa-sites json', Array.isArray(sites), true);
  if (!Array.isArray(sites)) return;
  assertEq('mfa-sites 20', sites.length, 20);
  const ids = {};
  const bad = [];
  sites.forEach(function (s) {
    if (!s || typeof s.id !== 'string' || !s.id || typeof s.name !== 'string' || !s.name ||
        !Array.isArray(s.domains) || !s.domains.length || typeof s.url !== 'string') { bad.push(JSON.stringify(s)); return; }
    if (ids[s.id]) bad.push('dup ' + s.id);
    ids[s.id] = true;
    if (s.url.indexOf('https://') !== 0) bad.push('url ' + s.id);
    s.domains.forEach(function (d) { if (L.etld1(d) !== d) bad.push('domain ' + d); });
    if (s.hosts !== undefined) {
      if (!Array.isArray(s.hosts) || !s.hosts.length) bad.push('hosts ' + s.id);
      else s.hosts.forEach(function (h) {
        if (typeof h !== 'string' || h !== h.toLowerCase() || s.domains.indexOf(L.etld1(h)) < 0) bad.push('host ' + h);
      });
    }
  });
  assertEq('mfa-sites entries valid', bad, []);
  const need = ['discord.com', 'turkiye.gov.tr', 'ziraatbank.com.tr', 'enpara.com', 'whatsapp.com', 'x.com', 'steampowered.com'];
  assertEq('mfa-sites key domains', need.filter(function (d) { return !L.findMfaSite(sites, 'www.' + d); }), []);
  // Genis alan adlari: yalnizca hesap sayfalarinda kart (aramada ve videoda degil)
  const acct = { 'accounts.google.com': 'google', 'myaccount.google.com': 'google', 'mail.google.com': 'google',
    'login.live.com': 'microsoft', 'account.microsoft.com': 'microsoft', 'outlook.live.com': 'microsoft',
    'appleid.apple.com': 'apple', 'account.apple.com': 'apple' };
  assertEq('mfa-sites account hosts match', Object.keys(acct).filter(function (h) { return (L.findMfaSite(sites, h) || {}).id !== acct[h]; }), []);
  const quiet = ['www.google.com', 'google.com', 'www.google.com.tr', 'www.youtube.com', 'm.youtube.com', 'www.microsoft.com',
    'www.bing.com', 'www.apple.com', 'www.icloud.com', 'support.google.com'];
  assertEq('mfa-sites broad domains quiet', quiet.filter(function (h) { return L.findMfaSite(sites, h) !== null; }), []);
  // Ek alias tablosunun kanonik adi listeninkiyle ayni (liste yuklenemese de ayni kayit)
  const extraDomains = ['steampowered.com', 'steamcommunity.com', 'garanti.com.tr', 'garantibbva.com.tr', 'live.com',
    'microsoftonline.com', 'microsoft.com', 'outlook.com', 'google.com', 'youtube.com'];
  assertEq('alias canonical same with/without list', extraDomains.filter(function (x) { return L.canonicalSite(x, sites) !== L.canonicalSite(x); }), []);
  assertEq('alias list groups', [L.canonicalSite('hotmail.com', sites), L.canonicalSite('gmail.com', sites), L.canonicalSite('twitter.com', sites)],
    ['microsoft.com', 'google.com', 'x.com']);
}
