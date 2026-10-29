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
  } catch (e) {
    fails.push('exception: ' + e.message);
  }
  finished = true;
  out.textContent = fails.length ? 'FAIL: ' + fails.join('; ') : 'PASS ' + n;
})();
