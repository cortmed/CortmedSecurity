# Cortmed Tarayıcı Koruması Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Chrome/Edge MV3 extension that adds four protections: a password-reuse warning, a leaked-password check, a reminder card for two-step verification (MFA), and a scan of downloaded files through Cortmed Security.

**Architecture:**
- The core logic is plain JavaScript (classic scripts that attach to `self.CortmedLib`). Edge headless runs its tests from PowerShell.
- The extension shell has three parts: the service worker, a content script that draws its cards inside a shadow DOM, and the popup.
- A C# 5 native-messaging host passes a downloaded file's path to the existing `CortmedSecurity.ps1 -Mode ScanFile`.

**Tech Stack:** JavaScript (ES2020, no build step, no npm), WebCrypto, Chrome extension APIs, C# 5 (csc v4), PowerShell 5.1.

**Spec:** `docs/superpowers/specs/2026-10-29-tarayici-eklentisi-design.md`

## Global Constraints

- **No Node, no npm, no bundler.** JavaScript runs exactly as written. Tests run in Edge headless.
- **Passwords never leave the machine.**
  - The only network call is `https://api.pwnedpasswords.com/range/<first 5 hex of SHA-1, uppercase>`, sent with the header `Add-Padding: true`.
  - Nothing is logged or stored in clear text.
- **Fingerprint:** PBKDF2-SHA256, using a 16-byte random salt per install and 100000 iterations. Keep the first 16 bytes and store them as hex. Everything lives in `chrome.storage.local`.
- **HIBP results:** cache them per fingerprint for 30 days. On a network error, stay silent.
- **MFA "Sonra" (later):** ask again after 7 days.
- **Downloads scanned:** only these extensions: exe, msi, scr, bat, cmd, ps1, js, vbs, jar, zip, rar, 7z, iso, img.
- **Native host:**
  - Name `com.cortmed.security`.
  - Accepts only `{"path": "<full path>"}`. The file must exist and its path must be under `%USERPROFILE%`.
  - Messages are limited to 64 KB.
  - It writes `data\browser-lastseen.txt` under `%LOCALAPPDATA%\CortmedSecurity`.
- **Registry:** HKCU only, at `Software\Google\Chrome\NativeMessagingHosts\com.cortmed.security` and `Software\Microsoft\Edge\NativeMessagingHosts\com.cortmed.security`. No admin rights.
- **No remote code.** `mfa-sites.json` is bundled with the extension.
- **Warn only.** The extension never deletes or moves files.
- **Text:** everything the user sees is Turkish, plain, in "siz" form. Card texts are copied verbatim from spec §3.
- **Colours:** the dark theme matches the Windows app: background `#0B1526`, surface `#13223A`, accent `#29B6F6`, text `#F1F5FB`, muted `#93A4BD`, red `#EF5350`, yellow `#FFB300`, green `#66BB6A`.
- **Encoding:** PowerShell scripts that contain Turkish text are saved as UTF-8 with BOM.
- **Full test suite:** `powershell -NoProfile -ExecutionPolicy Bypass -File tests/guard/run.ps1` must exit 0 with 0 FAIL after every task.

## Review Focus

1. **Login forms that do not submit.** Many sites (Google, Discord) log in with JavaScript and no `<form>` submit. The content script must also catch a click on a button inside the same form or container, and Enter in the password field. Test: Task 2 fixture page with a JS-only login.
2. **The same site on different subdomains** (`accounts.google.com` vs `mail.google.com`) must not count as reuse. Test: Task 1 eTLD+1 cases, including `co.uk` and `com.tr`.
3. **Very long or odd passwords** (empty, 1 char, 500 chars, emoji) must not crash anything. Empty passwords are ignored. Test: Task 1.
4. **Native host missing or failing.** The download notification must not hang; the popup shows the "kurulu olmalı" text. Test: Task 2 handles `chrome.runtime.lastError`; Task 3 host returns an error JSON on a bad path.
5. **Download paths with spaces, Turkish letters or OneDrive** (`C:\Users\Ahmet\OneDrive\Masaüstü\a b.exe`) must be accepted when they are under the profile. Test: Task 3.

---

### Task 1: Core logic and browser test runner

**Files:**
- Create: `browser/extension/lib/core.js`, `browser/tests/test.html`, `browser/tests/tests.js`
- Modify: `tests/guard/run.ps1` (add an Edge headless run)

**Interfaces:**
- Produces (on `self.CortmedLib`):
  - `etld1(hostname: string) -> string`. Uses a built-in table of two-part suffixes: `co.uk, com.tr, gov.tr, edu.tr, org.tr, net.tr, k12.tr, com.au, co.jp`.
  - `async fingerprint(password: string, saltHex: string) -> string`. 32 hex characters.
  - `async sha1Hex(text) -> string`. Uppercase.
  - `recordUse(index: object, fp: string, site: string) -> {index, otherSites: string[]}`. The index maps fp to an array of sites. The site is first removed from any other fp, which handles a changed password.
  - `mfaState(entry: {status, until}|undefined, now: number) -> 'ask'|'ok'|'snoozed'|'never'`.
  - `isScannable(filename: string) -> boolean`.
  - `parseRange(body: string, suffix: string) -> number`. The count, or 0 if not found.

- [ ] **Step 1: Write the tests** in `tests.js`, using a tiny `assertEq` helper. When everything passes the page shows `<div id="result">PASS n</div>`, otherwise `FAIL: <names>`.
  - `etld1`: `accounts.google.com` → `google.com`; `www.garanti.com.tr` → `garanti.com.tr`; `a.b.co.uk` → `b.co.uk`; `localhost` → `localhost`; `192.168.1.1` → `192.168.1.1`.
  - `fingerprint`: same password and salt give the same result; a different salt gives a different result; the result is 32 hex characters; a 500-char password and an emoji password both work.
  - `recordUse`: the same fp on `discord.com`, then on `steampowered.com`, gives `otherSites == ['discord.com']`. The same fp again on `discord.com` gives no new other site. When `discord.com` gets a new fp, it is removed from the old one.
  - `mfaState`: undefined → `ask`; `{status:'ok'}` → `ok`; `{status:'later',until:now+1}` → `snoozed`; `{status:'later',until:now-1}` → `ask`; `{status:'never'}` → `never`.
  - `isScannable`: `a.EXE` → true; `b.pdf` → false; `c.tar.gz` → false; `d.7z` → true.
  - `parseRange`: on the body `"ABC:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n"` with suffix `1E4C9B93F3F0682250B6CF8331B7EE68FD8`, the result is 42. A missing suffix gives 0.
  - `sha1Hex('password')` → `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`.
- [ ] **Step 2: Add a check to run.ps1.**
  - Find Edge at `${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe`, then fall back to `$env:ProgramFiles`.
  - Run `msedge --headless=new --disable-gpu --allow-file-access-from-files --virtual-time-budget=5000 --dump-dom file:///<abs>/browser/tests/test.html`.
  - Check that the output contains `id="result">PASS`. If Edge is missing, print SKIP.
  - Run it: expect FAIL, because core.js does not exist yet.
- [ ] **Step 3: Implement `core.js`.**
- [ ] **Step 4: Run run.ps1.** The new check should PASS and the suite should exit 0.
- [ ] **Step 5: Commit** with the message `"eklenti: cekirdek mantik ve testler"`.

### Task 2: Extension shell (manifest, service worker, content script, popup)

**Files:**
- Create in `browser/extension/`: `manifest.json`, `background.js`, `content.js`, `card.css`, `popup.html`, `popup.js`, `popup.css`, `mfa-sites.json`, `icons/16.png`, `icons/48.png`, `icons/128.png` (made from `windows/cortmed-logo.png`).
- Create `browser/tests/login-fixture.html`.
- Create `tools/extension-key.ps1`. It generates an RSA-2048 key pair, writes the public key's base64 SPKI into manifest `key`, and prints the extension ID. The ID is the SHA-256 of the DER key: the first 32 hex characters with digits 0-f mapped to the letters a-p. Only the public key is committed. The private key goes to `android/keystore/cortmed-extension.pem`, which is gitignored.

**Interfaces:**
- Consumes the Task 1 functions.
- Messages from the content script to the service worker:
  - `{type:'pwSubmit', site, password}` → reply `{reuse: string[], leaked: number}`. The service worker computes everything, and the password is dropped immediately after use.
  - `{type:'mfaCheck', site}` → reply `{show: bool, name, url}`.
  - `{type:'mfaAnswer', site, answer:'ok'|'later'|'never'}`.
- Native message to `com.cortmed.security`: `{path}` → reply `{level:'RED'|'YELLOW'|'OK'|'ERROR', title, reasons:[]}`.
- Manifest:
  - MV3, name "Cortmed Tarayıcı Koruması".
  - permissions: `storage`, `downloads`, `notifications`, `nativeMessaging`.
  - content script on `<all_urls>`, `all_frames: false`, run_at `document_idle`.
  - `minimum_chrome_version` "110".

- [ ] **Step 1: Write the tests.** Extend the test runner with `background-logic` tests: call the handler functions directly, after factoring them as pure functions in `core.js` that take a storage object.
  - `handlePwSubmit` with a fake store: the second site returns its reuse list.
  - `handleMfaCheck`: a listed site returns `show:true` once. After the answer `ok`, it returns `show:false`.
  - The `login-fixture.html` page holds a JS-only login: a button click with no form submit, and Enter in the password field. The test loads `content.js` with a stubbed `chrome.runtime.sendMessage` and asserts that both trigger exactly one `pwSubmit`.
- [ ] **Step 2: Run run.ps1.** Expect FAIL.
- [ ] **Step 3: Implement.**
  - **Content script:**
    - It listens in capture phase for `submit`, a `click` on a button or `[role=button]` in the same form or nearest container of a password field, and `keydown` Enter in the password field.
    - It reads the field value, sends `pwSubmit`, and never stores the password.
    - Cards are drawn in a closed shadow root, fixed in the bottom-right corner, z-index max, and dismiss themselves after 30 s.
    - It uses the texts from spec §3 verbatim, with the yellow card for reuse and the red card for leaked. If both apply, it shows red first, then yellow.
    - "Bu site için bir daha gösterme" stores `noReuseWarn[site]`.
  - **MFA:** on `document_idle`, send `mfaCheck`. If `show`, draw the card with the buttons [Nasıl açılır?] [Açık] [Sonra].
  - **Downloads:** `downloads.onChanged` state `complete` plus `isScannable` → `chrome.runtime.sendNativeMessage`. Then notify:
    - OK → title `✓ <dosya> temiz görünüyor`;
    - RED → `⚠ <dosya> tehlikeli olabilir` with the reasons;
    - on `lastError` or ERROR → no notification, but `storage.hostMissing = true`.
  - **Popup:** the header "Cortmed Tarayıcı Koruması", a status line (host ok, or "Bu özellik için Cortmed Security kurulu olmalı"), and "Hesaplarım", which lists `mfa-sites.json` with a status icon for each (✓ / ? / ⏱).
  - **`mfa-sites.json`:** the 20 sites from spec §3.3, each as `{id, name, domains:[...], url}` where `url` is the official 2-step settings page. Use the public help or settings page for each; for the banks, use the bank's security or Mobil Onay help page.
- [ ] **Step 4: Run run.ps1.** Expect PASS. Then load it by hand in the built-in browser pane only if available. Do not install it into the user's browsers.
- [ ] **Step 5: Commit** with the message `"eklenti: manifest, arka plan, icerik betigi, acilir pencere"`.

### Task 3: Native messaging host and ScanFile JSON

**Files:**
- Create: `windows/browser/CortmedBrowserHost.cs`, `windows/browser/com.cortmed.security.json.template`
- Modify: `windows/CortmedSecurity.ps1`: add the switch `-Json` for `-Mode ScanFile`. It prints one JSON line `{level,title,reasons}` built from `Get-FileAnalysis`.
- Test: `tests/guard/run.ps1`

**Interfaces:**
- The host's stdio follows Chrome's protocol: a 4-byte little-endian length, then a UTF-8 JSON body. It handles one request per process.
- `CortmedBrowserHost.exe [--scan-cmd <exe> <args...>]`. The override exists only for tests. By default it runs `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<dir>\CortmedSecurity.ps1" -Mode ScanFile -Json -Path "<path>"`, with a 120 s timeout.
- Error replies use `{level:'ERROR', title:'<Turkish reason>', reasons:[]}`.

- [ ] **Step 1: Write the tests in run.ps1.**
  - Build the host to a temp directory, then feed it framed messages:
    - a missing file → ERROR;
    - `C:\Windows\notepad.exe` (outside the profile) → ERROR;
    - a message larger than 64 KB → ERROR, and the host exits;
    - a malformed JSON → ERROR;
    - a valid file at `%TEMP%\cortmed host test ü\a b.exe` with `--scan-cmd` pointing at a stub that echoes `{"level":"OK","title":"t","reasons":[]}` → the reply is equal to that, and `browser-lastseen.txt` was written. Use a temp `--data` override.
  - Also check that `CortmedSecurity.ps1 -Mode ScanFile -Json -Path <a temp txt>` prints valid JSON with a `level`.
- [ ] **Step 2: Run them.** Expect FAIL.
- [ ] **Step 3: Implement.**
  - Use C# 5 only.
  - Check the path with `Path.GetFullPath`. It must start with `Environment.GetFolderPath(UserProfile) + "\"` (case-insensitive) and `File.Exists` must be true.
  - Never pass the path through a shell string. Use `ProcessStartInfo` with each argument quoted, rejecting `"` in the path.
  - Write a single reply.
- [ ] **Step 4: Run.** Expect PASS.
- [ ] **Step 5: Commit** with the message `"eklenti: yerel kopru ve ScanFile JSON"`.

### Task 4: Install, uninstall, package and panel

**Files:**
- Modify: `windows/Install.ps1`, `windows/Uninstall.ps1`, `make-windows-package.ps1`, `windows/CortmedSecurity.ps1` (panel status row and setup guide).
- Test: `tests/guard/run.ps1`, `tests/guard/tray-tests.ps1`.

**Interfaces:**
- `Install.ps1`:
  - copies `browser\extension\*` to `%LOCALAPPDATA%\CortmedSecurity\browser\`;
  - compiles the host into `%LOCALAPPDATA%\CortmedSecurity\CortmedBrowserHost.exe`;
  - writes `com.cortmed.security.json` next to it, with `path` pointing to the exe and `allowed_origins` set to `["chrome-extension://<ID from manifest key>/"]`;
  - sets the two HKCU registry keys' default value to that json path.
- `Uninstall.ps1` removes both keys.
- Panel (`Get-StatusSummary` / status checks): a fifth check "Tarayıcı koruması".
  - If `browser-lastseen.txt` is from the last 7 days → "Tarayıcı koruması açık" ✓.
  - Otherwise, an Önerilerimiz card "Tarayıcı korumasını ekleyin". Its button opens a dark guide window with 4 numbered steps (Chrome / Edge → Geliştirici modu → Paketlenmemiş öğe yükle → the folder path, with a "Klasör yolunu kopyala" button), and buttons that open `chrome://extensions` and `edge://extensions` by starting the browser with that URL.
- Package: include `browser\extension\` and `windows\browser\*.cs`.

- [ ] **Step 1: Write the tests.**
  - Static checks: Install.ps1 references `NativeMessagingHosts` and `com.cortmed.security`; Uninstall.ps1 removes it.
  - A tray test: the guide form builds with 4 steps. The panel shows ✓ with a fresh lastseen file and the advice card with an old one.
  - Do not run Install.ps1.
- [ ] **Step 2: Run them.** Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expect PASS.
- [ ] **Step 5: Commit** with the message `"eklenti: kurulum, kaldirma, paket ve panel"`.

### Task 5: README and the manual test checklist

**Files:** Modify `README.md`.

- [ ] **Step 1:** Add a Turkish section "Tarayıcı koruması" with five parts:
  - what it does, in 4 bullets;
  - privacy: "Şifreniz bilgisayarınızdan çıkmaz";
  - how to add it to Chrome and to Edge;
  - Edge Add-ons store publishing as a later step for the user;
  - the Sandbox checklist from spec §6.3: two sites with the same test password; `password123`; the Discord page; downloading the EICAR test file.
- [ ] **Step 2: Commit** with the message `"docs: tarayici korumasi"`.
