# Cortmed Tarayıcı Koruması (Chrome / Edge eklentisi): Tasarım

Tarih: 2026-10-29 · Durum: onay bekliyor · Platform: Windows'ta Chrome ve Edge

## 1. Amaç

Arkadaşın Discord ve e-posta hesabının çalınmasının iki kökü var: aynı şifrenin her yerde kullanılması ve
indirilen zararlı dosyalar. Eklenti bu ikisine tarayıcının içinden karşı koyar ve hesapları korumaya yönelik
iki adımlı doğrulama (MFA) önerilerini doğru anda ekrana getirir.

**Başarı ölçütü:**
- Aynı şifre ikinci bir sitede girildiğinde, gönderim anında sarı bir kart çıkar.
- Sızmış bir şifre girildiğinde kırmızı bir kart çıkar.
- Listedeki bir siteye girildiğinde MFA kartı bir kez çıkar.
- İndirilen bir `.exe` 10 saniye içinde Cortmed'e taratılır ve sonuç bildirim olarak gösterilir.
- Normal gezintide hiçbir şey çıkmaz.

### Kullanıcının seçtikleri
1. Aynı şifre uyarısı
2. Sızmış şifre kontrolü
3. MFA kartı
4. İndirme kontrolü (öneri listesindeki 6. madde)

Sahte site uyarısı, dolandırıcılık bağlantıları, eklenti denetimi ve şifresiz sayfa uyarısı **bu sürümde yok**.

## 2. Parçalar

| Parça | Görev | Nerede |
|---|---|---|
| **Eklenti** (Manifest V3; Chrome ve Edge için tek kod) | Şifre izi, sızıntı sorgusu, MFA kartı, indirme izleme, açılır pencere | `browser/extension/` |
| **Yerel köprü** `CortmedBrowserHost.exe` (C# 5, native messaging) | Eklentiden gelen dosya yolunu mevcut Cortmed taramasına verir, sonucu döndürür | `%LOCALAPPDATA%\CortmedSecurity\`; kurulumda derlenir |
| **Kayıt** | Chrome ve Edge'e köprüyü tanıtır | `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.cortmed.security` ve `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.cortmed.security`; yönetici izni gerekmez |
| **Panel** | "Tarayıcı koruması" durum satırı; köprünün son görülme zamanına bakar | `CortmedSecurity.ps1` |

Eklentinin kimliği sabittir (`manifest.json` içindeki `key` alanından gelir). Böylece köprünün `allowed_origins`
listesi yalnızca bu eklentiye izin verir.

## 3. İşlevler

### 3.1 Aynı şifre uyarısı
- **Ne zaman:** bir formdaki şifre alanı gönderilirken (submit ya da Enter).
- **Parmak izi:** `PBKDF2-SHA256(şifre, kurulum başına rastgele 16 bayt tuz, 100 000 tur)`, ilk 16 bayt.
  - Tuz ve izler yalnızca `chrome.storage.local` içinde durur.
  - Şifrenin kendisi hiçbir yere yazılmaz ve hiçbir yere gönderilmez.
- **Eşleşme:** aynı iz başka bir alan adında (eTLD+1, basit tablo) da kayıtlıysa, sayfanın köşesinde sarı kart çıkar:
  "Bu şifreyi başka **N** sitede de kullanıyorsunuz: a.com, b.com. Bir site sızarsa hepsi tehlikeye girer. Bu site için farklı bir şifre seçin."
  Düğmeler: **[Tamam]** ve **[Bu site için bir daha gösterme]**.
- **Kayıt biçimi:** `{iz → [alan adları]}`. Bir alan adının şifresi değişince eski kaydı silinir.

### 3.2 Sızmış şifre kontrolü
- **Ne zaman:** aynı gönderim anında, SHA-1 özetinin ilk 5 karakteri `https://api.pwnedpasswords.com/range/XXXXX` adresine gönderilir.
  `Add-Padding: true` başlığı eklenir. Şifre gönderilmez.
- **Bulunursa:** kırmızı kart çıkar: "Bu şifre daha önce internete sızmış (**N** kez görülmüş). Hemen değiştirin."
- **Önbellek:** sonuç parmak izine göre 30 gün saklanır. Ağ hatasında sessiz kalınır.

### 3.3 MFA kartı
- **Site listesi** (`mfa-sites.json`, ayar sayfası bağlantılarıyla): Google, Microsoft/Outlook, Apple, Instagram, Facebook,
  WhatsApp Web, X, TikTok, Discord, Steam, Epic Games, e-Devlet, Ziraat, Garanti BBVA, İş Bankası, Akbank, Yapı Kredi,
  VakıfBank, Halkbank, Enpara.
- **Ne zaman:** listedeki siteye ilk girişte köşede kart çıkar:
  "**Discord** hesabınızda iki adımlı doğrulama açık mı? Açıksa şifreniz çalınsa bile hesabınıza girilemez."
- **Düğmeler:**
  - **[Nasıl açılır?]** ayar sayfasını yeni sekmede açar.
  - **[Açık]** site için kalıcı olarak "tamam" işaretler.
  - **[Sonra]** 7 gün sonra yeniden sorar.
- **Açılır pencere:** "Hesaplarım" listesi, her sitenin durumunu gösterir (✓ açık / ? bilinmiyor / ⏱ ertelendi).
- **Not:** eklenti MFA'nın gerçekten açık olup olmadığını göremez. Kart soruyu sorar ve cevabı hatırlar.

### 3.4 İndirme kontrolü
- **Ne zaman:** `chrome.downloads.onChanged` bir indirmenin bittiğini bildirdiğinde. Yalnızca şu uzantılar için:
  exe, msi, scr, bat, cmd, ps1, js, vbs, jar, zip, rar, 7z, iso, img.
- **Akış:** eklenti köprüye `{"path": "..."}` gönderir.
  - Köprü yolu doğrular: dosya gerçekten var olmalı ve kullanıcının profilinde bulunmalı.
  - Sonra `powershell -File CortmedSecurity.ps1 -Mode ScanFile -Path <yol> -Json` çalıştırır
    ve sonucu döndürür: `{"level":"RED|YELLOW|OK","title":"...","reasons":[...]}`.
- **Bildirim:**
  - Temizse: "✓ dosya.exe temiz görünüyor".
  - Tehlikeliyse kırmızı bildirim ve **[Ayrıntılar]** düğmesi; Cortmed panelinde aynı dosyanın raporu açılır.
- **Dosyaya dokunulmaz.** Uyar-sadece varsayılanı geçerlidir.
- **Köprü yoksa** (Cortmed kurulu değilse): açılır pencerede "Bu özellik için Cortmed Security kurulu olmalı" yazar.
- **Panel:** köprü her çağrıda `data\browser-lastseen.txt` dosyasını yazar. 7 gün içindeyse panel "Tarayıcı koruması açık (✓)" gösterir.

## 4. Güvenlik ve gizlilik

1. **Şifre bilgisayarda kalır.** Şifre ya da tam özeti hiçbir yere gönderilmez. Yalnızca SHA-1'in ilk 5 karakteri HIBP'ye gider (k-anonimlik).
2. **Saklama:** parmak izi yavaş bir türetmeyle (PBKDF2) ve tuzla saklanır. Disk çalınsa bile şifreler geri çıkarılamaz.
3. **Köprünün sınırları:** köprü yalnızca tek bir dosya yolu kabul eder; komut almaz. Yol tam yol olmalı, dosya var olmalı
   ve `%USERPROFILE%` altında bulunmalıdır. Mesajlar 64 KB'tan büyük olamaz.
4. **İzinler:** `storage`, `downloads`, `notifications`, `nativeMessaging` ve tüm sitelerde içerik betiği
   (yalnızca şifre alanı gönderimini dinler; sayfa içeriğini okumaz, hiçbir yere göndermez).
5. **Uzak kod yok.** Eklenti kodu uzaktan yüklenmez; MFA listesi pakete gömülüdür.

## 5. Dağıtım (sıfır maliyet)

- **Edge:** Edge Eklentileri mağazası ücretsizdir. Yükleme kullanıcının Microsoft hesabıyla, kullanıcı tarafından yapılır.
- **Chrome:** mağaza 5 dolar istediği için ilk sürümde "paketlenmemiş yükle" kullanılır.
  Kurulum sonunda Cortmed adım adım ekranı gösterir: `chrome://extensions` → Geliştirici modu → Paketlenmemiş öğe yükle → `%LOCALAPPDATA%\CortmedSecurity\browser`.
- **Kurulum:** `Install.ps1` eklenti klasörünü kopyalar, köprüyü derler ve HKCU kayıtlarını yazar. `Uninstall.ps1` bunları siler.

## 6. Test

1. **Saf mantık testleri** (eTLD+1, şifre izi eşleşmesi, MFA durum makinesi, uzantı filtresi):
   `browser/tests/test.html`, tarayıcıda açılınca sonuç yazar.
   Bilgisayarda Node yok; testler tarayıcıda çalışır.
2. **Köprü testleri** (`tests/guard/run.ps1` içine):
   - geçersiz yol, profil dışı yol ve büyük mesaj reddedilir;
   - geçerli bir dosya için JSON yanıt döner (sahte tarama komutuyla).
3. **Elle deneme** (Sandbox'ta, davranış bekçisi denemesiyle birlikte):
   - iki sitede aynı test şifresi girilir;
   - `password123` girilir (sızmış);
   - Discord sayfası açılır;
   - EICAR test dosyası indirilir.

## 7. Kapsam dışı (bu sürümde yok)
- Sahte site ve dolandırıcılık bağlantısı uyarıları, eklenti denetimi, şifresiz sayfa uyarısı
- Firefox
- Android tarayıcı
- Şifre yöneticisi özellikleri (otomatik doldurma, şifre üretme)
