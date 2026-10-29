# Cortmed Security

Aile ve arkadaşlar için ücretsiz güvenlik aracı: **Android uygulaması (APK)** ve **Windows koruması**.
Virüs tespiti üç katmanlı: Cortmed Engine parmak izi veritabanı, isteğe bağlı VirusTotal ikinci görüşü ve davranış kuralları.

## Hazır dosyalar (`dist/` klasörü)

| Dosya | Ne için |
|---|---|
| `CortmedSecurity.apk` | Telefonlara kurulacak uygulama |
| `CortmedSecurity-Windows.zip` | Bilgisayara kurulum paketi (içinden `Kur.bat`) |

---

## 📱 Android kurulumu

1. `CortmedSecurity.apk` dosyasını telefona gönder (WhatsApp, USB, Drive).
2. Telefonda dosyayı aç. "Bilinmeyen uygulama yükleme" izni istenirse **sadece kurulum için** ver.
3. Kurulumdan sonra **o izni geri kapat**: Ayarlar > Uygulamalar > (dosyayı açtığın uygulama) > Bilinmeyen uygulamaları yükle > Kapalı.
   Cortmed bu izni açık bırakan uygulamaları zaten sarı öneri olarak gösterir.
4. Cortmed'i aç, bildirim iznine **İzin ver** de.
5. **Yönetici ayarları**'na gir. İlk girişte bir PIN belirlersin; anne-baba bu PIN'i bilmemeli.
   - Cihaz adı: "Annemin telefonu" gibi

Kurulduktan sonra uygulama her 15 dakikada bir sessizce tarar. Normal günde hiçbir bildirim göstermez.

### Telefonda neyi yakalar?

| Bulgu | Seviye |
|---|---|
| Veritabanında kayıtlı virüs (APK parmak izi) | 🔴 |
| VirusTotal'da 3 veya daha fazla motorun "zararlı" dediği mağaza dışı uygulama | 🔴 |
| AnyDesk, TeamViewer, RustDesk vb. uzaktan erişim uygulaması | 🔴 |
| Mağaza dışından yüklenmiş ve banka / e-Devlet / kargo adı taşıyan uygulama | 🔴 |
| Erişilebilirlik izni + (mağaza dışı veya SMS okuma veya cihaz yöneticisi) = bankacılık truva atı profili | 🔴 |
| Mağaza dışı uygulamanın SMS veya bildirim okuması (tek kullanımlık şifre hırsızlığı) | 🔴 |
| Ekran kilidi yok, güvenli DNS kapalı, USB hata ayıklama açık, root, eski güvenlik yaması | 🟡 |
| Bilinmeyen kaynak yükleme izni olan uygulamalar, mağaza dışı uygulamalar | 🟡 |

🔴 olunca telefonda **genel bir uyarı** çıkar ("Telefonunuzda tehlikeli bir uygulama ya da ayar bulundu…").
🟡 öneriler bildirim göndermez; uygulamada **Önerilerimiz** sekmesinde konu başlıkları altında toplanır.

**Güvenilir** düğmesi (PIN ister) bir uygulama için davranış uyarılarını susturur. Virüs eşleşmesi ise her zaman bildirilir.

---

## 💻 Windows kurulumu

1. `CortmedSecurity-Windows.zip` dosyasını bir klasöre çıkar.
2. `Kur.bat`'a çift tıkla. Yönetici yetkisi gerekmez.
3. Açılan panelde **Önerilerimiz** sekmesindeki *Windows korumalarını güçlendirin* kartında **Tek tıkla aç**'a bas.
   Yönetici onayı ister ve bir kere yapılır. Defender'ın kapalı gelen korumalarını, hesap çalan programlara karşı
   Microsoft ASR kurallarını ve güvenli DNS'i açar. Geri almak için: `%LOCALAPPDATA%\CortmedSecurity\Harden.ps1 -Undo`

Cortmed sağ altta, saatin yanındaki **sistem tepsisinde** çalışır. Üstüne gelince durumu yazar
("Koruma aktif · Güvendesiniz"), tıklayınca panel açılır, sağ tıkla "Şimdi tara" seçilebilir.

Kaldırmak için `Kaldir.bat`.

### Bilgisayarda ne yapar?

| Görev | Nasıl |
|---|---|
| **İndirme bekçisi** | İndirilenler ve Masaüstü'ne düşen her `.exe`, `.scr`, `.zip`, `.bat`… dosyasını saniyeler içinde tarar. Virüsse **uyarı verir; dosyaya dokunmaz** |
| Tanınmayan program uyarısı | İnternetten inmiş ve imzasız programlar için tek bir uyarı (engellemez) |
| **Discord hırsızı tespiti** | Discord'un çekirdek dosyasına kod enjekte edilmiş mi diye bakar; token çalan virüslerin en yaygın izi |
| Başlangıç taraması | Run anahtarları, Başlangıç klasörü ve zamanlanmış görevlerdeki virüsleri, şifrelenmiş PowerShell komutlarını ve imzasız programları bulur |
| Güvenlik ayarları | Defender, güvenlik duvarı, UAC, SmartScreen, DNS, Windows Update ve yönetici hesabı kullanımı |
| Günlük işler | Günde bir tam tarama ve veritabanı güncellemesi |

Varsayılan mod **sadece uyar**: Cortmed hiçbir dosyayı silmez ya da taşımaz. İstersen Ayarlar'daki *Virüslü dosyaları otomatik karantinaya taşı* kutusunu işaretleyebilirsin. O zaman dosyalar `.karantina` uzantısıyla Karantina klasörüne taşınır ve açılamaz.

### Tarama motorları

Her şüpheli dosya, birbirinden bağımsız motorlarla kontrol edilir. Hepsi bilgisayarda, internetsiz çalışır ve dosyaya dokunmaz:

| Motor | Ne yapar | Varsayılan |
|---|---|---|
| Cortmed veritabanı | Dosyanın parmak izini 2 milyon bilinen zararlıyla karşılaştırır | Açık |
| Microsoft Defender | Windows'un kendi antivirüsü dosyanın içeriğini tarar (`-DisableRemediation`: sadece rapor eder) | Açık |
| YARA | YARA-Forge "core" paketindeki 5.000'den fazla topluluk kuralıyla içerikte zararlı yazılım kalıpları arar | Açık |
| ClamAV | Cisco'nun açık kaynak motoru; arşivlerin ve kurulum paketlerinin içine de bakar | **Kapalı.** Ayarlar'dan açılır (yaklaşık 500 MB). Sadece şüpheli dosyada birkaç saniye çalışır, RAM'i sürekli kullanmaz |
| VirusTotal | 70'ten fazla motorun görüşü (internet gerekir) | API anahtarı girilirse |

Panelde bir bulguya çift tıklayınca **dosya raporu** açılır: ne olduğu, üreticisi, imzası, nereden indiği ve her motorun sonucu.

> Not: Cortmed dosyalara dokunmasa da Windows Defender'ın kendi gerçek zamanlı koruması, kesin zararlı bulduğu dosyayı kendisi karantinaya alabilir. Bu Windows'un normal davranışıdır.

YARA kuralları içinde zararlı yazılım parçaları barındırdığı için Defender kural *metnini* virüs sanabilir. Bu yüzden kurallar gece GitHub'da derlenir (`engine/build_yara.py`) ve bilgisayarlara sadece derlenmiş `windows.yarc` dosyası gider.

---

## 🔑 Ücretsiz hesaplar

| Hesap | Ne için | Nasıl |
|---|---|---|
| **VirusTotal** | İkinci görüş (isteğe bağlı) | virustotal.com'a kaydol > profil > API Key. Ücretsiz sürüm: dakikada 4, günde 500 sorgu |
| **abuse.ch** | Daha güncel virüs veritabanı (isteğe bağlı) | auth.abuse.ch'den ücretsiz Auth-Key al, GitHub'da `ABUSECH_AUTH_KEY` gizli değişkeni olarak ekle |
| **GitHub** | Her gece otomatik veritabanı güncellemesi | Aşağıya bak |

### GitHub ile gece güncellemesi

1. GitHub'da `CortmedSecurity` adında bir depo aç ve bu klasörü yükle (`.gitignore` imza anahtarını zaten dışarıda tutar).
2. Depo > Actions > **Cortmed DB guncelle** > *Run workflow* ile bir kere elle çalıştır.
3. Uygulamalardaki **güncelleme adresi**:
   `https://github.com/cortmed/CortmedSecurity/releases/download/db-latest`
4. (İsteğe bağlı) Depo > Settings > Secrets > Actions > `ABUSECH_AUTH_KEY` ekle. MalwareBazaar'ın en yeni örnekleri de veritabanına girer.

Telefonlar veritabanını sadece Wi-Fi'dayken ve sadece yeni sürüm varsa indirir.

---

## 🧪 Test etme (zararsız test dosyaları)

Antivirüslerdeki EICAR mantığı: bu dosyalar zararsızdır ama Cortmed veritabanında "virüs" olarak kayıtlıdır.

- **Android:** `test/cortmed-test-virus.apk` ("Kargo Takip (Cortmed Test)") kur ve Cortmed'de *Şimdi Tara*'ya bas. Kırmızı uyarı gelmeli. Sonra test uygulamasını kaldır.
- **Windows:** `cortmed-test-dosyasi.txt` dosyasını kopyalayıp İndirilenler'e `deneme.exe` adıyla yapıştır. Birkaç saniye içinde uyarı gelmeli (dosyaya dokunulmaz, testten sonra kendin sil). Test dosyası kurulum paketinde yok, `test/` klasöründe duruyor.

### Davranış bekçisini deneme

Davranış bekçisi (CortmedGuard), kötü huylu bir programı çalışırken yakalar. Aşağıdaki zararsız program iki kötü huyu taklit eder:
kendini açılışa eklemeyi ve sahte bir Discord dosyasını değiştirmeyi. Gerçek Discord'a ya da başka bir programa dokunmaz.
Bu program kurulum paketinde yok; kendiniz derlersiniz.

1. Programı derleyin: `powershell -ExecutionPolicy Bypass -File windows\guard\Test\build-test.ps1`
   Sonuç: `%LOCALAPPDATA%\CortmedBuild\test\CortmedBehaviorTest.exe`
2. `CortmedBehaviorTest.exe` dosyasını **İndirilenler** ya da **Masaüstü** klasörüne kopyalayın.
   Temp ya da `%LOCALAPPDATA%` içinden çalıştırmayın: bekçi bu klasörlerdeki programlara kendi klasörü gibi davranır ve uyarmayabilir.
3. Kopyaladığınız programa çift tıklayın. **5 saniye içinde** bir soru penceresi çıkmalı ve iki neden yazmalı:
   - Kendini açılışa eklemeye çalıştı.
   - Başka bir programın (Discord/tarayıcı) dosyalarını değiştirmeye çalıştı.
4. **Programı kapat**'ı seçin. Program kapanmalı. Panelin **Önerilerimiz** sekmesinde, **Durdurulan programlar** başlığı altında bir bulgu görünmeli.
5. Program temizlik yapamadan kapandığı için izleri elle silin: `CortmedBehaviorTest.exe --cleanup`
   (Açılıştaki `CortmedTest` değerini ve Temp altındaki `CortmedFakeDiscord` klasörünü siler.)

Soruda **İzin ver** seçilirse aynı program (aynı dosya) bir daha sorulmaz: dosyanın parmak izi izin listesine eklenir.
Denemeyi tekrarlamak için **Programı kapat**'ı seçin.

**Yanlış alarm denemesi:** Discord, Steam ve Chrome'u kurun ya da güncelleyin. `C:\ProgramData\Cortmed\guard.log` içinde
"Ağaç donduruldu" (Freeze) satırı da, "Şüpheli davranış" satırı da **olmamalı**:

```powershell
Select-String -Path C:\ProgramData\Cortmed\guard.log -Encoding UTF8 -Pattern 'Ağaç donduruldu', 'Şüpheli davranış'
```

**Windows Sandbox kontrol listesi** (kurulumdan sonra, yukarıdaki adımlara ek olarak):
- **Edge'den indirilen deneme programı:** `CortmedBehaviorTest.exe` dosyasını Edge ile indirin (örneğin yerel bir klasörden
  `file:///` adresiyle açıp kaydedin) ve Edge'in indirme çubuğundaki **Aç**'a tıklayın. Soru penceresi `CortmedBehaviorTest.exe`'yi
  adlandırmalı, `msedge.exe`'yi değil; **Programı kapat** Edge'i kapatmamalı.
- **OneDrive eşitleme:** OneDrive'da oturum açın ve 200 dosyalık bir klasörü Masaüstü'ne eşitleyin. `guard.log` içinde
  "Şüpheli davranış" ya da "Ağaç donduruldu" satırı olmamalı.
- **Etkin Sysmon ayarı:** yönetici PowerShell'de `C:\Windows\Sysmon64.exe -c` çalıştırın. Çıktıda ProcessAccess kuralı
  `lsass.exe` ile birlikte `GrantedAccess` maskelerini (0x1010, 0x1410, 0x1fffff…) göstermeli.

**Birden fazla kullanıcı:** Bilgisayarda aynı anda birden fazla kullanıcı oturumu açıksa sorular ilk oturumdaki Cortmed'e gider.

**Performans denemesi:** 10 dakika normal kullanımdan sonra `Get-Process CortmedGuard` çalıştırın.
Ortalama işlemci kullanımı %1'in altında, bellek (çalışma kümesi) 80 MB'ın altında olmalı.

Otomatik kontrol: `tests\guard\run.ps1`, aynı olayları bekçiye sahte olarak oynatır ve dondurma kararını doğrular (programı çalıştırmaz).

---

## 🌐 Tarayıcı koruması

Chrome ve Edge için küçük bir eklenti. Tarayıcıda şifrelerinizi korur, indirdiğiniz dosyaları da Cortmed'e taramaya gönderir.

### Ne yapar?

- Aynı şifreyi farklı sitelerde kullandığınızda sizi uyarır.
- Sızdırılmış şifreleri uyarır. Bunun için Have I Been Pwned'in k-anonimlik kontrolünü kullanır: şifrenizin SHA-1 özetinin sadece ilk 5 karakteri gönderilir.
- 20 sitede iki adımlı doğrulama (MFA) hatırlatma kartı gösterir. Açılır pencerede **Hesaplarım** listesi de vardır.
- İndirdiğiniz dosyaları Cortmed'e taratır. Bunun için Cortmed Security'nin kurulu olması gerekir.

### Gizlilik

**Şifreniz bilgisayarınızdan çıkmaz.** Bilgisayarda sadece yavaş hesaplanan ve tuzlanmış bir parmak izi saklanır; şifrenin kendisi saklanmaz.
Kontroller sınırlıdır: bir sitede 10 dakikada en fazla 5 kontrol, 24 saatte en fazla 30 farklı şifre.

### Nasıl eklenir?

`Kur.bat` her şeyi hazırlar. Panelde **Tarayıcı korumasını ekleyin** kartındaki **Nasıl eklenir?** rehberi de adımları gösterir.

Klasör yolu: `%LOCALAPPDATA%\CortmedSecurity\browser`. Bu klasör gizlidir, pencerede gezinerek bulunamaz;
yolu kopyalayın (rehberdeki **Klasör yolunu kopyala** düğmesi tam yolu kopyalar).

**Chrome:**
1. Adres çubuğuna `chrome://extensions` yazın.
2. Sağ üstteki **Geliştirici modu**'nu açın.
3. **Paketlenmemiş öğe yükle**'ye basın.
4. Açılan pencerede üstteki adres çubuğuna kopyaladığınız yolu yapıştırın, Enter'a basın, sonra **Klasör seç** düğmesine basın.

**Edge:**
1. Adres çubuğuna `edge://extensions` yazın.
2. Sol alttaki **Geliştirici modu**'nu açın.
3. **Paketten çıkarılmışı yükle**'ye basın.
4. Açılan pencerede üstteki adres çubuğuna kopyaladığınız yolu yapıştırın, Enter'a basın, sonra **Klasör seç** düğmesine basın.

### Edge Add-ons mağazası (sonraki, isteğe bağlı adım)

Eklentiyi ileride Edge Add-ons mağazasına koyabilirsiniz; bu adımı kendi Microsoft hesabınızla yaparsınız ve ücretsizdir.
Bakım yapacak kişi için not: yayımlandıktan sonra mağaza eklentiye **farklı bir eklenti kimliği** verir. Bu kimlik `allowed_origins` listesine eklenmelidir.

### Windows Sandbox kontrol listesi

1. İki farklı deneme sitesinde aynı deneme şifresini kullanın. İkincisinde **sarı kart** çıkmalı.
2. Bir giriş formuna `password123` yazın. **Kırmızı "sızdırılmış" kartı** çıkmalı.
3. Bir giriş formunun şifre alanına 6 haneli bir banka şifresi (örneğin `482913`) yazıp gönderin. **Hiçbir kart çıkmamalı.**
4. Gönderildikten sonra başka bir sayfaya yönlendiren bir girişte `password123` kullanın. Kart **bir sonraki sayfada** çıkmalı.
5. discord.com'u açın. MFA kartı **bir kez** çıkmalı; **Sonra**'ya basarsanız 7 gün sonra tekrar gelir.
6. eicar.org'dan `eicar_com.zip` dosyasını indirin (zip taranır; `eicar.com` taranmaz). "Tehlikeli olabilir" bildirimi gelmeli.
   Defender dosyayı Cortmed'den önce silerse Cortmed bildirimi gelmeyebilir; bu normaldir. Denemeyi Defender'ın gerçek zamanlı korumasını Sandbox içinde kapatarak tekrarlayın.
7. İmzasız küçük bir program (`.exe`) indirin. Başlığı **"Tanınmayan program"** olan **sarı** bir bildirim gelmeli.
8. Panelde **Tarayıcı koruması açık** yazmalı.

Otomatik kontrol: `tests/guard/run.ps1`, eklenti testlerini Edge'in başsız (headless) modunda çalıştırır.

---

## 🛠️ Geliştirici notları

```
engine/build_db.py         Veritabanı derleyici (VirusShare + MalwareBazaar + extra_hashes.txt)
engine/rules/              Android davranış kuralları (banka adları, uzaktan erişim uygulamaları…)
engine/extra_hashes.txt    Elle eklenen parmak izleri (arkadaşından gelen zararlıyı buraya ekle)
android/                   Kotlin uygulaması; derlemek için android/build-apk.bat
windows/                   PowerShell + C# motor; paket için make-windows-package.ps1
.github/workflows/         Gece veritabanı güncellemesi
```

- Veritabanını yerelde yenilemek için: `python engine/build_db.py`, sonra `android/build-apk.bat` ve `make-windows-package.ps1`.
- ⚠️ **`android/keystore/` ve `android/keystore.properties` dosyalarını kaybetme.** Aynı anahtarla imzalanmayan
  yeni sürüm, telefonlardaki Cortmed'in üstüne kurulamaz. Klasör OneDrive'da olduğu için yedekleniyor, ama ayrıca bir USB'ye de kopyala.
  Bu dosyalar asla GitHub'a yüklenmemeli.

## Bilinen sınırlar

- Hiçbir araç %100 koruma sağlamaz. Hiç görülmemiş yeni bir virüsü sadece davranış kuralları yakalayabilir.
- Android, uygulamaların başka uygulamaları kendiliğinden silmesine izin vermez. Cortmed "Kaldır" ekranını açar, onayı insanın vermesi gerekir.
- Bilgisayarda çalışmış bir bilgi hırsızı tarayıcı oturumlarını çalmış olabilir. Böyle bir alarmda tüm önemli hesapların şifrelerini başka bir cihazdan değiştir ve oturumları kapat.
- VirusShare listeleri MD5 tabanlıdır ve ağırlıklı olarak Windows zararlılarını içerir. Android için asıl güç davranış kuralları ve (anahtar eklenirse) MalwareBazaar'dır.
