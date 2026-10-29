# Davranış Bekçisi (Faz 2) — Tasarım

Tarih: 2026-10-29 · Durum: onay bekliyor · Platform: Windows

## 1. Amaç

Dosya taramasından geçen, hiçbir listede olmayan bir programı **çalışırken ne yaptığından** yakalamak.
Örnek: arkadaşa "oyunumu dene" diye gönderilen program açılınca kendini açılışa ekliyor, Discord'un
dosyasını değiştiriyor ya da gizli bir PowerShell komutu başlatıyor.

**Başarı ölçütü:** zararsız Cortmed test programı çalıştırıldığında en geç birkaç saniye içinde program
donuyor ve kullanıcıya "Durdur / İzin ver" sorusu "neden?" listesiyle çıkıyor. Normal kullanımda (Discord,
Steam, Chrome, Office güncellemeleri) hiç soru çıkmıyor.

### Kullanıcının kararları
- Yönetici yetkisi: **kurulumda bir kez** onay istenebilir (Sysmon kullanılacak).
- Tepki: **duraklat ve sor**. Cortmed sormadan program kapatmaz.
- Yaklaşım: **B**. Ayrı bir Cortmed hizmeti (SYSTEM), tepsi uygulaması sadece arayüz.

### Varsayımlar (kullanıcı söylemedi, tasarım böyle kabul ediyor)
- Hedef: arkadaşların Windows 10/11 bilgisayarları, .NET Framework 4.8 hazır.
- Android kapsam dışı (orada uygulamalar birbirini izleyemiyor; izin profili zaten var).
- İlk sürümde ağ bağlantıları izlenmiyor (yük ve yanlış alarm riski); sonraki sürüme bırakıldı.

## 2. Parçalar

```
 Sysmon (Microsoft)  ──olaylar──▶  CortmedGuard hizmeti (SYSTEM)  ──soru──▶  Tepsi Cortmed (kullanıcı)
  olay kaydı                        süreç ağacı, puan, dondurma        ◀─cevap──  "Durdur / İzin ver"
```

| Parça | Görev | Nerede |
|---|---|---|
| **Sysmon** | Windows olaylarını kaydeder | Kurulumda resmi Sysinternals adresinden indirilir, Microsoft imzası doğrulanır. Lisans dağıtıma izin vermediği için pakete konmaz |
| **Cortmed Sysmon ayarı** | Sadece gerekli olayları açar (aşağıda) | `ProgramData\Cortmed\sysmon-cortmed.xml` |
| **CortmedGuard.exe** | Windows hizmeti (LocalSystem). Olayları okur, süreç ağacını tutar, puanlar, dondurur, kapatır | `Program Files\Cortmed\` (sadece yönetici yazabilir); kaynak kurulumda oraya kopyalanıp orada derlenir |
| **Davranış kuralları** | Puan tablosu ve istisnalar | `ProgramData\Cortmed\behavior-rules.json` + imza; gece güncellemesiyle gelir |
| **Tepsi Cortmed** (mevcut) | Hizmetten gelen soruyu gösterir, cevabı yollar; panelde bekçi durumunu gösterir | `%LOCALAPPDATA%\CortmedSecurity\` |
| **Kanal** | Yerel named pipe `\\.\pipe\CortmedGuard` | Sadece SYSTEM ve etkileşimli oturumdaki kullanıcı bağlanabilir |

## 3. İzlenen olaylar (Sysmon)

| Sysmon olayı | Ne için |
|---|---|
| 1 Süreç başlatma | Süreç ağacı, imza, komut satırı (gizlenmiş komut) |
| 11 Dosya oluşturma | Başlangıç klasörü, Discord çekirdek klasörü, tarayıcı eklenti klasörleri, belgelerde toplu değişiklik |
| 12/13 Kayıt defteri | Run/RunOnce, Defender ayarları |
| 8 Uzak iş parçacığı | Başka programa kod sokma |
| 10 Süreç erişimi | LSASS'a erişim |

Zamanlanmış görev ekleme, süreç başlatma olayındaki `schtasks` komut satırından yakalanır.

## 4. Puanlama

- Başlangıç puanı: programın **dosya risk puanı** (mevcut motor, `Get-RiskAssessment`).
- Davranış puanları, programa **ve onun başlattığı tüm alt süreçlere** son 5 dakika içinde birlikte eklenir.
- Her puan Türkçe bir "neden" cümlesi taşır.

| Davranış | Puan |
|---|---|
| Kendini açılışa eklemek (Run, Başlangıç klasörü, zamanlanmış görev) | +35 |
| Başka bir programın dosyalarını değiştirmek (Discord çekirdeği, tarayıcı eklentileri) | +50 |
| Gizlenmiş komutla PowerShell / cmd / mshta / wscript başlatmak | +30 |
| Koruma ayarlarını kapatmaya çalışmak (Defender istisnası / kapatma) | +60 |
| Başka bir programa kod sokmak | +50 |
| LSASS'a erişmek | +70 |
| 10 saniyede 50'den fazla belgeyi değiştirmek (fidye yazılımı belirtisi) | +70 |
| Program Files'ta ve geçerli imzalı | −30 |

| Toplam | Karar |
|---|---|
| ≥ 80 | Ağacı dondur, kullanıcıya sor |
| 50–79 | Dondurma yok; kısa bildirim + Tehditler sekmesi |
| < 50 | Sadece kayıt |

**İstisnalar:** Windows Update, Cortmed, kullanıcının "İzin ver" dediği dosyalar (SHA-256 ile), Program Files'taki
geçerli imzalı yayıncıların izin listesi (kural dosyasında).

## 5. Dondurma ve soru akışı

1. Puan 80'i geçer → hizmet ağaçtaki her süreci `NtSuspendProcess` ile dondurur, bekleyen soru kaydı oluşturur.
2. Hizmet kanaldan tepsiye soru yollar: `{id, program, yol, yayıncı, puan, nedenler[]}`.
3. Tepsi, her pencerenin üstünde koyu temalı pencere açar: başlık, neden listesi,
   **[Programı kapat (önerilen)] [İzin ver, devam etsin] [Ayrıntılar]**.
4. Cevap kanaldan döner: `{id, karar}`.
   - **Kapat:** hizmet ağacı kapatır, bulgu Tehditler sekmesine raporuyla eklenir. Dosyaya dokunulmaz (otomatik karantina açıksa karantinaya alınır).
   - **İzin ver:** ağaç devam ettirilir, dosyanın SHA-256'sı izin listesine eklenir.
5. Cevap yok → program donuk kalır, **asla sormadan kapatılmaz**. 10 dakika sonra kalıcı bildirim çıkar.
   Tepsi kapalıysa ya da oturum yoksa soru bekletilir, tepsi açılınca gösterilir. Yeniden başlatmada süreç zaten biter.

**Asla dondurulmaz:** System, csrss, wininit, winlogon, services, lsass, smss, explorer, Cortmed süreçleri.
Şüpheli ağacın içindeki Windows araçları (powershell, cmd, mshta, rundll32…) ağacın parçası olarak dondurulur.

## 6. Hata durumları

| Durum | Davranış |
|---|---|
| Hizmet çöker | Windows hizmet kurtarma ayarı: 3 kez otomatik yeniden başlat |
| Sysmon durur / kaldırılır | Hizmet yeniden başlatmayı dener; olmazsa panelde ve tepside "Davranış bekçisi kapalı" (sarı) |
| Kural dosyası imzası tutmaz | Önceki geçerli kurallarla devam, kayda yazılır |
| Kanal bağlantısı yok | Sorular bekletilir; panel bekçi durumunu "tepsi bağlı değil" gösterir |
| Kurulumda yönetici onayı verilmez | Cortmed bugünkü haliyle (davranış bekçisi olmadan) çalışır; panelde "Davranış bekçisini aç" önerisi |

Kayıtlar: `ProgramData\Cortmed\guard.log` (kullanıcı okur, sadece hizmet yazar).

## 7. Güvenlik (yetkili kodun kendisi açık kapı olmasın)

1. Hizmet dosyaları `Program Files\Cortmed`, ayarlar `ProgramData\Cortmed`. ACL: SYSTEM ve Administrators yazar, Users okur.
2. Hizmet tepsiden **yalnızca** `{id, karar}` kabul eder. id bekleyen bir soruya ait değilse, karar iki değerden biri değilse ya da mesaj 4 KB'tan büyükse reddedilir. Tepsiden dosya yolu ya da komut alınmaz.
3. Named pipe ACL'si: SYSTEM tam yetki, INTERACTIVE okuma/yazma, diğer herkes yok.
4. Davranış kuralları gece imzasıyla (ECDSA P-256, mevcut anahtar) doğrulanmadan yüklenmez.
5. Sysmon kurulum dosyası Authenticode ile doğrulanır, imzalayan Microsoft olmalı.
6. Kaldırma: hizmet, Cortmed'in kurduğu Sysmon (önceden kurulu Sysmon'a dokunulmaz), Program Files ve ProgramData klasörleri silinir.

## 8. Test

1. **Puanlama testleri:** `tests/behavior/*.json` örnek olay dizileri → beklenen puan ve nedenler (C# test programı, kurulum gerektirmez).
2. **Zararsız test programı (`CortmedBehaviorTest.exe`):** HKCU Run'a "CortmedTest" ekler ve sahte bir Discord klasörüne dosya yazar. Beklenen: donma ve soru. Kapatılınca ya da izin verilince kendi izlerini temizler.
3. **Yanlış alarm:** Discord, Steam, Chrome ve Office güncellemesi sırasında soru çıkmamalı.
4. **Performans:** normal kullanımda hizmet < %1 CPU, < 80 MB bellek.
5. **Ortam:** önce **Windows Sandbox** içinde (kullanıcının bir kez özelliği açması ve yeniden başlatması gerekir), sonra kullanıcının bilgisayarında.

## 9. Kapsam dışı (bu sürümde yok)

- Ağ bağlantısı izleme ve engelleme
- Android davranış izleme
- Bulut tarafında olay toplama (birden çok bilgisayarı tek yerden görme)
- Yapay zeka modeli (Faz 3)
