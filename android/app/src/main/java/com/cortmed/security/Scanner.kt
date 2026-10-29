package com.cortmed.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import android.view.accessibility.AccessibilityManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale

enum class Level { RED, YELLOW }

/** Bir bulgu. [action]: "app" (uygulama), veya acilacak ayar ekrani. */
data class Finding(
    val key: String,
    val level: Level,
    val title: String,
    val detail: String,
    val pkg: String? = null,
    val action: String? = null,
    /** Sari ama "Tehditler" sekmesinde gosterilir (supheli uygulama). */
    val threat: Boolean = level == Level.RED,
    /** Cortmed risk puani (0-100); ayar onerilerinde 0. */
    val score: Int = 0,
) {
    fun toJson() = JSONObject().put("key", key).put("level", level.name).put("title", title)
        .put("detail", detail).put("pkg", pkg ?: "").put("action", action ?: "")
        .put("threat", threat).put("score", score)

    companion object {
        fun fromJson(o: JSONObject) = Finding(
            o.getString("key"), Level.valueOf(o.getString("level")), o.getString("title"),
            o.getString("detail"), o.optString("pkg").ifEmpty { null }, o.optString("action").ifEmpty { null },
            o.optBoolean("threat", o.getString("level") == "RED"), o.optInt("score", 0),
        )
    }
}

data class ScanResult(
    val time: Long,
    val appsScanned: Int,
    val signatures: Int,
    val dbTime: Long,
    val findings: List<Finding>,
) {
    val level: Level? get() = when {
        findings.any { it.level == Level.RED } -> Level.RED
        findings.isNotEmpty() -> Level.YELLOW
        else -> null
    }

    fun toJson(): String = JSONObject().put("time", time).put("apps", appsScanned)
        .put("sigs", signatures).put("db", dbTime)
        .put("findings", JSONArray(findings.map { it.toJson() })).toString()

    companion object {
        fun fromJson(s: String): ScanResult? = runCatching {
            val o = JSONObject(s)
            val arr = o.getJSONArray("findings")
            ScanResult(o.getLong("time"), o.getInt("apps"), o.getInt("sigs"), o.getLong("db"),
                List(arr.length()) { Finding.fromJson(arr.getJSONObject(it)) })
        }.getOrNull()
    }
}

class Scanner(private val ctx: Context) {
    private val pm = ctx.packageManager
    private val store = Store(ctx)
    private val rules = Rules.load(ctx)

    fun scan(onProgress: (String) -> Unit = {}): ScanResult = synchronized(LOCK) {
        val findings = mutableListOf<Finding>()
        val db = CmdbDatabase.get(ctx)
        onProgress("Telefon ayarları kontrol ediliyor…")
        findings += deviceChecks()

        val whitelist = store.whitelist()
        val a11y = accessibilityPackages()
        val admins = deviceAdminPackages()
        val listeners = notificationListenerPackages()
        val apps = installedPackages().filter { pi ->
            val ai = pi.applicationInfo ?: return@filter false
            pi.packageName != ctx.packageName && (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0
        }
        var vtBudget = 4
        apps.forEachIndexed { i, pi ->
            val pkg = pi.packageName
            val ai = pi.applicationInfo!!
            val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(pkg)
            onProgress("Uygulamalar taranıyor (${i + 1}/${apps.size}): $label")

            val installer = installerOf(pkg)
            val sideloaded = installer == null || installer !in rules.trustedInstallers
            val hashes = hashesFor(pi)

            // Cortmed risk puani: her ipucu puan ve kullanicinin anlayacagi bir neden ekler
            val reasons = mutableListOf<String>()
            var score = 0
            fun add(points: Int, why: String) { score += points; reasons += why }

            // 1) Parmak izi: Cortmed veritabani
            val family = hashes?.let { db.lookup(it.first, it.second) }
            if (family != null) add(100, "Bilinen bir virüsün birebir kopyası (Cortmed veritabanı).")

            // 2) Ikinci gorus: VirusTotal (sadece magaza disi uygulamalar)
            var malicious = -1
            if (family == null && sideloaded && hashes != null && store.vtKey.isNotEmpty()) {
                val shaHex = hashes.first.toHex()
                // Temiz/bilinmeyen sonuc 3 gun sonra yeniden sorulur; zararli sonuc kalicidir
                val cached = store.vtCache.getString(shaHex, null)?.split('|')?.takeIf {
                    it.size == 2 && (it[0].toInt() > 0 || System.currentTimeMillis() - it[1].toLong() < 3 * 86_400_000L)
                }
                malicious = if (cached != null) cached[0].toInt()
                else if (vtBudget > 0) {
                    vtBudget--
                    virusTotal(shaHex)?.also {
                        store.vtCache.edit().putString(shaHex, "$it|${System.currentTimeMillis()}").apply()
                    } ?: -1
                } else -1
                if (malicious >= rules.vtThreshold) add(90, "$malicious farklı antivirüs programı bu uygulamaya zararlı diyor.")
                else if (malicious > 0) add(20, "$malicious antivirüs programı bu uygulamadan şüpheleniyor.")
            }
            val known = family != null || malicious >= rules.vtThreshold

            // Guvenilir listesi sadece davranis ipuclarini susturur; bilinen virus her zaman bildirilir
            if (pkg !in whitelist || known) {
                // 3) Davranis ve izin profili
                val perms = grantedPermissions(pi)
                val sms = perms.any { it in rules.smsPermissions }
                val hasA11y = pkg in a11y
                val isAdmin = pkg in admins
                val listens = pkg in listeners
                val impersonated = if (sideloaded) rules.impersonatedName(label) else null

                if (rules.isRemoteAccess(pkg)) add(75, "Başka birinin telefonunuzu uzaktan kullanmasını sağlar. Dolandırıcılar " +
                    "kendini banka ya da kurum görevlisi gibi tanıtıp bunu yükletir.")
                if (sideloaded) add(20, "Play Store'dan yüklenmemiş.")
                if (impersonated != null) add(60, "\"$impersonated\" adını kullanıyor; bankalar ve kurumlar uygulamalarını sadece Play Store'dan dağıtır.")
                if (hasA11y) add(25, "Ekranınızı okuyup telefonu sizin yerinize kullanabiliyor.")
                if (hasA11y && sideloaded) add(30, "Ekran kontrolü + Play Store dışı kurulum, banka bilgisi çalan uygulamaların tipik birleşimidir.")
                if (sms) add(if (sideloaded) 45 else 10, "SMS'lerinizi (bankanın gönderdiği şifreler dahil) okuyabiliyor.")
                if (listens && sideloaded) add(40, "Bildirimlerinizi (tek kullanımlık şifreler dahil) okuyabiliyor.")
                if (isAdmin) add(if (sideloaded) 45 else 10, "Kendine özel yönetici yetkisi almış; normal yolla silinemeyebilir.")
            }
            score = score.coerceIn(0, 100)
            val why = if (reasons.isEmpty()) "" else "\n\nNeden?\n" + reasons.joinToString("\n") { "• $it" }

            when {
                score >= 70 -> findings += Finding("risk:$pkg", Level.RED,
                    (if (known) "Virüs bulundu: " else "Tehlikeli uygulama: ") + label,
                    "Bu uygulama tehlikeli. \"Kaldır\" düğmesiyle silin.$why", pkg, "app", score = score)
                score >= 40 -> findings += Finding("risk:$pkg", Level.YELLOW, "Şüpheli uygulama: $label",
                    "Bu uygulama şüpheli ama kesin virüs değil. Tanımıyorsanız kaldırın.$why", pkg, "app",
                    threat = true, score = score)
                score >= 15 -> findings += Finding(if (pkg in a11y && !sideloaded) "a11y:$pkg" else "side:$pkg", Level.YELLOW,
                    (if (sideloaded) "Play Store dışından yüklenmiş: " else "Ekranı kullanabilen uygulama: ") + label,
                    (if (sideloaded) "Bu uygulama Play Store'dan yüklenmemiş. Siz yüklediyseniz sorun yok, tanımıyorsanız kaldırın."
                    else "Bu uygulamaya ekranı okuma ve kullanma izni verilmiş. Bu izni siz verdiyseniz sorun yok."), pkg, "app",
                    score = score)
            }
            if (pkg in whitelist) return@forEachIndexed
            val canInstall = canRequestInstalls(pkg, ai.uid)
            if (canInstall) findings += Finding("installer:$pkg", Level.YELLOW,
                "Uygulama yükleme izni açık: $label",
                "Bu uygulama Play Store dışından uygulama yükleyebiliyor. Sahte uygulamalar genelde bu yolla gelir. \"Ayarı aç\" ile izni kapatın.",
                pkg, Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
        }

        ScanResult(System.currentTimeMillis(), apps.size, db.signatureCount, db.buildTime,
            findings.sortedBy { it.level.ordinal })
    }

    // ---------------- Telefon ayarlari ----------------

    private fun deviceChecks(): List<Finding> {
        val out = mutableListOf<Finding>()
        val km = ctx.getSystemService(KeyguardManager::class.java)
        if (km != null && !km.isDeviceSecure) out += Finding("lock", Level.YELLOW, "Ekran kilidi yok",
            "Telefon kaybolursa herkes açıp kullanabilir. Şifre ya da parmak izi kilidi ekleyin.",
            action = Settings.ACTION_SECURITY_SETTINGS)

        runCatching {
            if (Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1)
                out += Finding("adb", Level.YELLOW, "Geliştirici bağlantısı açık",
                    "Telefon kabloyla bağlandığı bilgisayardan kontrol edilebilir. Bu ayara ihtiyacınız yoksa kapatın.",
                    action = Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
        }

        runCatching {
            val mode = Settings.Global.getString(ctx.contentResolver, "private_dns_mode")
            if (mode != null && mode != "hostname") out += Finding("dns", Level.YELLOW, "Zararlı site engelleme kapalı",
                "Dolandırıcı siteler açılmadan engellenmiyor. Ayarlar > Ağ ve internet > Özel DNS bölümüne \"family.cloudflare-dns.com\" yazın.",
                action = "android.settings.WIRELESS_SETTINGS")
        }

        val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/app/Superuser.apk")
        val magisk = runCatching { pm.getPackageInfo("com.topjohnwu.magisk", 0); true }.getOrDefault(false)
        if (magisk || suPaths.any { File(it).exists() }) out += Finding("root", Level.YELLOW,
            "Telefonun koruması kaldırılmış (root)",
            "Telefonun güvenlik kilitleri kaldırılmış. Zararlı uygulamalar telefonun tamamını ele geçirebilir. Banka uygulamaları için risklidir.")

        runCatching {
            val patch = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(Build.VERSION.SECURITY_PATCH)!!
            val ageDays = (System.currentTimeMillis() - patch.time) / 86_400_000L
            if (ageDays > 365) out += Finding("patch", Level.YELLOW, "Telefon güncel değil",
                "Telefonun son güvenlik güncellemesi ${Build.VERSION.SECURITY_PATCH} tarihli. Ayarlar > Sistem > Sistem güncellemesi bölümünden kontrol edin.",
                action = Settings.ACTION_DEVICE_INFO_SETTINGS)
        }
        return out
    }

    // ---------------- Yardimcilar ----------------

    @Suppress("DEPRECATION")
    private fun installedPackages(): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33)
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        else pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

    @Suppress("DEPRECATION")
    private fun installerOf(pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else pm.getInstallerPackageName(pkg)
    }.getOrNull()

    private fun grantedPermissions(pi: PackageInfo): List<String> {
        val names = pi.requestedPermissions ?: return emptyList()
        val flags = pi.requestedPermissionsFlags ?: return emptyList()
        return names.filterIndexed { i, _ -> (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0 }
    }

    private fun accessibilityPackages(): Set<String> = runCatching {
        ctx.getSystemService(AccessibilityManager::class.java)
            .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }.toSet()
    }.getOrDefault(emptySet()) + runCatching {
        // Bazi cihazlarda servis listesi bos doner; ayarin kendisini de oku
        (Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: "")
            .split(':').mapNotNull { it.substringBefore('/').ifBlank { null } }.toSet()
    }.getOrDefault(emptySet())

    private fun deviceAdminPackages(): Set<String> = runCatching {
        ctx.getSystemService(DevicePolicyManager::class.java).activeAdmins
            ?.map { it.packageName }?.toSet() ?: emptySet()
    }.getOrDefault(emptySet())

    private fun notificationListenerPackages(): Set<String> = runCatching {
        (Settings.Secure.getString(ctx.contentResolver, "enabled_notification_listeners") ?: "")
            .split(':').mapNotNull { it.substringBefore('/').ifBlank { null } }.toSet()
    }.getOrDefault(emptySet())

    private fun canRequestInstalls(pkg: String, uid: Int): Boolean = runCatching {
        val aom = ctx.getSystemService(AppOpsManager::class.java)
        val op = "android:request_install_packages"
        val mode = if (Build.VERSION.SDK_INT >= 29) aom.unsafeCheckOpNoThrow(op, uid, pkg)
        else @Suppress("DEPRECATION") aom.checkOpNoThrow(op, uid, pkg)
        mode == AppOpsManager.MODE_ALLOWED
    }.getOrDefault(false)

    /** APK'nin SHA-256 ve MD5'i; uygulama guncellenmedikce onbellekten gelir. */
    private fun hashesFor(pi: PackageInfo): Pair<ByteArray, ByteArray>? {
        val path = pi.applicationInfo?.sourceDir ?: return null
        val stamp = "${pi.lastUpdateTime}"
        store.hashCache.getString(pi.packageName, null)?.split('|')?.let {
            if (it.size == 3 && it[0] == stamp) return it[1].hexToBytes() to it[2].hexToBytes()
        }
        return runCatching {
            val sha = MessageDigest.getInstance("SHA-256")
            val md5 = MessageDigest.getInstance("MD5")
            FileInputStream(path).use { inp ->
                val buf = ByteArray(1 shl 16)
                while (true) {
                    val n = inp.read(buf)
                    if (n < 0) break
                    sha.update(buf, 0, n)
                    md5.update(buf, 0, n)
                }
            }
            val r = sha.digest() to md5.digest()
            store.hashCache.edit().putString(pi.packageName, "$stamp|${r.first.toHex()}|${r.second.toHex()}").apply()
            r
        }.onFailure { Log.w(TAG, "hash hatasi ${pi.packageName}", it) }.getOrNull()
    }

    /** VirusTotal'da kac motorun zararli dedigi; bilinmiyorsa 0, hata/sinirda null. */
    private fun virusTotal(sha256: String): Int? = runCatching {
        val conn = URL("https://www.virustotal.com/api/v3/files/$sha256").openConnection() as HttpURLConnection
        conn.setRequestProperty("x-apikey", store.vtKey)
        conn.connectTimeout = 15_000
        conn.readTimeout = 15_000
        try {
            when (conn.responseCode) {
                200 -> JSONObject(conn.inputStream.bufferedReader().readText())
                    .getJSONObject("data").getJSONObject("attributes")
                    .getJSONObject("last_analysis_stats").optInt("malicious", 0)
                404 -> 0
                else -> null
            }
        } finally {
            conn.disconnect()
        }
    }.getOrNull()

    companion object {
        const val TAG = "Cortmed"
        private val LOCK = Any()
    }
}

private fun String.hexToBytes() = ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
