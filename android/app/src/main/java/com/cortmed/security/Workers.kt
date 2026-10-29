package com.cortmed.security

import android.app.Application
import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

class CortmedApp : Application() {
    override fun onCreate() {
        super.onCreate()
        schedule(this)
    }

    companion object {
        fun schedule(ctx: Context) {
            val wm = WorkManager.getInstance(ctx)
            // Hafif kontrol: sadece yeni/guncellenen uygulamalarin parmak izi hesaplanir
            wm.enqueueUniquePeriodicWork(
                "cortmed_scan", ExistingPeriodicWorkPolicy.KEEP,
                PeriodicWorkRequestBuilder<ScanWorker>(15, TimeUnit.MINUTES).build(),
            )
            // Veritabani gunde bir, yalnizca Wi-Fi'da guncellenir
            wm.enqueueUniquePeriodicWork(
                "cortmed_db", ExistingPeriodicWorkPolicy.KEEP,
                PeriodicWorkRequestBuilder<DbUpdateWorker>(24, TimeUnit.HOURS)
                    .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build())
                    .build(),
            )
        }
    }
}

class ScanWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result = runCatching {
        Alerter.handle(applicationContext, Scanner(applicationContext).scan())
        Result.success()
    }.getOrElse {
        Log.e(Scanner.TAG, "tarama hatasi", it)
        Result.retry()
    }
}

class DbUpdateWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result =
        if (DbUpdater.update(applicationContext) != null) Result.success() else Result.retry()
}

/** GitHub "db-latest" surumunden veritabani ve kurallari indirir. */
object DbUpdater {
    /** Basarida durum metni, hatada null. */
    fun update(ctx: Context): String? = runCatching {
        val base = Store(ctx).updateUrl.trim().trimEnd('/')
        if (base.isEmpty()) return "Güncelleme adresi ayarlı değil"
        val prefs = ctx.getSharedPreferences("cortmed", Context.MODE_PRIVATE)
        // Once imzali dosya listesi: imza Cortmed'in gizli anahtariyla atilmamissa hicbir sey indirilmez
        val manifestBytes = download("$base/manifest.json")
        check(verifySignature(manifestBytes, download("$base/manifest.sig"))) { "imza dogrulanamadi" }
        val manifest = org.json.JSONObject(String(manifestBytes))
        val remoteVersion = manifest.getString("version")
        if (remoteVersion == prefs.getString("db_version", "")) return "Veritabanı zaten güncel ($remoteVersion)"
        val files = manifest.getJSONObject("files")

        val dbBytes = downloadVerified("$base/${CmdbDatabase.FILE_NAME}", files.getJSONObject(CmdbDatabase.FILE_NAME))
        // Bozuk ya da yarim veritabanini asla kullanma
        check(CmdbDatabase.isAcceptable(CmdbDatabase.parse(dbBytes), CmdbDatabase.get(ctx))) { "veritabani reddedildi" }
        val rules = downloadVerified("$base/${Rules.FILE_NAME}", files.getJSONObject(Rules.FILE_NAME))
        Rules(org.json.JSONObject(String(rules)))
        atomicWrite(CmdbDatabase.updatedFile(ctx), dbBytes)
        atomicWrite(Rules.updatedFile(ctx), rules)
        CmdbDatabase.invalidate()
        prefs.edit().putString("db_version", remoteVersion).apply()
        "Veritabanı güncellendi ($remoteVersion)"
    }.onFailure { Log.w(Scanner.TAG, "veritabani guncellenemedi", it) }.getOrNull()

    /** Gece isinin imza anahtarinin acik yarisi (engine/sign_db.py --generate ciktisi). */
    private const val PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJuAxgIHY09Te/ZMhaZkiUcf00I1GqV85XM0iwcSMcsUTzY998L3Kn2fNcg4fQuQXQDOEKlYB2cmL9o4u8kAvTw=="

    fun verifySignature(data: ByteArray, signature: ByteArray): Boolean = runCatching {
        val key = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(android.util.Base64.decode(PUBLIC_KEY, android.util.Base64.DEFAULT)))
        java.security.Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(data)
            verify(signature)
        }
    }.getOrDefault(false)

    /** Dosyayi indirir ve imzali listedeki parmak iziyle birebir ayni oldugunu dogrular. */
    private fun downloadVerified(url: String, expected: org.json.JSONObject): ByteArray {
        val bytes = download(url)
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
        check(sha == expected.getString("sha256")) { "parmak izi tutmuyor: $url" }
        return bytes
    }

    private fun download(url: String): ByteArray {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 20_000
        conn.readTimeout = 60_000
        conn.instanceFollowRedirects = true
        try {
            check(conn.responseCode == 200) { "HTTP ${conn.responseCode}: $url" }
            return conn.inputStream.use { it.readBytes() }
        } finally {
            conn.disconnect()
        }
    }

    private fun atomicWrite(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeBytes(bytes)
        check(tmp.renameTo(target)) { "dosya yazilamadi: $target" }
    }
}
