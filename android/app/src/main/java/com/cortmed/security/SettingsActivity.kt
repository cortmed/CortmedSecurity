package com.cortmed.security

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.widget.LinearLayout
import com.cortmed.security.Ui.button
import com.cortmed.security.Ui.card
import com.cortmed.security.Ui.column
import com.cortmed.security.Ui.dp
import com.cortmed.security.Ui.field
import com.cortmed.security.Ui.header
import com.cortmed.security.Ui.setScreen
import com.cortmed.security.Ui.smallButton
import com.cortmed.security.Ui.text
import com.cortmed.security.Ui.toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Yonetici ayarlari (PIN korumali), konu konu kartlar halinde. */
class SettingsActivity : Activity() {
    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = column()
        setScreen(root)
        render()
    }

    private fun section(title: String, desc: String? = null): LinearLayout {
        root.addView(Ui.spaced(text(title.uppercase(Locale("tr")), 12f, Ui.ACCENT, bold = true).apply {
            letterSpacing = 0.08f
        }, 24))
        val c = card(Ui.SURFACE2)
        if (desc != null) c.addView(text(desc, 14f, Ui.MUTED))
        root.addView(Ui.spaced(c, 8))
        return c
    }

    private fun render() {
        val s = Store(this)
        root.removeAllViews()
        root.addView(header())
        root.addView(Ui.spaced(text("Ayarlar", 26f, Ui.TEXT, bold = true), 20))

        // Ikinci gorus
        val vt = section("İkinci görüş (isteğe bağlı)",
            "Play Store dışından yüklenen uygulamaları 70'ten fazla antivirüs programına sorar. Ücretsiz bir VirusTotal anahtarı gerekir.")
        val vtKey = field("VirusTotal API anahtarı", s.vtKey)
        vt.addView(Ui.spaced(vtKey, 6))
        vt.addView(Ui.spaced(smallButton("Ücretsiz anahtar al") {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/join-us")))
        }, 6).apply { layoutParams = LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(6) } })

        // Veritabani
        val db = section("Virüs veritabanı")
        val info = runCatching {
            val d = CmdbDatabase.get(this)
            "%,d imza  ·  %s tarihli".format(Locale("tr"), d.signatureCount,
                SimpleDateFormat("dd.MM.yyyy", Locale("tr")).format(Date(d.buildTime * 1000)))
        }.getOrDefault("Hazır")
        db.addView(text(info, 15f, Ui.TEXT, bold = true))
        db.addView(Ui.spaced(text("Telefon Wi-Fi'a bağlıyken her gün kendiliğinden güncellenir.", 13f, Ui.MUTED), 4))
        db.addView(Ui.spaced(smallButton("Şimdi güncelle") {
            runAsync({ DbUpdater.update(this) }) { msg -> toast(msg ?: "Güncellenemedi. İnternet bağlantısını kontrol edin.") }
        }, 12))
        db.addView(Ui.spaced(text("Gelişmiş: güncelleme adresi", 12f, Ui.MUTED), 14))
        val url = field("https://github.com/cortmed/CortmedSecurity/releases/download/db-latest",
            s.updateUrl, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI).apply { textSize = 13f }
        db.addView(url)

        // Guvenlik
        val sec = section("Güvenlik", "Ayarlar ve güvenilir uygulamalar bu PIN ile korunur.")
        sec.addView(Ui.spaced(smallButton("PIN'i değiştir") {
            val pin = field("Yeni PIN", "", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
            android.app.AlertDialog.Builder(this).setTitle("Yeni PIN")
                .setView(LinearLayout(this).apply { setPadding(dp(20), dp(8), dp(20), 0); addView(pin) })
                .setPositiveButton("Kaydet") { _, _ ->
                    if (pin.text.length >= 4) { s.setPin(pin.text.toString()); toast("PIN değişti") }
                    else toast("PIN en az 4 rakam olmalı")
                }.setNegativeButton("Vazgeç", null).show()
        }, 12))

        // Guvenilir uygulamalar
        val wl = s.whitelist().sorted()
        val trust = section("Güvenilir uygulamalar",
            if (wl.isEmpty()) "Henüz güvenilir olarak işaretlediğiniz bir uygulama yok."
            else "Bu uygulamalar için öneri gösterilmez. Virüs bulunursa yine de uyarılırsınız.")
        wl.forEach { pkg ->
            val label = runCatching {
                packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
            }.getOrDefault(pkg)
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL }
            row.addView(text(label, 15f, Ui.TEXT), LinearLayout.LayoutParams(0, -2, 1f))
            row.addView(smallButton("Çıkar") { s.removeWhitelist(pkg); render() })
            trust.addView(Ui.spaced(row, 10))
        }

        root.addView(Ui.spaced(button("Kaydet") {
            s.vtKey = vtKey.text.toString()
            s.updateUrl = url.text.toString()
            toast("Kaydedildi")
            finish()
        }, 28))
    }

    private fun <T> runAsync(work: () -> T, done: (T) -> Unit) {
        Thread { val r = work(); runOnUiThread { done(r) } }.start()
    }
}
