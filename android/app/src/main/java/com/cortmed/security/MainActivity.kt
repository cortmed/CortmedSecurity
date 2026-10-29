package com.cortmed.security

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import com.cortmed.security.Ui.button
import com.cortmed.security.Ui.card
import com.cortmed.security.Ui.column
import com.cortmed.security.Ui.setScreen
import com.cortmed.security.Ui.dp
import com.cortmed.security.Ui.header
import com.cortmed.security.Ui.requirePin
import com.cortmed.security.Ui.smallButton
import com.cortmed.security.Ui.text
import com.cortmed.security.Ui.toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private lateinit var root: LinearLayout
    private var scanning = false
    private var progress: TextView? = null
    private var tab: Level? = null
    private val expanded = mutableSetOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = column()
        setScreen(root)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        CortmedApp.schedule(this)
    }

    override fun onResume() {
        super.onResume()
        val last = ScanResult.fromJson(Store(this).lastResultJson)
        render(last)
        // Son tarama 15 dakikadan eskiyse acilista otomatik tara
        if (last == null || System.currentTimeMillis() - last.time > 15 * 60_000L) startScan()
    }

    private fun startScan() {
        if (scanning) return
        scanning = true
        render(ScanResult.fromJson(Store(this).lastResultJson))
        Thread {
            val result = runCatching {
                Scanner(applicationContext).scan { msg -> runOnUiThread { progress?.text = msg } }
            }
            result.getOrNull()?.let { Alerter.handle(applicationContext, it) }
            runOnUiThread {
                scanning = false
                result.exceptionOrNull()?.let { toast("Tarama hatası: ${it.message}") }
                render(ScanResult.fromJson(Store(this).lastResultJson))
            }
        }.start()
    }

    private fun render(r: ScanResult?) {
        root.removeAllViews()
        root.addView(header())

        val (color, icon, title, sub) = when {
            r == null -> Quad(Ui.MUTED, "…", "İlk tarama yapılıyor", "Lütfen bekleyin, bir dakikadan kısa sürer.")
            r.level == Level.RED -> Quad(Ui.RED, "✕", "Dikkat: tehdit bulundu",
                "Telefonunuzda tehlikeli bir uygulama ya da ayar var. Ne yapmanız gerektiği aşağıda yazıyor.")
            else -> Quad(Ui.GREEN, "✓", "Telefonunuz korunuyor", "Tehdit bulunmadı.")
        }
        // Durum halkasi: dista yumusak isik, icte renkli halka
        val circle = text(icon, 58f, color, bold = true, center = true).apply {
            gravity = Gravity.CENTER
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(Ui.alpha(color, 0x22))
                setStroke(dp(6), color)
            }
            layoutParams = LinearLayout.LayoutParams(dp(150), dp(150)).apply { gravity = Gravity.CENTER }
        }
        val glow = android.widget.FrameLayout(this).apply {
            background = GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                intArrayOf(Ui.alpha(color, 0x30), Ui.alpha(color, 0x00))).apply {
                shape = GradientDrawable.OVAL
                gradientType = GradientDrawable.RADIAL_GRADIENT
                gradientRadius = dp(110).toFloat()
            }
            addView(circle)
            layoutParams = LinearLayout.LayoutParams(dp(210), dp(210)).apply {
                gravity = Gravity.CENTER_HORIZONTAL; topMargin = dp(16)
            }
        }
        root.addView(glow)
        root.addView(Ui.spaced(text(title, 26f, Ui.TEXT, bold = true, center = true), 4))
        root.addView(Ui.spaced(text(sub, 16f, Ui.MUTED, center = true), 6))

        // Koruma kontrolleri: kullanici neyin calistigini gorsun
        if (r != null) {
            val fmt = SimpleDateFormat("dd.MM HH:mm", Locale("tr"))
            val checks = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                setPadding(dp(14), dp(10), dp(14), dp(10))
                background = GradientDrawable().apply { setColor(Ui.SURFACE); cornerRadius = dp(14).toFloat() }
            }
            listOf(
                "Otomatik koruma açık (15 dakikada bir kontrol)",
                "Virüs veritabanı: ${"%,d".format(Locale("tr"), r.signatures)} imza",
                "Son tarama: ${fmt.format(Date(r.time))} · ${r.appsScanned} uygulama",
            ).forEach { checks.addView(text("✓  $it", 13f, Ui.GREEN, bold = true).apply { setPadding(0, dp(2), 0, dp(2)) }) }
            root.addView(Ui.spaced(checks, 14).apply {
                layoutParams = LinearLayout.LayoutParams(-2, -2).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = dp(14) }
            })
        }

        progress = text(if (scanning) "Tarama başlıyor…" else "", 13f, Ui.ACCENT, center = true)
        root.addView(Ui.spaced(progress!!, 8))
        root.addView(Ui.spaced(button(if (scanning) "Taranıyor…" else "Şimdi Tara") { startScan() }, 12))

        // Sekmeler: Tehditler (kirmizi) / Oneriler (sari)
        val threats = r?.findings?.filter { it.threat } ?: emptyList()
        val advice = r?.findings?.filter { !it.threat } ?: emptyList()
        val current = tab ?: if (threats.isNotEmpty()) Level.RED else Level.YELLOW
        val tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun tabButton(label: String, level: Level, accent: Int) = TextView(this).apply {
            val on = level == current
            text = label
            textSize = 15f
            gravity = Gravity.CENTER
            setTextColor(if (on) Ui.TEXT else Ui.MUTED)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setPadding(0, dp(12), 0, dp(12))
            background = GradientDrawable().apply {
                cornerRadius = dp(12).toFloat()
                setColor(if (on) Ui.SURFACE2 else Ui.BG)
                setStroke(dp(if (on) 2 else 1), if (on) accent else Ui.alpha(Ui.MUTED, 0x55))
            }
            setOnClickListener { tab = level; render(ScanResult.fromJson(Store(this@MainActivity).lastResultJson)) }
        }
        tabs.addView(tabButton("Tehditler (${threats.size})", Level.RED, Ui.RED),
            LinearLayout.LayoutParams(0, -2, 1f).apply { marginEnd = dp(6) })
        val groups = adviceGroups(advice)
        tabs.addView(tabButton("Önerilerimiz (${groups.size})", Level.YELLOW, Ui.ACCENT),
            LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = dp(6) })
        root.addView(Ui.spaced(tabs, 22))

        if (current == Level.RED) {
            if (threats.isEmpty()) root.addView(Ui.spaced(text("✓  Tehdit bulunmadı\nCortmed telefonunuzu arka planda korumaya devam ediyor.",
                15f, Ui.GREEN, bold = true, center = true), 28))
            threats.forEach { root.addView(Ui.spaced(findingCard(it), 14)) }
        } else {
            if (groups.isEmpty()) root.addView(Ui.spaced(text("✓  Şu an bir önerimiz yok. Her şey yolunda.",
                15f, Ui.GREEN, bold = true, center = true), 28))
            groups.forEach { (cat, items) -> root.addView(Ui.spaced(groupCard(cat, items), 14)) }
        }

        root.addView(Ui.spaced(smallButton("⚙  Ayarlar") {
            requirePin { startActivity(Intent(this, SettingsActivity::class.java)) }
        }, 32))
    }

    /** Oneri kategorisi: baslik, kisa aciklama ve istenirse acilan ayrintilar. */
    private data class AdviceCat(val id: String, val icon: String, val title: String, val text: String)

    private val categories = listOf(
        AdviceCat("settings", "🛡", "Telefon ayarlarını güçlendirin", "%d ayar telefonunuzu daha güvenli yapar."),
        AdviceCat("perms", "🔑", "Uygulama izinlerini gözden geçirin",
            "%d uygulamanın hassas bir izni var. İzni siz verdiyseniz sorun yok."),
        AdviceCat("side", "📦", "Play Store dışından yüklenen uygulamalar",
            "%d uygulama Play Store'dan yüklenmemiş. Tanıyorsanız bir şey yapmanıza gerek yok."),
    )

    private fun categoryOf(f: Finding) = when (f.key.substringBefore(':')) {
        "installer", "a11y" -> "perms"
        "side" -> "side"
        else -> "settings"
    }

    private fun adviceGroups(advice: List<Finding>) =
        categories.map { c -> c to advice.filter { categoryOf(it) == c.id } }.filter { it.second.isNotEmpty() }

    private fun groupCard(c: AdviceCat, items: List<Finding>) = card(Ui.ACCENT).apply {
        val top = LinearLayout(context).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        top.addView(text(c.icon, 24f, Ui.ACCENT), LinearLayout.LayoutParams(dp(42), -2))
        val col = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        col.addView(text(c.title, 16f, Ui.TEXT, bold = true))
        col.addView(Ui.spaced(text(c.text.format(items.size), 13f, Ui.MUTED), 2))
        top.addView(col, LinearLayout.LayoutParams(0, -2, 1f))
        addView(top)
        val open = c.id in expanded
        addView(Ui.spaced(smallButton(if (open) "Gizle" else "Göster") {
            if (open) expanded.remove(c.id) else expanded.add(c.id)
            render(ScanResult.fromJson(Store(this@MainActivity).lastResultJson))
        }, 10).apply { layoutParams = LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(10); marginStart = dp(42) } })
        if (open) items.forEach { addView(Ui.spaced(findingCard(it), 10)) }
    }

    private fun findingCard(f: Finding) = card(if (f.level == Level.RED) Ui.RED else Ui.YELLOW).apply {
        addView(text((if (f.level == Level.RED) "⛔  " else "⚠️  ") + f.title, 16f, Ui.TEXT, bold = true))
        addView(Ui.spaced(text(f.detail, 14f, Ui.MUTED), 4))
        val row = LinearLayout(context).apply { orientation = LinearLayout.HORIZONTAL }
        fun add(b: android.view.View) = row.addView(b, LinearLayout.LayoutParams(-2, -2).apply { marginEnd = dp(8) })
        if (f.pkg != null && f.action == "app") {
            add(smallButton("Kaldır") { open(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.pkg}"))) })
            add(smallButton("İzinler") {
                open(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${f.pkg}")))
            })
        } else if (f.action != null && f.action != "app") {
            add(smallButton("Ayarı aç") {
                val i = Intent(f.action)
                if (f.pkg != null && f.action == Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
                    i.data = Uri.parse("package:${f.pkg}")
                open(i)
            })
        }
        if (f.pkg != null) add(smallButton("Güvenilir") {
            requirePin {
                Store(context).addWhitelist(f.pkg)
                toast("${f.pkg} güvenilir listesine eklendi")
                startScan()
            }
        })
        if (row.childCount > 0) addView(Ui.spaced(row, 10))
    }

    private fun open(i: Intent) = try {
        startActivity(i)
    } catch (e: ActivityNotFoundException) {
        startActivity(Intent(Settings.ACTION_SETTINGS))
    }

    private data class Quad(val color: Int, val icon: String, val title: String, val sub: String)
}
