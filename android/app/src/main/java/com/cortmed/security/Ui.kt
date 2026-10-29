package com.cortmed.security

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

/** Kucuk gorunum yardimcilari: XML yerine koddan, bagimliliksiz arayuz. Renkler logodaki lacivert/camgobeginden. */
object Ui {
    const val BG = 0xFF0B1526.toInt()
    const val SURFACE = 0xFF13223A.toInt()
    const val SURFACE2 = 0xFF1B2E4B.toInt()
    const val ACCENT = 0xFF29B6F6.toInt()
    const val ACCENT_DARK = 0xFF1565C0.toInt()
    const val TEXT = 0xFFF1F5FB.toInt()
    const val MUTED = 0xFF93A4BD.toInt()
    const val GREEN = 0xFF22C55E.toInt()
    const val YELLOW = 0xFFF5A524.toInt()
    const val RED = 0xFFEF4444.toInt()

    fun Context.dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    /** Rengin seffaf hali (0-255 opaklik). */
    fun alpha(color: Int, a: Int) = (color and 0x00FFFFFF) or (a shl 24)

    fun Context.column(padding: Int = 20) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(padding), dp(padding), dp(padding), dp(padding))
    }

    fun Context.text(s: String, size: Float = 16f, color: Int = TEXT, bold: Boolean = false,
                     center: Boolean = false) = TextView(this).apply {
        text = s
        textSize = size
        setTextColor(color)
        if (bold) typeface = Typeface.DEFAULT_BOLD
        if (center) gravity = Gravity.CENTER_HORIZONTAL
    }

    /** Ust bant: logo + CORTMED / SECURITY yazisi. */
    fun Context.header() = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(ImageView(context).apply {
            setImageResource(R.drawable.cortmed_logo)
            scaleType = ImageView.ScaleType.CENTER_CROP
            clipToOutline = true
            background = GradientDrawable().apply { cornerRadius = dp(8).toFloat(); setColor(SURFACE) }
        }, LinearLayout.LayoutParams(dp(44), dp(44)))
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, 0, 0)
            addView(text("CORTMED", 20f, TEXT, bold = true).apply { letterSpacing = 0.18f })
            addView(text("SECURITY", 11f, ACCENT, bold = true).apply { letterSpacing = 0.45f })
        })
    }

    fun Context.button(label: String, bg: Int = ACCENT, onClick: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 16f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(Color.WHITE)
        stateListAnimator = null
        background = GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,
            if (bg == ACCENT) intArrayOf(ACCENT, ACCENT_DARK) else intArrayOf(bg, bg)).apply {
            cornerRadius = dp(14).toFloat()
        }
        minHeight = dp(52)
        setOnClickListener { onClick() }
    }

    fun Context.smallButton(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 13f
        setTextColor(ACCENT)
        stateListAnimator = null
        background = GradientDrawable().apply {
            setColor(alpha(ACCENT, 0x1A)); cornerRadius = dp(10).toFloat(); setStroke(dp(1), alpha(ACCENT, 0x88))
        }
        minHeight = 0
        minimumHeight = 0
        minWidth = 0
        minimumWidth = 0
        setPadding(dp(14), dp(8), dp(14), dp(8))
        setOnClickListener { onClick() }
    }

    fun Context.card(accent: Int) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(14), dp(16), dp(14))
        background = GradientDrawable().apply {
            setColor(SURFACE); cornerRadius = dp(16).toFloat(); setStroke(dp(1), alpha(accent, 0xAA))
        }
    }

    fun Context.field(hint: String, value: String, type: Int = InputType.TYPE_CLASS_TEXT) = EditText(this).apply {
        this.hint = hint
        setText(value)
        inputType = type
        textSize = 15f
        setTextColor(TEXT)
        setHintTextColor(alpha(MUTED, 0x99))
        backgroundTintList = ColorStateList.valueOf(ACCENT)
    }

    fun spaced(v: View, top: Int) = v.apply {
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = (top * v.resources.displayMetrics.density).toInt()
        }
    }

    /** Icerigi kaydirilabilir ekran yapar; Android 15+ kenardan kenara modda sistem cubuklarini atlar. */
    fun Activity.setScreen(content: View) {
        val scroll = android.widget.ScrollView(this).apply { addView(content); clipToPadding = false }
        if (android.os.Build.VERSION.SDK_INT >= 35) {
            scroll.setOnApplyWindowInsetsListener { v, insets ->
                val b = insets.getInsets(android.view.WindowInsets.Type.systemBars() or
                    android.view.WindowInsets.Type.ime())
                v.setPadding(b.left, b.top, b.right, b.bottom)
                insets
            }
        }
        setContentView(scroll)
    }

    fun Context.toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    /** Yonetici PIN'i ister; ilk kullanimda PIN olusturur. */
    fun Activity.requirePin(onOk: () -> Unit) {
        val store = Store(this)
        val input = field("PIN", "", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
        val creating = !store.hasPin
        AlertDialog.Builder(this)
            .setTitle(if (creating) "Yönetici PIN'i oluştur (en az 4 rakam)" else "Yönetici PIN'i")
            .setView(LinearLayout(this).apply { setPadding(dp(20), dp(8), dp(20), 0); addView(input) })
            .setPositiveButton("Tamam") { _, _ ->
                val pin = input.text.toString()
                when {
                    creating && pin.length >= 4 -> { store.setPin(pin); onOk() }
                    creating -> toast("PIN en az 4 rakam olmalı")
                    store.checkPin(pin) -> onOk()
                    else -> toast("PIN yanlış")
                }
            }
            .setNegativeButton("Vazgeç", null)
            .show()
    }
}
