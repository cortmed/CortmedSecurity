package com.cortmed.security

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom

/** Ayarlar, guvenilir uygulama listesi, PIN ve onbellekler. Her sey yalnizca telefonda kalir. */
class Store(ctx: Context) {
    private val p = ctx.getSharedPreferences("cortmed", Context.MODE_PRIVATE)
    val hashCache = ctx.getSharedPreferences("cortmed_hash", Context.MODE_PRIVATE)!!
    val vtCache = ctx.getSharedPreferences("cortmed_vt", Context.MODE_PRIVATE)!!

    private fun str(key: String) = p.getString(key, "") ?: ""
    private fun put(key: String, value: String) = p.edit().putString(key, value.trim()).apply()

    var vtKey: String
        get() = str("vt_key")
        set(v) = put("vt_key", v)
    /** Bos birakilirsa her gece GitHub'da derlenen resmi Cortmed veritabani kullanilir. */
    var updateUrl: String
        get() = str("update_url").ifEmpty { DEFAULT_UPDATE_URL }
        set(v) = put("update_url", if (v.trim() == DEFAULT_UPDATE_URL) "" else v)
    var lastResultJson: String
        get() = str("last_result")
        set(v) = p.edit().putString("last_result", v).apply()

    // --- Guvenilir uygulamalar (yonetici onayi) ---
    fun whitelist(): Set<String> = p.getStringSet("whitelist", emptySet())!!.toSet()
    fun addWhitelist(pkg: String) = p.edit().putStringSet("whitelist", whitelist() + pkg).apply()
    fun removeWhitelist(pkg: String) = p.edit().putStringSet("whitelist", whitelist() - pkg).apply()

    // --- Daha once bildirilen kirmizi bulgular (ayni sey icin iki kez uyari yok) ---
    fun alerted(): Set<String> = p.getStringSet("alerted", emptySet())!!.toSet()
    fun setAlerted(keys: Set<String>) = p.edit().putStringSet("alerted", keys).apply()

    // --- Yonetici PIN'i ---
    val hasPin: Boolean get() = str("pin_hash").isNotEmpty()

    fun setPin(pin: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }.toHex()
        p.edit().putString("pin_salt", salt).putString("pin_hash", hashPin(salt, pin)).apply()
    }

    fun checkPin(pin: String): Boolean = hasPin && hashPin(str("pin_salt"), pin) == str("pin_hash")

    private fun hashPin(salt: String, pin: String) =
        MessageDigest.getInstance("SHA-256").digest("$salt:$pin".toByteArray()).toHex()
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

const val DEFAULT_UPDATE_URL = "https://github.com/cortmed/CortmedSecurity/releases/download/db-latest"
