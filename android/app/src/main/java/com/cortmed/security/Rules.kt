package com.cortmed.security

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.util.Locale

/** android_rules.json: guvenilir magazalar, uzaktan erisim uygulamalari, taklit anahtar kelimeleri. */
class Rules(json: JSONObject) {
    val trustedInstallers = json.strings("trusted_installers").toSet()
    val remoteAccessPrefixes = json.strings("remote_access_prefixes")
    val smsPermissions = json.strings("sms_permissions").toSet()
    val vtThreshold = json.optInt("virustotal_malicious_threshold", 3)
    private val keywordRegexes = json.strings("impersonation_keywords").map {
        Regex("(?<![\\p{L}\\p{N}])" + Regex.escape(it.lowercase(TR)) + "(?![\\p{L}\\p{N}])")
    }
    private val keywords = json.strings("impersonation_keywords")

    fun isRemoteAccess(pkg: String) = remoteAccessPrefixes.any { pkg == it.trimEnd('.') || pkg.startsWith(it) }

    /** Etiket bir banka / devlet / kargo / bilinen marka adini iceriyorsa o kelimeyi dondurur. */
    fun impersonatedName(label: String): String? {
        val l = label.lowercase(TR)
        val idx = keywordRegexes.indexOfFirst { it.containsMatchIn(l) }
        return if (idx >= 0) keywords[idx] else null
    }

    companion object {
        const val FILE_NAME = "android_rules.json"
        val TR: Locale = Locale.forLanguageTag("tr")

        private fun JSONObject.strings(key: String): List<String> {
            val arr = optJSONArray(key) ?: return emptyList()
            return List(arr.length()) { arr.getString(it) }
        }

        fun updatedFile(ctx: Context) = File(ctx.filesDir, FILE_NAME)

        fun load(ctx: Context): Rules {
            val updated = updatedFile(ctx).takeIf { it.exists() }?.let {
                runCatching { Rules(JSONObject(it.readText())) }.getOrNull()
            }
            return updated ?: Rules(JSONObject(ctx.assets.open(FILE_NAME).bufferedReader().readText()))
        }
    }
}
