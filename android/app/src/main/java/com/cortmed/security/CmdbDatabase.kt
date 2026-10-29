package com.cortmed.security

import android.content.Context
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Arrays

/**
 * Cortmed Engine parmak izi veritabani (engine/build_db.py ile uretilen CMDB v1).
 * Onekler isaretsiz siralidir; Java'nin isaretli aramasi icin isaret biti cevrilir.
 */
class CmdbDatabase private constructor(
    val buildTime: Long,
    private val families: Array<String>,
    private val sha: LongArray,
    private val shaFamily: ShortArray,
    private val md5: LongArray,
) {
    val signatureCount: Int get() = sha.size + md5.size

    /** Eslesme varsa aile adini ("" = bilinmeyen aile), yoksa null dondurur. */
    fun lookup(sha256: ByteArray, md5Hash: ByteArray): String? {
        val i = Arrays.binarySearch(sha, prefix(sha256))
        if (i >= 0) {
            val fam = shaFamily[i].toInt() and 0xFFFF
            return if (fam in 1..families.size) families[fam - 1] else ""
        }
        if (Arrays.binarySearch(md5, prefix(md5Hash)) >= 0) return ""
        return null
    }

    companion object {
        const val FILE_NAME = "android.cmdb"
        private val lock = Any()
        @Volatile private var cached: CmdbDatabase? = null

        private fun prefix(hash: ByteArray): Long =
            ByteBuffer.wrap(hash, 0, 8).order(ByteOrder.BIG_ENDIAN).long xor Long.MIN_VALUE

        fun parse(bytes: ByteArray): CmdbDatabase {
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val magic = ByteArray(4).also { b.get(it) }
            require(String(magic, Charsets.US_ASCII) == "CMDB") { "Gecersiz CMDB dosyasi" }
            val version = b.short.toInt()
            require(version == 1) { "Desteklenmeyen CMDB surumu $version" }
            b.short
            val buildTime = b.long
            val families = Array(b.int) {
                val len = b.short.toInt() and 0xFFFF
                val raw = ByteArray(len).also { b.get(it) }
                String(raw, Charsets.UTF_8)
            }
            val nSha = b.int
            val sha = LongArray(nSha).also { b.asLongBuffer().get(it) }
            b.position(b.position() + nSha * 8)
            val shaFam = ShortArray(nSha).also { b.asShortBuffer().get(it) }
            b.position(b.position() + nSha * 2)
            val nMd5 = b.int
            val md5 = LongArray(nMd5).also { b.asLongBuffer().get(it) }
            for (i in sha.indices) sha[i] = sha[i] xor Long.MIN_VALUE
            for (i in md5.indices) md5[i] = md5[i] xor Long.MIN_VALUE
            return CmdbDatabase(buildTime, families, sha, shaFam, md5)
        }

        fun updatedFile(ctx: Context) = File(ctx.filesDir, FILE_NAME)

        /** Indirilmis guncel veritabani varsa onu, yoksa APK icindekini yukler. */
        fun get(ctx: Context): CmdbDatabase = synchronized(lock) {
            cached?.let { return it }
            val bundled = ctx.assets.open(FILE_NAME).use { parse(it.readBytes()) }
            val updated = updatedFile(ctx).takeIf { it.exists() }?.let {
                runCatching { parse(it.readBytes()) }.getOrNull()
            }
            val db = if (updated != null && isAcceptable(updated, bundled)) updated else bundled
            cached = db
            db
        }

        /** Yeni veritabani daha yeni olmali ve elimizdekinin en az yarisi kadar imza tasimali (yarim derlemeye karsi). */
        fun isAcceptable(candidate: CmdbDatabase, current: CmdbDatabase) =
            candidate.buildTime > current.buildTime && candidate.signatureCount >= current.signatureCount / 2

        fun invalidate() = synchronized(lock) { cached = null }
    }
}
