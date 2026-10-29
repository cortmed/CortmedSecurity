package com.cortmed.security

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

/**
 * Kirmizi bulgularda telefonda genel bir uyari bildirimi gosterir.
 * Sari bulgular (oneriler) bildirim gondermez; sadece uygulama icinde gorunur.
 */
object Alerter {
    private const val CHANNEL = "cortmed_alarm"
    private const val NOTIFICATION_ID = 7001

    /** Tarama sonucunu isler; yeni kirmizi bulgu varsa uyarir. */
    fun handle(ctx: Context, result: ScanResult) {
        val store = Store(ctx)
        store.lastResultJson = result.toJson()
        val reds = result.findings.filter { it.level == Level.RED }
        val redKeys = reds.map { it.key }.toSet()
        val fresh = reds.filter { it.key !in store.alerted() }
        // Cozulen bulgular listeden duser; tekrar ortaya cikarsa yeniden uyarilir
        store.setAlerted(store.alerted().intersect(redKeys) + fresh.map { it.key })
        if (fresh.isEmpty()) {
            if (reds.isEmpty()) ctx.getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
            return
        }
        notifyPhone(ctx)
    }

    private fun notifyPhone(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Güvenlik uyarıları", NotificationManager.IMPORTANCE_HIGH)
        )
        val open = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, AlertActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = Notification.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("⚠️ Güvenlik Uyarısı")
            .setContentText("Telefonunuzda tehlikeli bir uygulama ya da ayar bulundu.")
            .setStyle(Notification.BigTextStyle().bigText(AlertActivity.GENERIC_TEXT))
            .setContentIntent(open)
            .setColor(Ui.RED)
            .setCategory(Notification.CATEGORY_ERROR)
            .setAutoCancel(false)
            .build()
        runCatching { nm.notify(NOTIFICATION_ID, n) }
    }
}
