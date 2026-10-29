package com.cortmed.security

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import com.cortmed.security.Ui.button
import com.cortmed.security.Ui.column
import com.cortmed.security.Ui.header
import com.cortmed.security.Ui.setScreen
import com.cortmed.security.Ui.text

/** Kirmizi alarm ekrani: teknik ayrinti yok, herkesin anlayacagi genel uyari. */
class AlertActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = column(28).apply { gravity = Gravity.CENTER_HORIZONTAL }
        col.addView(header())
        col.addView(Ui.spaced(text("⚠️", 72f, Color.WHITE, center = true), 40))
        col.addView(Ui.spaced(text("Güvenlik Uyarısı", 30f, Color.WHITE, bold = true, center = true), 12))
        col.addView(Ui.spaced(text(GENERIC_TEXT, 19f, Color.WHITE, center = true), 20))
        col.addView(Ui.spaced(text(ADVICE, 17f, Color.WHITE), 28))
        col.addView(Ui.spaced(button("Anladım", 0x33000000) { finish() }, 36))
        col.addView(Ui.spaced(button("Ayrıntılar", 0x22000000) {
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }, 12))
        setScreen(col)
    }

    companion object {
        const val GENERIC_TEXT = "Telefonunuzda tehlikeli bir uygulama ya da ayar bulundu. Ayrıntılar için " +
            "Cortmed Security'yi açın. O zamana kadar banka uygulamalarını kullanmayın ve gelen bağlantılara tıklamayın."
        const val ADVICE = "• Telefonda arayan kimseye kod veya şifre söylemeyin.\n" +
            "• Kimsenin isteğiyle uygulama yüklemeyin.\n" +
            "• Banka asla telefonda uygulama yükletmez."
    }
}
