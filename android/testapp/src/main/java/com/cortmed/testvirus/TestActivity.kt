package com.cortmed.testvirus

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

class TestActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "Bu bir Cortmed Security test uygulamasıdır ve tamamen zararsızdır.\n\n" +
                "Cortmed bu uygulamayı virüs olarak algılamalı ve kırmızı uyarı vermelidir. " +
                "Testten sonra kaldırabilirsiniz."
            textSize = 18f
            setPadding(48, 96, 48, 48)
        })
    }
}
