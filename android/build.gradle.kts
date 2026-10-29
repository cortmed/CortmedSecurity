plugins {
    id("com.android.application") version "8.7.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}

// Proje OneDrive'da; OneDrive derleme dosyalarini kilitledigi icin derleme ciktisi yerel diske yazilir
val buildRoot = File(System.getenv("LOCALAPPDATA") ?: System.getProperty("java.io.tmpdir"), "CortmedBuild")
allprojects {
    layout.buildDirectory.set(File(buildRoot, name))
}
