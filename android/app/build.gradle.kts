import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

// Cortmed Engine veritabani ve kurallari APK'nin icine gomulur
val engineDir = rootProject.projectDir.resolve("../engine")
val cmdbAssets = layout.buildDirectory.dir("cmdbAssets")
val copyCmdb by tasks.registering(Copy::class) {
    from(engineDir.resolve("dist")) { include("android.cmdb", "version.txt") }
    from(engineDir.resolve("rules")) { include("android_rules.json") }
    into(cmdbAssets)
}

android {
    namespace = "com.cortmed.security"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.cortmed.security"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        create("release") {
            if (keystoreProps.isNotEmpty()) {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (keystoreProps.isNotEmpty()) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets["main"].assets.srcDir(cmdbAssets)
    androidResources {
        noCompress += "cmdb"
    }
}

tasks.named("preBuild") { dependsOn(copyCmdb) }

dependencies {
    implementation("androidx.work:work-runtime-ktx:2.9.1")
}
