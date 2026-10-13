plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "hum.blst.runtime"
    compileSdk = 35
    buildToolsVersion = "35.0.0"
    defaultConfig {
        applicationId = "hum.blst.runtime"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1"
        ndk { abiFilters += "arm64-v8a" }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets.getByName("main") {
        java.srcDir("../../out/android/uniffi")
        jniLibs.srcDir("../../out/runtime-jni")
    }
    packaging { jniLibs.useLegacyPackaging = true }
}

kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

dependencies { implementation("net.java.dev.jna:jna:5.18.1@aar") }
dependencyLocking { lockAllConfigurations() }
