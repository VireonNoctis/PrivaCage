plugins {
    id("com.android.test")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.privacage.android.performance"
    compileSdk = 36
    targetProjectPath = ":app"
    // AndroidX Macrobenchmark requires test modules to self-instrument separately from the target app.
    // Source checked 2026-10-31: https://android.googlesource.com/platform/frameworks/support/+/e0ecf6d2233244754e505cb53cedc0359e0c87ba/benchmark/benchmark-macro/src/main/java/androidx/benchmark/macro/Macrobenchmark.kt
    experimentalProperties["android.experimental.self-instrumenting"] = true

    defaultConfig {
        minSdk = 28
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        create("benchmark") {
            isDebuggable = true
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.benchmark:benchmark-macro-junit4:1.5.0")
    implementation("androidx.test:runner:1.6.2")
    implementation("androidx.test.ext:junit:1.2.1")
    implementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
