plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.privacage.android"
    compileSdk = 36

    sourceSets {
        getByName("main") {
            assets.srcDir("../../shared/tracker-db")
        }
    }

    defaultConfig {
        applicationId = "org.privacage.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":android-core"))
    implementation("com.android.tools.build:apksig:8.10.1")
    testImplementation("junit:junit:4.13.2")
}
