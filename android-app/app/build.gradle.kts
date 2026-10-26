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
            assets.srcDir("../../shared/app-alternatives")
        }
    }

    testOptions {
        unitTests.all {
            it.systemProperty("privacage.repo-root", rootProject.projectDir.parentFile.absolutePath)
        }
    }

    defaultConfig {
        applicationId = "org.privacage.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        create("benchmark") {
            initWith(getByName("release"))
            isDebuggable = false
            signingConfig = signingConfigs.getByName("debug")
            matchingFallbacks += listOf("release")
        }
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
    implementation("androidx.profileinstaller:profileinstaller:1.4.1")
    testImplementation("junit:junit:4.13.2")
    // Use a real JSON implementation in local JVM tests; android.jar JSON methods are stubs.
    testImplementation("org.json:json:20260719")
}
